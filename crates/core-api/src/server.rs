use engine::check::{self, Transition};
use engine::db;
use engine::discover;
use engine::ScanParams;
use ipnet::Ipv4Net;
use engine::model::{Model, State};
use engine::report;
use anyhow::Result;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct Params {
    pub port: u16,
    pub bind: String,
    pub no_open: bool,
    pub interval_secs: u64,
    pub extra_subnets: Vec<Ipv4Net>,
    pub out_dir: PathBuf,
}

#[derive(Clone, Copy, PartialEq)]
enum Job {
    Idle,
    Discover,
    Check,
}

impl Job {
    fn as_str(self) -> &'static str {
        match self {
            Job::Idle => "idle",
            Job::Discover => "discover",
            Job::Check => "check",
        }
    }
}

struct Shared {
    job: Mutex<Job>,
    message: Mutex<String>,
    monitoring: Arc<AtomicBool>,
    engine_lock: Mutex<()>,
    revision: AtomicU64,
    events: Mutex<VecDeque<Event>>,
    store: Arc<engine::db::Db>,
    last_stats: Mutex<Option<engine::ops::CycleStats>>,
    started_ts: i64,
    hardened: bool,
}

/// Resolve the authenticated role for a request, if any.
/// Bearer tokens (automation) and session cookies both hash to stored values.
fn resolve_role(shared: &Shared, authorization: Option<&str>, cookie: Option<&str>) -> Option<String> {
    let conn = shared.store.lock();
    if let Some(header) = authorization {
        let raw = header.strip_prefix("Bearer ").map(str::trim).filter(|s| !s.is_empty());
        if let Some(raw) = raw {
            let hashed = engine::auth::token_hash(raw);
            if let Ok(Some(role)) = db::api_token_role(&conn, &hashed) {
                return Some(role);
            }
        }
    }
    let raw = cookie
        .and_then(|c| c.split(';').find_map(|part| part.trim().strip_prefix("nms_session=")))
        .filter(|s| !s.is_empty())?;
    db::session_role(&conn, &engine::auth::token_hash(raw)).ok().flatten()
}

fn login_page(err: Option<&str>) -> Vec<u8> {
    let err_html = err
        .map(|e| format!(r#"<div class="err">{}</div>"#, crate::ui::esc(e)))
        .unwrap_or_default();
    html(
        "200 OK",
        format!(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>NMS login</title><style>
body{{background:#0b1020;color:#dbe4f5;font:14px system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
form{{background:#0e1730;border:1px solid #22304f;padding:26px;border-radius:10px;display:flex;flex-direction:column;gap:10px;width:300px}}
input{{background:#0b1220;color:#dbe4f5;border:1px solid #22304f;padding:8px;border-radius:6px}}
button{{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:9px;cursor:pointer}}
.err{{color:#ff5470;font-size:12px}}</style></head><body>
<form method="post" action="/login"><b>NMS</b>{err_html}
<input name="username" placeholder="username" autofocus>
<input name="password" type="password" placeholder="password">
<button>sign in</button></form></body></html>"#
        ),
    )
}

/// Render a response that sets a session cookie (login success).
fn session_response(raw_token: &str, max_age_secs: i64) -> Vec<u8> {
    format!(
        "HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: nms_session={raw}; Path=/; Max-Age={age}; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        raw = raw_token,
        age = max_age_secs
    )
    .into_bytes()
}

fn unauthorized(api: bool) -> Vec<u8> {
    if api {
        json("401 Unauthorized", serde_json::json!({"error": "authentication required"}))
    } else {
        see_other("/login")
    }
}

fn forbidden(api: bool) -> Vec<u8> {
    if api {
        json("403 Forbidden", serde_json::json!({"error": "insufficient role"}))
    } else {
        text("403 Forbidden", "insufficient role for this action".into())
    }
}

#[derive(Clone, Serialize)]
struct Event {
    at: String,
    kind: String,
    ip: String,
    role: String,
    subnet: Option<String>,
    message: String,
}

pub fn run(p: Params) -> Result<()> {
    let bind_ip: std::net::IpAddr = p
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --bind '{}': {e}", p.bind))?;
    let hardened = !bind_ip.is_loopback()
        || db::get_setting_or(
            &engine::db::Db::open(&p.out_dir.join("ops.db"))?.lock(),
            "auth_mode",
            "open",
        ) == "hardened";
    let addr = format!("{}:{}", p.bind, p.port);
    let listener = TcpListener::bind(&addr)?;
    let store = Arc::new(engine::db::Db::open(&p.out_dir.join("ops.db"))?);
    let shared = Arc::new(Shared {
        job: Mutex::new(Job::Idle),
        message: Mutex::new("ready".into()),
        monitoring: Arc::new(AtomicBool::new(false)),
        engine_lock: Mutex::new(()),
        revision: AtomicU64::new(0),
        events: Mutex::new(VecDeque::new()),
        last_stats: Mutex::new(None),
        started_ts: chrono::Utc::now().timestamp(),
        hardened,
        store,
    });
    let url = format!("http://{addr}");
    println!("[*] NMS control panel: {url}");
    let pending = engine::ops::spool_count(&p.out_dir);
    if pending > 0 {
        println!("[*] {pending} spooled cycle(s) pending replay");
    }
    match engine::ops::replay_spool(&shared.store, &p.out_dir) {
        Ok(n) if n > 0 => println!("[*] replayed {n} spooled cycle(s)"),
        Ok(_) => {}
        Err(e) => eprintln!("[!] spool replay failed: {e}"),
    }
    if hardened {
        println!("[*] auth mode: HARDENED (non-loopback bind or auth_mode=hardened)");
    } else {
        println!("[*] auth mode: open (no login required)");
    }
    println!("[*] Ctrl+C stops the web server and any in-process monitor loop");
    engine::jobs::start_housekeeping(Arc::clone(&shared.store));
    engine::jobs::start_webhook_sender(Arc::clone(&shared.store));
    engine::jobs::start_report_writer(Arc::clone(&shared.store), p.out_dir.clone());
    if !p.no_open {
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();
    }
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let sh = shared.clone();
                let pp = p.clone();
                std::thread::spawn(move || handle(stream, sh, pp));
            }
            Err(e) => eprintln!("[!] web accept failed: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: TcpStream, shared: Arc<Shared>, p: Params) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() || request.is_empty() {
        return;
    }
    let mut content_length = 0usize;
    let mut cookie: Option<String> = None;
    let mut authorization: Option<String> = None;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {
                let lower = header.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if lower.starts_with("cookie:") {
                    cookie = header.split_once(':').map(|(_, v)| v.trim().to_string());
                } else if lower.starts_with("authorization:") {
                    authorization =
                        header.split_once(':').map(|(_, v)| v.trim().to_string());
                }
            }
        }
    }
    let mut body = String::new();
    if content_length > 0 && content_length < 64 * 1024 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_ok() {
            body = String::from_utf8_lossy(&buf).into_owned();
        }
    }
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    // Hardened-mode enforcement gate (FR-PLAT-005).
    if shared.hardened {
        if let Some((rank, is_api)) = engine::auth::requirement(method, path) {
            match resolve_role(&shared, authorization.as_deref(), cookie.as_deref()) {
                None => {
                    let _ = writer.write_all(&unauthorized(is_api));
                    let _ = writer.flush();
                    return;
                }
                Some(role_str) => {
                    let role = engine::auth::Role::parse(&role_str)
                        .unwrap_or(engine::auth::Role::Viewer);
                    if !engine::auth::authorized(role, is_api, rank) {
                        let _ = writer.write_all(&forbidden(is_api));
                        let _ = writer.flush();
                        return;
                    }
                }
            }
        }
    }

    let response = route(method, path, query, &body, cookie.as_deref(), &shared, &p);
    let _ = writer.write_all(&response);
    let _ = writer.flush();
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn form_value(form: &str, key: &str) -> Option<String> {
    form.split('&')
        .filter_map(|part| part.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| url_decode(v))
}

fn html(status: &str, page: String) -> Vec<u8> {
    response(status, "text/html; charset=utf-8", page.into_bytes())
}

fn route(method: &str, path: &str, query: &str, body: &str, cookie: Option<&str>, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => map_page(shared, p),
        ("GET", "/map") => map_page(shared, p),
        ("GET", "/console") => html("200 OK", crate::ui::dashboard(&shared.store.lock())),
        ("GET", "/devices") => html(
            "200 OK",
            crate::ui::devices_page(
                &shared.store.lock(),
                &url_decode(&query_param(query, "state").unwrap_or_default()),
                &url_decode(&query_param(query, "q").unwrap_or_default()),
            ),
        ),
        ("GET", "/events") => {
            let view = query_param(query, "view");
            let sev = query_param(query, "severity").filter(|s| !s.is_empty());
            let only_open = view.as_deref() != Some("all");
            html("200 OK", crate::ui::events_page(&shared.store.lock(), only_open, sev.as_deref()))
        }
        ("GET", "/audit") => html("200 OK", crate::ui::audit_page(&shared.store.lock())),
        ("GET", "/settings") => {
            let saved = query_param(query, "saved").as_deref() == Some("1");
            html("200 OK", crate::ui::settings_page(&shared.store.lock(), saved))
        }
        ("GET", "/triage") => {
            let Some(ip) = query_param(query, "ip").filter(|s| !s.is_empty()) else {
                return text("400 Bad Request", "query parameter ip is required".into());
            };
            html("200 OK", crate::ui::triage_page(&shared.store.lock(), &url_decode(&ip)))
        }
        ("GET", "/reports") => {
            let hours: i64 = query_param(query, "hours")
                .and_then(|h| h.parse().ok())
                .unwrap_or(24);
            html("200 OK", crate::ui::reports_page(&shared.store.lock(), hours.clamp(1, 24 * 45)))
        }
        ("GET", "/api/report/availability.csv") => {
            let hours: i64 = query_param(query, "hours").and_then(|h| h.parse().ok()).unwrap_or(24);
            text_csv(
                "200 OK",
                engine::reports::availability_csv(&shared.store.lock(), hours.clamp(1, 24 * 45)),
            )
        }
        ("GET", "/api/report/devices.csv") => {
            let hours: i64 = query_param(query, "hours").and_then(|h| h.parse().ok()).unwrap_or(24);
            let site = query_param(query, "site").filter(|s| !s.is_empty());
            text_csv(
                "200 OK",
                engine::reports::devices_csv(&shared.store.lock(), hours.clamp(1, 24 * 45), site.as_deref()),
            )
        }
        ("POST", "/api/settings") => settings_save(body, shared),
        ("POST", "/api/device") => device_action(body, shared, p),
        ("POST", "/api/event/ack") => event_ack(body, shared),
        ("POST", "/api/webhook/test") => webhook_test(shared),
        ("POST", "/api/diagnose") => diagnose_endpoint(query, shared),
        ("POST", "/api/trace") => trace_endpoint(query, shared),
        ("GET", "/api/health") => health_endpoint(shared),
        ("GET", "/api/openapi.json") => json("200 OK", openapi_spec()),
        ("GET", "/metrics") => text(
            "200 OK",
            engine::metrics::render(&shared.store.lock()),
        ),
        ("GET", "/api/search") => search_endpoint(query, shared),
        ("GET", "/login") => login_page(None),
        ("POST", "/login") => {
            let username = form_value(body, "username").unwrap_or_default();
            let password = form_value(body, "password").unwrap_or_default();
            let user = db::get_user(&shared.store.lock(), &username)
                .ok()
                .flatten()
                .filter(|u| !u.disabled);
            match user {
                Some(u) if engine::auth::verify_password(&password, &u.password_hash) => {
                    let (raw, hashed) = engine::auth::new_token();
                    let expires = chrono::Utc::now().timestamp() + 7 * 86_400;
                    let _ = db::create_session(&shared.store.lock(), &hashed, u.id, &u.role, expires);
                    db::audit(&shared.store.lock(), &format!("web:{}", u.username), "auth.login", &u.username, "");
                    session_response(&raw, 7 * 86_400)
                }
                _ => {
                    db::audit(&shared.store.lock(), "web:anonymous", "auth.failure", &username, "");
                    login_page(Some("invalid username or password"))
                }
            }
        }
        ("POST", "/logout") => {
            if let Some(raw) = cookie.and_then(|c| c.split(';').find_map(|p| p.trim().strip_prefix("nms_session="))) {
                let hashed = engine::auth::token_hash(raw);
                let _ = db::delete_session(&shared.store.lock(), &hashed);
            }
            see_other("/login")
        }
        ("GET", "/api/dashboard.json") => dashboard_json(shared),
        _ if method == "GET" && path.starts_with("/device/") && !path.ends_with(".json") => {
            let ip = url_decode(path.trim_start_matches("/device/"));
            html("200 OK", crate::ui::device_detail(&shared.store.lock(), &ip))
        }
        _ if method == "GET" && path.starts_with("/api/device/") && path.ends_with(".json") => {
            let ip = url_decode(
                path.trim_start_matches("/api/device/")
                    .trim_end_matches(".json"),
            );
            match db::device_by_ip(&shared.store.lock(), &ip) {
                Ok(Some(d)) => json("200 OK", serde_json::to_value(&d).unwrap_or_default()),
                _ => json("404 Not Found", serde_json::json!({"error":"unknown device"})),
            }
        }
        ("GET", "/api/model") => match std::fs::read(p.out_dir.join("model.json")) {
            Ok(body) => response("200 OK", "application/json", body),
            Err(_) => json("404 Not Found", serde_json::json!({"error":"no model yet"})),
        },
        ("GET", "/api/status") => {
            let job = *shared.job.lock().unwrap();
            let stats = shared.last_stats.lock().unwrap().clone();
            json(
                "200 OK",
                serde_json::json!({
                    "job": job.as_str(),
                    "monitoring": shared.monitoring.load(Ordering::Relaxed),
                    "message": shared.message.lock().unwrap().clone(),
                    "revision": shared.revision.load(Ordering::Relaxed),
                    "progress": engine::progress::snapshot(),
                    "events": shared.events.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
                    "ops": stats,
                }),
            )
        }
        ("POST", "/api/discover") => start_job(shared, p, Job::Discover),
        ("POST", "/api/check") => start_job(shared, p, Job::Check),
        ("POST", "/api/monitor/start") => start_monitor(shared, p),
        ("POST", "/api/monitor/stop") => {
            if shared.monitoring.swap(false, Ordering::Relaxed) {
                set_message(shared, "monitor stopping");
                text("200 OK", "monitor stopping".into())
            } else {
                text("409 Conflict", "monitor is not running".into())
            }
        }
        ("POST", "/api/ping") => ping_endpoint(query),
        ("POST", "/api/associate") => associate_endpoint(query, shared, p),
        ("GET", "/api/routes") => routes_endpoint(),
        ("GET", "/api/ifaces") => ifaces_endpoint(),
        _ => text("404 Not Found", "unknown endpoint".into()),
    }
}

fn response(status: &str, content_type: &str, body: Vec<u8>) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

fn see_other(location: &str) -> Vec<u8> {
    format!("HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn text_csv(status: &str, body: String) -> Vec<u8> {
    response(status, "text/csv; charset=utf-8", body.into_bytes())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
}

fn map_page(shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    let _ = shared;
    match Model::load(&p.out_dir.join("model.json")) {
        Ok(model) => match report::render(&model, 3500) {
            Ok(page) => html("200 OK", page),
            Err(e) => text("500 Internal Server Error", format!("map render failed: {e}")),
        },
        Err(_) => response(
            "200 OK",
            "text/html; charset=utf-8",
            NO_MODEL_HTML.as_bytes().to_vec(),
        ),
    }
}

fn dashboard_json(shared: &Arc<Shared>) -> Vec<u8> {
    use std::collections::BTreeMap;
    let conn = shared.store.lock();
    let now = chrono::Utc::now().timestamp();
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT eff_state, COUNT(*) FROM devices WHERE managed=1 GROUP BY eff_state")
    {
        for (k, v) in stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .into_iter()
            .flatten()
            .flatten()
        {
            *counts.entry(k).or_default() += v;
        }
    }
    let trend: Vec<(i64, f64)> = conn
        .prepare(
            "SELECT hour, 100.0*SUM(ups)/MAX(SUM(probes),1) FROM rollup_hourly
             WHERE hour >= ?1 GROUP BY hour ORDER BY hour",
        )
        .ok()
        .and_then(|mut s| {
            s.query_map([now - 86_400], |r| Ok((r.get(0)?, r.get(1)?)))
                .ok()?
                .flatten()
                .collect::<Vec<_>>()
                .into()
        })
        .unwrap_or_default();
    let worst: Vec<(String, String, f64)> = conn
        .prepare(
            "SELECT d.ip, d.role, SUM(r.rtt_sum)/MAX(SUM(r.ups),1)
             FROM rollup_hourly r JOIN devices d ON d.id=r.device_id
             WHERE r.hour >= ?1 AND r.ups > 0
             GROUP BY r.device_id ORDER BY avg_rtt DESC LIMIT 10",
        )
        .ok()
        .and_then(|mut s| {
            s.query_map([now - 3600], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .ok()?
                .flatten()
                .collect::<Vec<_>>()
                .into()
        })
        .unwrap_or_default();
    let (open, unacked, total) = db::event_counts(&conn);
    json(
        "200 OK",
        serde_json::json!({
            "devices": counts,
            "sites": conn.query_row("SELECT COUNT(*) FROM sites", [], |r| r.get::<_, i64>(0)).unwrap_or(0),
            "events": {"open": open, "unacked": unacked, "total": total},
            "availability_trend_24h": trend,
            "worst_latency_1h": worst,
        }),
    )
}

fn settings_save(body: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let conn = shared.store.lock();
    let mut changed = 0usize;
    for pair in body.split('&') {
        let Some((k, v)) = pair.split_once('=') else { continue };
        let key = url_decode(k);
        let val = url_decode(v);
        if db::DEFAULT_SETTINGS.iter().any(|(known, _)| *known == key)
            && db::set_setting(&conn, &key, &val).is_ok()
        {
            changed += 1;
        }
    }
    db::audit(&conn, "web", "settings.save", "", &format!("updated {changed} setting(s)"));
    see_other("/settings?saved=1")
}

fn device_action(body: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    let Some(ip) = form_value(body, "ip") else {
        return json("400 Bad Request", serde_json::json!({"error":"ip required"}));
    };
    let action = form_value(body, "action").unwrap_or_default();
    let value = form_value(body, "value").unwrap_or_default();
    let conn = shared.store.lock();
    let Some(dev) = db::device_by_ip(&conn, &ip).ok().flatten() else {
        return json("404 Not Found", serde_json::json!({"error":"unknown device"}));
    };
    let ok = match action.as_str() {
        "maintenance" => {
            let until = if value == "off" || value.is_empty() {
                None
            } else {
                value.parse::<i64>().ok().map(|mins| chrono::Utc::now().timestamp() + mins * 60)
            };
            db::set_maintenance(&conn, dev.id, until)
        }
        "site" => {
            let name = if value.trim().is_empty() { None } else { Some(value.trim()) };
            db::assign_site(&conn, dev.id, name)
        }
        "managed" => db::set_managed(&conn, dev.id, value != "0"),
        "remove" => {
            // drop from inventory; keep events history
            match db::remove_device(&conn, dev.id) {
                Ok(_) => {
                    drop(conn);
                    return remove_from_model(shared, p, &ip);
                }
                Err(e) => Err(e),
            }
        }
        _ => Err(anyhow::anyhow!("unknown action")),
    };
    let status = match &ok {
        Ok(_) => {
            db::audit(&conn, "web", &format!("device.{action}"), &ip, &value);
            see_other(&format!("/device/{ip}"))
        }
        Err(e) => json("400 Bad Request", serde_json::json!({"error": e.to_string()})),
    };
    status
}

fn remove_from_model(shared: &Arc<Shared>, p: &Params, ip: &str) -> Vec<u8> {
    let model_path = p.out_dir.join("model.json");
    if let Ok(mut model) = Model::load(&model_path) {
        let before = model.devices.len();
        model.devices.retain(|d| d.ip.to_string() != ip);
        model.edges
            .retain(|e| e.src != ip && e.dst != ip);
        if model.devices.len() != before {
            let _ = model.save(&model_path);
            if let Ok(page) = report::render(&model, 3500) {
                let _ = std::fs::write(p.out_dir.join("map.html"), page);
            }
            shared.revision.fetch_add(1, Ordering::Relaxed);
        }
    }
    {
        let conn = shared.store.lock();
        db::audit(&conn, "web", "device.remove", ip, "removed from inventory + map");
    }
    see_other("/devices")
}

fn event_ack(body: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let Some(id) = form_value(body, "id").and_then(|v| v.parse::<i64>().ok()) else {
        return json("400 Bad Request", serde_json::json!({"error":"id required"}));
    };
    let ack = form_value(body, "ack").as_deref() != Some("0");
    let conn = shared.store.lock();
    let _ = db::ack_event(&conn, id, ack, "web", chrono::Utc::now().timestamp());
    db::audit(&conn, "web", "event.ack", &format!("event:{id}"), &format!("ack={ack}"));
    see_other("/events")
}

fn diagnose_endpoint(query: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let Some(ip) = query_param(query, "ip").and_then(|v| v.parse::<Ipv4Addr>().ok()) else {
        return json("400 Bad Request", serde_json::json!({"error":"query parameter ip is required"}));
    };
    let count: u32 = query_param(query, "count").and_then(|v| v.parse().ok()).unwrap_or(40);
    let count = count.clamp(5, 200);
    let started = std::time::Instant::now();
    let diag = match engine::diag::run_burst(ip, count, 25.0, 1000) {
        Ok(d) => d,
        Err(e) => return json("500 Internal Server Error", serde_json::json!({"error": e.to_string()})),
    };
    let (role_hint, mac_hint) = {
        let conn = shared.store.lock();
        match db::device_by_ip(&conn, &ip.to_string()) {
            Ok(Some(d)) => (d.role, d.mac),
            _ => ("endpoint".into(), None),
        }
    };
    let prof = engine::profile::profile_endpoint(ip, mac_hint.as_deref(), &role_hint);
    {
        let conn = shared.store.lock();
        if let Ok(Some(dev)) = db::device_by_ip(&conn, &ip.to_string()) {
            let ports = prof
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let _ = db::save_diag(
                &conn,
                dev.id,
                chrono::Utc::now().timestamp(),
                diag.sent as i64,
                diag.recv as i64,
                diag.loss_pct,
                diag.rtt_min,
                diag.rtt_avg,
                diag.rtt_max,
                diag.rtt_p95,
                diag.jitter_ms,
                diag.score,
                diag.verdict,
                (!ports.is_empty()).then_some(ports.as_str()),
            );
        }
    }
    let services: Vec<serde_json::Value> = prof
        .open_ports
        .iter()
        .map(|p| {
            serde_json::json!({
                "port": p,
                "service": engine::profile::service_names().get(p).copied().unwrap_or("?"),
            })
        })
        .collect();
    let missing: Vec<u16> =
        engine::profile::missing_expected(&prof.device_class, &prof.open_ports);
    json(
        "200 OK",
        serde_json::json!({
            "diag": diag,
            "hostname": prof.hostname,
            "device_class": prof.device_class,
            "services": services,
            "expected_missing": missing,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        }),
    )
}

fn trace_endpoint(query: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let Some(ip) = query_param(query, "ip").and_then(|v| v.parse::<Ipv4Addr>().ok()) else {
        return json("400 Bad Request", serde_json::json!({"error":"query parameter ip is required"}));
    };
    let max_hops: u8 = query_param(query, "max").and_then(|v| v.parse().ok()).unwrap_or(15);
    let hops = match engine::trace::trace_path(ip, max_hops.clamp(3, 30), 700, 3) {
        Ok(h) => h,
        Err(e) => return json("500 Internal Server Error", serde_json::json!({"error": e.to_string()})),
    };
    let enriched: Vec<serde_json::Value> = {
        let conn = shared.store.lock();
        hops.iter()
            .map(|h| {
                let mut o = serde_json::json!({
                    "ttl": h.ttl,
                    "ip": h.ip,
                    "reached": h.reached,
                    "rtt_ms": h.rtt_ms,
                });
                if let Some(hip) = &h.ip {
                    if let Ok(Some(d)) = db::device_by_ip(&conn, hip) {
                        o["role"] = serde_json::json!(d.role);
                        o["site"] = serde_json::json!(db::site_name(&conn, d.site_id));
                        if let Some(cls) = &d.device_class {
                            o["class"] = serde_json::json!(cls);
                        }
                    }
                }
                o
            })
            .collect()
    };
    json("200 OK", serde_json::json!({"ip": ip.to_string(), "hops": enriched}))
}

fn search_endpoint(query: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let Some(q) = query_param(query, "q").map(|v| url_decode(&v)).filter(|v| v.len() >= 2) else {
        return json("200 OK", serde_json::json!({"devices": [], "sites": []}));
    };
    let like = format!("%{q}%");
    let conn = shared.store.lock();

    let devices: Vec<serde_json::Value> = {
        let Ok(mut stmt) = conn.prepare(
            "SELECT ip, role, COALESCE(hostname,''), COALESCE(device_class,''),
                    (SELECT name FROM sites WHERE id=site_id)
             FROM devices
             WHERE ip LIKE ?1 OR COALESCE(hostname,'') LIKE ?1 OR COALESCE(mac,'') LIKE ?1
                OR COALESCE(device_class,'') LIKE ?1
             ORDER BY ip LIMIT 20",
        ) else {
            return json("500 Internal Server Error", serde_json::json!({"error":"query failed"}));
        };
        stmt.query_map(rusqlite::params![like], |r| {
            Ok(serde_json::json!({
                "ip": r.get::<_, String>(0)?,
                "role": r.get::<_, String>(1)?,
                "hostname": r.get::<_, String>(2)?,
                "class": r.get::<_, String>(3)?,
                "site": r.get::<_, Option<String>>(4)?
            }))
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    };

    let sites: Vec<String> = {
        let Ok(mut stmt) =
            conn.prepare("SELECT name FROM sites WHERE name LIKE ?1 ORDER BY name LIMIT 10")
        else {
            return json("500 Internal Server Error", serde_json::json!({"error":"query failed"}));
        };
        stmt.query_map(rusqlite::params![like], |r| r.get::<_, String>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    };

    db::audit(&conn, "web", "search.query", &q, "");
    json("200 OK", serde_json::json!({ "devices": devices, "sites": sites }))
}

fn health_endpoint(shared: &Arc<Shared>) -> Vec<u8> {
    // Database probe: time a trivial query. Never hold the lock longer than
    // this check; a poisoned/hung DB surfaces as degraded, not a hung request.
    let t0 = std::time::Instant::now();
    let db_ok = {
        let conn = shared.store.lock();
        conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).is_ok()
    };
    let db_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (job, monitoring) = (
        *shared.job.lock().unwrap(),
        shared.monitoring.load(Ordering::Relaxed),
    );
    let scheduler_state = match (job, monitoring) {
        (Job::Idle, false) => "idle",
        (Job::Idle, true) => "monitoring",
        (_, _) => "busy",
    };

    let pending_outbound: i64 = {
        let conn = shared.store.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM outbound WHERE status = 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(-1)
    };

    let degraded = !db_ok || pending_outbound < 0;
    json(
        if degraded { "503 Service Unavailable" } else { "200 OK" },
        serde_json::json!({
            "status": if degraded { "degraded" } else { "ok" },
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": chrono::Utc::now().timestamp() - shared.started_ts,
            "components": {
                "database": {
                    "status": if db_ok { "ok" } else { "error" },
                    "probe_ms": (db_ms * 100.0).round() / 100.0,
                },
                "scheduler": {
                    "status": scheduler_state,
                    "last_cycle": shared.last_stats.lock().unwrap().clone(),
                },
                "webhook_queue": {
                    "pending": pending_outbound,
                    "status": if pending_outbound < 0 { "error" } else { "ok" },
                },
            },
        }),
    )
}

/// Single source of truth for the public API surface: every entry is served by
/// `route()` and must appear in `/api/openapi.json` (enforced by unit test).
pub const API_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/api/status", "Job state, revision, progress and last cycle stats"),
    ("GET", "/api/health", "Component health: database, scheduler, webhook queue"),
    ("GET", "/api/openapi.json", "This OpenAPI 3.0 document"),
    ("GET", "/metrics", "Prometheus text-format exposition of platform gauges"),
    ("GET", "/api/search", "Global search across devices and sites"),
    ("GET", "/api/model", "Current discovered topology model.json"),
    ("GET", "/api/dashboard.json", "Dashboard aggregates: counts, trend, worst latency, event counters"),
    ("GET", "/api/device/{ip}.json", "One inventory device record"),
    ("GET", "/api/report/availability.csv", "Per-site availability CSV for a time window"),
    ("GET", "/api/report/devices.csv", "Per-device availability CSV for a window/site"),
    ("POST", "/api/discover", "Queue a network discovery crawl"),
    ("POST", "/api/check", "Queue one status sweep cycle"),
    ("POST", "/api/monitor/start", "Start continuous monitoring loop"),
    ("POST", "/api/monitor/stop", "Stop continuous monitoring loop"),
    ("POST", "/api/ping", "Single ICMP probe of one address"),
    ("POST", "/api/associate", "Manually bind an endpoint to a WAP"),
    ("POST", "/api/diagnose", "Burst-ping diagnostics + port profile for one address"),
    ("POST", "/api/trace", "ICMP traceroute with inventory-enriched hops"),
    ("POST", "/api/event/ack", "Acknowledge or unacknowledge an event"),
    ("POST", "/api/device", "Device actions: maintenance, site assignment, managed flag, removal"),
    ("POST", "/api/settings", "Update known settings keys"),
    ("POST", "/api/webhook/test", "Send a test payload to the configured webhook"),
    ("GET", "/api/routes", "IPv4 routing table of the collector host"),
    ("GET", "/api/ifaces", "Network interfaces of the collector host"),
];

fn openapi_spec() -> serde_json::Value {
    use serde_json::json;
    let mut paths = serde_json::Map::new();
    for (method, path, summary) in API_ROUTES {
        // Keys are the exact served paths; `{ip}` stays a template parameter.
        let entry = paths.entry(*path).or_insert_with(|| json!({}));
        entry[&method.to_lowercase()] = json!({
            "summary": summary,
            "tags": ["nms"],
            "responses": {
                "200": { "description": "Success" },
                "400": { "description": "Bad request" },
                "404": { "description": "Not found" }
            }
        });
    }
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "nms-ng API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Embedded API. In hardened mode (non-loopback bind or auth_mode=hardened) \
                            requests require a session cookie or Bearer token; /api/health and \
                            /api/openapi.json stay public. Webhook payload contract v1 is frozen per PRD §4.3."
        },
        "servers": [{ "url": "/", "description": "same origin" }],
        "paths": paths,
    })
}

fn webhook_test(shared: &Arc<Shared>) -> Vec<u8> {
    let (url, enabled_note) = {
        let conn = shared.store.lock();
        let url = db::get_setting_or(&conn, "webhook_url", "");
        let en = db::get_setting_or(&conn, "webhook_enabled", "0");
        (url, en)
    };
    if url.is_empty() {
        return json("400 Bad Request", serde_json::json!({"error":"webhook_url is not configured"}));
    }
    if enabled_note != "1" {
        return json("400 Bad Request", serde_json::json!({"error":"webhook_enabled is 0; enable it in settings"}));
    }
    let payload = serde_json::json!({
        "type": "nms.test",
        "ts": chrono::Utc::now().to_rfc3339(),
        "message": "NMS webhook connectivity test",
    });
    // NOTE: no DB lock held during network I/O.
    let result = engine::jobs::send_webhook(&url, payload);
    {
        let conn = shared.store.lock();
        match result {
            Ok(status) => {
                db::audit(&conn, "web", "webhook.test", &url, &format!("status={status}"));
                json("200 OK", serde_json::json!({"sent": true, "status": status}))
            }
            Err(e) => {
                db::audit(&conn, "web", "webhook.test", &url, &format!("failed: {e}"));
                json("502 Bad Gateway", serde_json::json!({"sent": false, "error": e}))
            }
        }
    }
}

fn text(status: &str, body: String) -> Vec<u8> {
    response(status, "text/plain; charset=utf-8", body.into_bytes())
}

fn json(status: &str, value: serde_json::Value) -> Vec<u8> {
    response(status, "application/json", serde_json::to_vec(&value).unwrap_or_default())
}

fn set_message(shared: &Arc<Shared>, message: &str) {
    *shared.message.lock().unwrap() = message.to_string();
}

fn start_job(shared: &Arc<Shared>, p: &Params, kind: Job) -> Vec<u8> {
    {
        let mut current = shared.job.lock().unwrap();
        if *current != Job::Idle {
            return text("409 Conflict", format!("{} already running", current.as_str()));
        }
        *current = kind;
    }
    if kind == Job::Discover && shared.monitoring.swap(false, Ordering::Relaxed) {
        set_message(shared, "monitor paused for discovery");
    }
    set_message(shared, "queued");
    let sh = shared.clone();
    let pp = p.clone();
    std::thread::spawn(move || run_job(sh, pp, kind));
    text("202 Accepted", format!("{} started", kind.as_str()))
}

fn run_job(shared: Arc<Shared>, p: Params, kind: Job) {
    let _engine = shared.engine_lock.lock().unwrap();
    set_message(&shared, &format!("{} running", kind.as_str()));
    let result = match kind {
        Job::Discover => discover::run(discover::Params {
            extra_subnets: p.extra_subnets.clone(),
            full: false,
            big_threshold: 4096,
            sample: 2048,
            budget: Duration::from_secs(10 * 60),
            no_auto: false,
            scan: ScanParams { rate_pps: 2000.0, concurrency: 512, timeout_ms: 500, payload_len: 32 },
            out_dir: p.out_dir.clone(),
            walk_budget: 24,
            snmp_community: "public".into(),
            deep: true,
            retire_days: 30,
        })
        .map(|m| {
            if let Ok(ids) = engine::ops::sync_model(
                &shared.store.lock(),
                &m,
                db::get_setting_or(&shared.store.lock(), "site_auto_prefix", "24")
                    .parse()
                    .unwrap_or(24),
            ) {
                format!(
                    "discovery complete: {} devices, {} subnets (inventory synced: {})",
                    m.devices.len(),
                    m.subnets.len(),
                    ids.len()
                )
            } else {
                format!("discovery complete: {} devices, {} subnets", m.devices.len(), m.subnets.len())
            }
        }),
        Job::Check => match engine::ops::run_cycle(&check_params(&p), &shared.store) {
            Ok((result, stats)) => {
                for transition in &result.transitions {
                    push_transition(&shared, transition);
                }
                *shared.last_stats.lock().unwrap() = Some(stats.clone());
                Ok(format!(
                    "check complete: up={up} down_root={down} unreachable={unreach} \
                         degraded={deg} events=+{ev} queued={q}",
                    up = stats.up,
                    down = stats.down_root,
                    unreach = stats.unreachable,
                    deg = stats.degraded,
                    ev = stats.new_events,
                    q = stats.queued
                ))
            }
            Err(e) => Err(e),
        },
        Job::Idle => unreachable!(),
    };
    let changed = result.is_ok();
    let message = result.unwrap_or_else(|e| format!("{} failed: {e}", kind.as_str()));
    if changed {
        shared.revision.fetch_add(1, Ordering::Relaxed);
    }
    println!("[server] {message}");
    set_message(&shared, &message);
    *shared.job.lock().unwrap() = Job::Idle;
}

fn check_params(p: &Params) -> check::Params {
    check::Params {
        extra_subnets: p.extra_subnets.clone(),
        scan: ScanParams { rate_pps: 1500.0, concurrency: 1024, timeout_ms: 1000, payload_len: 32 },
        out_dir: p.out_dir.clone(),
        max_targets: 200_000,
        budget_secs: 115,
        confirm_down: 1,
    }
}

fn start_monitor(shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    if shared.monitoring.swap(true, Ordering::Relaxed) {
        return text("409 Conflict", "monitor is already running".into());
    }
    set_message(shared, "monitor starting");
    let sh = shared.clone();
    let pp = p.clone();
    std::thread::spawn(move || monitor_loop(sh, pp));
    text("202 Accepted", "monitor started".into())
}

fn monitor_loop(shared: Arc<Shared>, p: Params) {
    while shared.monitoring.load(Ordering::Relaxed) {
        let interval = {
            let conn = shared.store.lock();
            Duration::from_secs(
                db::get_setting_or(&conn, "poll_interval_secs", &p.interval_secs.to_string())
                    .parse()
                    .unwrap_or(p.interval_secs)
                    .max(5),
            )
        };
        let started = std::time::Instant::now();
        {
            let _engine = shared.engine_lock.lock().unwrap();
            if !shared.monitoring.load(Ordering::Relaxed) {
                break;
            }
            match engine::ops::run_cycle(&check_params(&p), &shared.store) {
                Ok((result, stats)) => {
                    for transition in &result.transitions {
                        push_transition(&shared, transition);
                    }
                    *shared.last_stats.lock().unwrap() = Some(stats.clone());
                    shared.revision.fetch_add(1, Ordering::Relaxed);
                    let message = format!(
                        "monitor: up={up} down_root={down} unreachable={unreach} \
                             degraded={deg} | events=+{ev} queued={q} | cycle {} ms",
                        stats.duration_ms,
                        up = stats.up,
                        down = stats.down_root,
                        unreach = stats.unreachable,
                        deg = stats.degraded,
                        ev = stats.new_events,
                        q = stats.queued
                    );
                    println!("[server] {message}");
                    set_message(&shared, &message);
                }
                Err(e) => set_message(&shared, &format!("monitor sweep failed: {e}")),
            }
        }
        let wait = interval.saturating_sub(started.elapsed());
        let slices = (wait.as_millis() / 250).max(1);
        for _ in 0..slices {
            if !shared.monitoring.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    set_message(&shared, "monitor stopped");
    println!("[server] monitor stopped");
}

fn ping_endpoint(query: &str) -> Vec<u8> {
    let ip = query
        .split('&')
        .find_map(|part| part.strip_prefix("ip="))
        .and_then(|raw| raw.parse::<Ipv4Addr>().ok());
    let Some(ip) = ip else {
        return json("400 Bad Request", serde_json::json!({"error":"query parameter ip is required"}));
    };
    let mut pinger = match engine::ping::open(1000, 32) {
        Ok(p) => p,
        Err(e) => return json("500 Internal Server Error", serde_json::json!({"error":e.to_string()})),
    };
    let started = std::time::Instant::now();
    let result = pinger.ping(ip, None);
    json(
        "200 OK",
        serde_json::json!({
            "ip": ip.to_string(),
            "up": result.up,
            "rtt_ms": result.rtt_ms,
            "reply_ttl": result.reply_ttl,
            "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
        }),
    )
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

fn associate_endpoint(query: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    let device = query_value(query, "device").and_then(|raw| raw.parse::<Ipv4Addr>().ok());
    let Some(device) = device else {
        return json("400 Bad Request", serde_json::json!({"error":"device IPv4 address is required"}));
    };
    let wap = query_value(query, "wap")
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| raw.parse::<Ipv4Addr>().ok());
    let mut model = match Model::load(&p.out_dir.join("model.json")) {
        Ok(model) => model,
        Err(e) => return json("404 Not Found", serde_json::json!({"error":e.to_string()})),
    };
    let Some(device_idx) = model.devices.iter().position(|d| d.ip == device) else {
        return json("404 Not Found", serde_json::json!({"error":"device not found"}));
    };
    if model.devices[device_idx].role != engine::model::Role::Endpoint {
        return json("400 Bad Request", serde_json::json!({"error":"only endpoints can be assigned to a WAP"}));
    }
    if let Some(wap_ip) = wap {
        let valid = model.devices.iter().any(|candidate| {
            candidate.ip == wap_ip
                && candidate.role == engine::model::Role::Wap
                && candidate.subnet == model.devices[device_idx].subnet
        });
        if !valid {
            return json("400 Bad Request", serde_json::json!({"error":"WAP not found in this endpoint subnet"}));
        }
    }
    model.devices[device_idx].wap = wap;
    model.devices[device_idx].wap_source = wap.map(|_| "manual".into());
    model.generated_at = chrono::Utc::now().to_rfc3339();
    if let Err(e) = model.save(&p.out_dir.join("model.json")) {
        return json("500 Internal Server Error", serde_json::json!({"error":e.to_string()}));
    }
    if let Ok(page) = report::render(&model, 3500) {
        let _ = std::fs::write(p.out_dir.join("map.html"), page);
    }
    shared.revision.fetch_add(1, Ordering::Relaxed);
    push_event(
        shared,
        Event {
            at: chrono::Utc::now().to_rfc3339(),
            kind: "association".into(),
            ip: device.to_string(),
            role: "endpoint".into(),
            subnet: model.devices[device_idx].subnet.clone(),
            message: wap.map_or_else(
                || "WAP assignment cleared".into(),
                |ip| format!("assigned to WAP {ip}"),
            ),
        },
    );
    json(
        "200 OK",
        serde_json::json!({"device":device.to_string(),"wap":wap.map(|ip| ip.to_string())}),
    )
}

fn push_transition(shared: &Arc<Shared>, transition: &Transition) {
    let kind = match (transition.from, transition.to) {
        (Some(State::Up), State::Down) => "down",
        (Some(State::Down), State::Up) => "recovered",
        (None, State::Up) => "new",
        _ => "changed",
    };
    push_event(
        shared,
        Event {
            at: chrono::Utc::now().to_rfc3339(),
            kind: kind.into(),
            ip: transition.ip.to_string(),
            role: transition.role.label().into(),
            subnet: transition.subnet.clone(),
            message: format!("{} {kind}", transition.role.label()),
        },
    );
}

fn push_event(shared: &Arc<Shared>, event: Event) {
    let mut events = shared.events.lock().unwrap();
    events.push_front(event);
    while events.len() > 30 {
        events.pop_back();
    }
}

fn routes_endpoint() -> Vec<u8> {
    let mut body = String::from("prefix               next-hop         metric\n");
    for route in engine::routes::read() {
        body += &format!(
            "{:<20} {:<16} {}\n",
            route.prefix,
            route.next_hop.map_or("-".into(), |g| g.to_string()),
            route.metric
        );
    }
    text("200 OK", body)
}

fn ifaces_endpoint() -> Vec<u8> {
    let mut body = String::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                let prefix = engine::netutil::mask_to_prefix(v4.netmask);
                body += &format!("{:<24} {}/{}\n", iface.name, v4.ip, prefix);
            }
        }
    }
    text("200 OK", body)
}

const NO_MODEL_HTML: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NMS control panel</title><style>
html,body{height:100%;margin:0;background:#0b1220;color:#e2e8f0;font:15px system-ui}
body{display:grid;place-items:center}.card{width:min(560px,calc(100% - 48px));background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:30px}
button{background:#2563eb;color:#fff;border:0;border-radius:7px;padding:10px 16px;cursor:pointer}#status{color:#94a3b8;margin-top:16px}
</style></head><body><div class="card"><h1>NMS control panel</h1><p>No model exists yet.</p>
<button id="discover">Discover network</button><div id="status">Ready</div></div>
<script>const b=document.getElementById('discover'),s=document.getElementById('status');b.onclick=async()=>{b.disabled=true;s.textContent='Discovery queued...';const r=await fetch('/api/discover',{method:'POST'});if(!r.ok){s.textContent=await r.text();b.disabled=false;return}const t=setInterval(async()=>{const j=await(await fetch('/api/status')).json();s.textContent=j.message;if(j.job==='idle'){clearInterval(t);location.reload()}},1500)};</script>
</body></html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shared() -> Arc<Shared> {
        Arc::new(Shared {
            job: Mutex::new(Job::Idle),
            message: Mutex::new("ready".into()),
            monitoring: Arc::new(AtomicBool::new(false)),
            engine_lock: Mutex::new(()),
            revision: AtomicU64::new(0),
            events: Mutex::new(VecDeque::new()),
            store: Arc::new(engine::db::Db::open_memory().unwrap()),
            last_stats: Mutex::new(None),
            started_ts: chrono::Utc::now().timestamp(),
            hardened: false,
        })
    }

    #[test]
    fn openapi_covers_every_registered_route() {
        let spec = openapi_spec();
        assert_eq!(spec["openapi"], "3.0.3");
        let paths = spec["paths"].as_object().expect("paths object");
        for (method, path, summary) in API_ROUTES {
            let node = paths
                .get(*path)
                .unwrap_or_else(|| panic!("openapi missing path {path}"));
            assert!(
                node.get(method.to_lowercase()).is_some(),
                "openapi missing {method} {path}"
            );
            assert!(!summary.is_empty());
        }
    }

    #[test]
    fn health_is_ok_on_healthy_store() {
        let resp = health_endpoint(&test_shared());
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        let body = &text[text.find('{').unwrap()..];
        let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["components"]["database"]["status"], "ok");
        assert_eq!(v["components"]["scheduler"]["status"], "idle");
        assert_eq!(v["components"]["webhook_queue"]["pending"], 0);
    }
}
