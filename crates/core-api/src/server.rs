use engine::check::{self, Transition};
use engine::db;
use engine::discover;
use engine::ScanParams;
use ipnet::Ipv4Net;
use engine::model::{Model, State};
use engine::report;
use anyhow::Result;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

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
    Inspect,
    Check,
}

impl Job {
    fn as_str(self) -> &'static str {
        match self {
            Job::Idle => "idle",
            Job::Discover => "discover",
            Job::Inspect => "inspect",
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
    // Brute-force throttle state (FR-PLAT-005): username -> (failures, last
    // failure unix secs). NOTE: in-memory only — counters reset on restart and
    // each replica throttles independently; persistent/distributed rate
    // limiting arrives with the Postgres path (PRD §6).
    login_failures: Mutex<HashMap<String, (u32, i64)>>,
}

/// Failed attempts allowed per username within the throttle window before it
/// locks; the 6th failure trips the lock.
const LOGIN_MAX_FAILURES: u32 = 6;
/// Throttle window and lockout duration (seconds).
const LOGIN_WINDOW_SECS: i64 = 10 * 60;

/// Pure decision core for login throttling: true when an attempt should be
/// rejected outright because `count` failures were recorded at `last_ts`
/// (unix secs) and `now` is still inside the window.
fn throttle_decision(count: u32, last_ts: i64, now: i64) -> bool {
    count >= LOGIN_MAX_FAILURES && now.saturating_sub(last_ts) < LOGIN_WINDOW_SECS
}

fn login_throttled(shared: &Shared, username: &str, now: i64) -> bool {
    match shared.login_failures.lock().unwrap_or_else(|e| e.into_inner()).get(username) {
        Some(&(count, last_ts)) => throttle_decision(count, last_ts, now),
        None => false,
    }
}

fn record_login_failure(shared: &Shared, username: &str, now: i64) {
    let mut map = shared.login_failures.lock().unwrap_or_else(|e| e.into_inner());
    let entry = match map.get(username) {
        Some(&(count, last_ts)) if now.saturating_sub(last_ts) < LOGIN_WINDOW_SECS => {
            (count + 1, now)
        }
        _ => (1, now),
    };
    if map.len() >= 4096 {
        map.retain(|_, (_, ts)| now.saturating_sub(*ts) < LOGIN_WINDOW_SECS);
    }
    map.insert(username.to_string(), entry);
}

/// Resolve the authenticated principal for a request, if any.
/// Bearer tokens (automation) and session cookies both hash to stored values.
fn resolve_principal(shared: &Shared, authorization: Option<&str>, cookie: Option<&str>) -> Option<db::PrincipalRec> {
    let conn = shared.store.lock();
    if let Some(header) = authorization {
        let raw = header.strip_prefix("Bearer ").map(str::trim).filter(|s| !s.is_empty());
        if let Some(raw) = raw {
            let hashed = engine::auth::token_hash(raw);
            if let Ok(Some(principal)) = db::api_token_principal(&conn, &hashed) {
                return Some(principal);
            }
        }
    }
    let raw = cookie
        .and_then(|c| c.split(';').find_map(|part| part.trim().strip_prefix("nms_session=")))
        .filter(|s| !s.is_empty())?;
    db::session_principal(&conn, &engine::auth::token_hash(raw)).ok().flatten()
}

/// Apply the complete request authorization policy and return the authenticated
/// principal for audit attribution. A vault mutation is gated even in open
/// mode; other routes retain the historical open-mode behavior.
fn authorization_gate(
    shared: &Shared,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    cookie: Option<&str>,
) -> Result<Option<db::PrincipalRec>, Vec<u8>> {
    let vault_mutation = (method == "POST" && path == "/api/credentials")
        || (method == "DELETE" && path.starts_with("/api/credentials/"));
    if !shared.hardened && !vault_mutation {
        return Ok(None);
    }
    let Some((rank, is_api)) = engine::auth::requirement(method, path) else {
        return Ok(None);
    };
    let principal = resolve_principal(shared, authorization, cookie);
    match principal {
        None => Err(unauthorized(is_api)),
        Some(principal) => {
            let role = engine::auth::Role::parse(&principal.role)
                .unwrap_or(engine::auth::Role::Viewer);
            if engine::auth::authorized(role, is_api, rank) {
                Ok(Some(principal))
            } else {
                Err(forbidden(is_api))
            }
        }
    }
}

fn login_page(err: Option<&str>) -> Vec<u8> {
    login_page_status("200 OK", err)
}

fn login_page_status(status: &str, err: Option<&str>) -> Vec<u8> {
    let err_html = err
        .map(|e| format!(r#"<div class="err">{}</div>"#, crate::ui::esc(e)))
        .unwrap_or_default();
    html(
        status,
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

/// Hardened-mode login with per-username brute-force throttling (FR-PLAT-005).
fn login_submit(body: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let username = form_value(body, "username").unwrap_or_default();
    let password = form_value(body, "password").unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    if shared.hardened && login_throttled(shared, &username, now) {
        db::audit(&shared.store.lock(), "web:anonymous", "auth.throttled", &username, "");
        return login_page_status(
            "429 Too Many Requests",
            Some("too many failed attempts; try again in a few minutes"),
        );
    }
    let user = db::get_user(&shared.store.lock(), &username)
        .ok()
        .flatten()
        .filter(|u| !u.disabled);
    match user {
        Some(u) if engine::auth::verify_password(&password, &u.password_hash) => {
            shared.login_failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&username);
            let (raw, hashed) = engine::auth::new_token();
            let expires = chrono::Utc::now().timestamp() + 7 * 86_400;
            let _ = db::create_session(&shared.store.lock(), &hashed, u.id, &u.role, expires);
            db::audit(&shared.store.lock(), &format!("web:{}", u.username), "auth.login", &u.username, "");
            session_response(&raw, 7 * 86_400)
        }
        _ => {
            record_login_failure(shared, &username, now);
            db::audit(&shared.store.lock(), "web:anonymous", "auth.failure", &username, "");
            login_page(Some("invalid username or password"))
        }
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
        login_failures: Mutex::new(HashMap::new()),
        store,
    });
    let url = format!("http://{addr}");
    engine::logging::init(p.out_dir.join("nms.log"));
    engine::logging::info(&format!("server starting: {url} hardened={hardened}"));
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

    let principal = match authorization_gate(&shared, method, path, authorization.as_deref(), cookie.as_deref()) {
        Ok(principal) => principal,
        Err(response) => {
            let _ = writer.write_all(&response);
            let _ = writer.flush();
            return;
        }
    };

    let response = {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            route_as(method, path, query, &body, cookie.as_deref(), principal.as_ref().map(|p| p.actor.as_str()), &shared, &p)
        }));
        match result {
            Ok(resp) => resp,
            Err(_) => {
                engine::logging::error(&format!("handler panicked: {} {}", method, path));
                text("500 Internal Server Error", "internal error".into())
            }
        }
    };
    if path.starts_with("/api/") {
        let status = String::from_utf8_lossy(&response[..response.len().min(24)]).to_string();
        engine::logging::info(&format!("{} {} -> {}", method, path, status.split_whitespace().nth(1).unwrap_or("?")));
    }
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

#[cfg(test)]
fn route(method: &str, path: &str, query: &str, body: &str, cookie: Option<&str>, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    route_as(method, path, query, body, cookie, None, shared, p)
}

#[allow(clippy::too_many_arguments)]
fn route_as(method: &str, path: &str, query: &str, body: &str, cookie: Option<&str>, actor: Option<&str>, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
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
            let completed_day = (chrono::Utc::now().date_naive() - chrono::Duration::days(1))
                .format("%Y-%m-%d")
                .to_string();
            let pdf = p.out_dir.join("reports").join(format!("daily-{completed_day}.pdf"));
            let pdf_date = std::fs::read(&pdf)
                .map(|bytes| bytes.starts_with(b"%PDF"))
                .unwrap_or(false)
                .then_some(completed_day.as_str());
            html("200 OK", crate::ui::reports_page_with_pdf(&shared.store.lock(), hours.clamp(1, 24 * 45), pdf_date))
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
        ("GET", "/api/report/availability.pdf") => availability_pdf_endpoint(query, p),
        ("POST", "/api/settings") => settings_save(body, shared),
        ("POST", "/api/credentials") => credential_write(body, actor.unwrap_or("web:admin"), shared, p),
        _ if method == "DELETE" && path.starts_with("/api/credentials/") => {
            credential_delete(path.trim_start_matches("/api/credentials/"), actor.unwrap_or("web:admin"), shared, p)
        }
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
        ("POST", "/login") => login_submit(body, shared),
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
            let job = *shared.job.lock().unwrap_or_else(|e| e.into_inner());
            let stats = shared.last_stats.lock().unwrap_or_else(|e| e.into_inner()).clone();
            json(
                "200 OK",
                serde_json::json!({
                    "job": job.as_str(),
                    "monitoring": shared.monitoring.load(Ordering::Relaxed),
                    "message": shared.message.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                    "revision": shared.revision.load(Ordering::Relaxed),
                    "progress": engine::progress::snapshot(),
                    "events": shared.events.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect::<Vec<_>>(),
                    "ops": stats,
                }),
            )
        }
        ("POST", "/api/discover") => start_job(shared, p, Job::Discover),
        ("POST", "/api/inspect") => start_job(shared, p, Job::Inspect),
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

fn credential_write(body: &str, actor: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    let (id, secret): (String, Zeroizing<Vec<u8>>) = if body.trim_start().starts_with('{') {
        let value: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return json("400 Bad Request", serde_json::json!({"error":"invalid credential request"})),
        };
        (
            value.get("credential_ref").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            Zeroizing::new(value.get("secret").and_then(|v| v.as_str()).unwrap_or_default().as_bytes().to_vec()),
        )
    } else {
        (
            form_value(body, "credential_ref").unwrap_or_default(),
            Zeroizing::new(form_value(body, "secret").unwrap_or_default().into_bytes()),
        )
    };
    if id.is_empty() || secret.is_empty() {
        return json("400 Bad Request", serde_json::json!({"error":"credential_ref and secret are required"}));
    }
    match engine::vault::write_secret(&p.out_dir, &id, &secret) {
        Ok(()) => {
            db::audit(&shared.store.lock(), actor, "credential.create", &id, "encrypted credential stored");
            json("201 Created", serde_json::json!({"credential_ref": id, "status":"stored"}))
        }
        Err(e) => json("400 Bad Request", serde_json::json!({"error": e.to_string()})),
    }
}

fn credential_delete(encoded_id: &str, actor: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    let id = url_decode(encoded_id);
    match engine::vault::delete_secret(&p.out_dir, &id) {
        Ok(()) => {
            db::audit(&shared.store.lock(), actor, "credential.delete", &id, "encrypted credential deleted");
            json("200 OK", serde_json::json!({"credential_ref": id, "status":"deleted"}))
        }
        Err(e) => json("404 Not Found", serde_json::json!({"error": e.to_string()})),
    }
}

fn availability_pdf_endpoint(query: &str, p: &Params) -> Vec<u8> {
    let date = query_param(query, "date").unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let Ok(parsed) = chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d") else {
        return text("400 Bad Request", "date must be YYYY-MM-DD".into());
    };
    let safe_date = parsed.format("%Y-%m-%d").to_string();
    let path = p.out_dir.join("reports").join(format!("daily-{safe_date}.pdf"));
    match std::fs::read(&path) {
        Ok(bytes) if bytes.starts_with(b"%PDF") => response("200 OK", "application/pdf", bytes),
        Ok(_) => text("404 Not Found", "PDF report is not available".into()),
        Err(_) => text("404 Not Found", "PDF report is not available".into()),
    }
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
        // Write-only secret: blank submission keeps the stored password.
        if key == "snow_password" && val.is_empty() {
            continue;
        }
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
        *shared.job.lock().unwrap_or_else(|e| e.into_inner()),
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
                    "last_cycle": shared.last_stats.lock().unwrap_or_else(|e| e.into_inner()).clone(),
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
    ("GET", "/api/report/availability.pdf", "Daily availability PDF when a rendered artifact exists"),
    ("POST", "/api/discover", "Queue a network discovery crawl"),
        ("POST", "/api/inspect", "Queue a deep device inspection pass (SNMP identity, ifTable, LLDP/CDP)"),
    ("POST", "/api/inspect", "Queue a deep device inspection pass (SNMP identity, ifTable, LLDP/CDP)"),
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
    ("POST", "/api/credentials", "Write one encrypted credential and return its opaque reference"),
    ("DELETE", "/api/credentials/{ref}", "Delete one encrypted credential reference"),
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
    *shared.message.lock().unwrap_or_else(|e| e.into_inner()) = message.to_string();
}

fn start_job(shared: &Arc<Shared>, p: &Params, kind: Job) -> Vec<u8> {
    {
        let mut current = shared.job.lock().unwrap_or_else(|e| e.into_inner());
        if *current != Job::Idle {
            return text("409 Conflict", format!("{} already running", current.as_str()));
        }
        *current = kind;
    }
    if matches!(kind, Job::Discover | Job::Inspect) && shared.monitoring.swap(false, Ordering::Relaxed) {
        set_message(shared, "monitor paused for discovery");
    }
    set_message(shared, "queued");
    let sh = shared.clone();
    let pp = p.clone();
    std::thread::spawn(move || run_job(sh, pp, kind));
    text("202 Accepted", format!("{} started", kind.as_str()))
}

fn run_job(shared: Arc<Shared>, p: Params, kind: Job) {
    // Poison-tolerant: a panic while holding these locks must not wedge the
    // whole control plane (that was the "system locked up" failure mode).
    let _engine = shared
        .engine_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    set_message(&shared, &format!("{} running", kind.as_str()));
    engine::logging::info(&format!("job start: {}", kind.as_str()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match kind {
        Job::Inspect => {
            let community = db::get_setting_or(&shared.store.lock(), "snmp_community", "public");
            engine::inspect::run(&shared.store, &p.out_dir, &community, 500, 161, 0).map(|stats| {
                format!(
                    "inspection complete: {} device(s) | snmp {} | interfaces {} | neighbors {} | {} ms",
                    stats.devices, stats.snmp_ok, stats.interfaces, stats.neighbors,
                    stats.duration_ms
                )
            })
        }
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
                *shared.last_stats.lock().unwrap_or_else(|e| e.into_inner()) = Some(stats.clone());
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
    }));

    // Always release the job slot - even if the job body panicked.
    *shared.job.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Job::Idle;

    let message = match result {
        Ok(Ok(message)) => {
            shared.revision.fetch_add(1, Ordering::Relaxed);
            message
        }
        Ok(Err(e)) => format!("{} failed: {e}", kind.as_str()),
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            format!("{} panicked: {detail}", kind.as_str())
        }
    };
    println!("[server] {message}");
    set_message(&shared, &message);
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
            let _engine = shared.engine_lock.lock().unwrap_or_else(|e| e.into_inner());
            if !shared.monitoring.load(Ordering::Relaxed) {
                break;
            }
            match engine::ops::run_cycle(&check_params(&p), &shared.store) {
                Ok((result, stats)) => {
                    for transition in &result.transitions {
                        push_transition(&shared, transition);
                    }
                    *shared.last_stats.lock().unwrap_or_else(|e| e.into_inner()) = Some(stats.clone());
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
    let mut events = shared.events.lock().unwrap_or_else(|e| e.into_inner());
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
            login_failures: Mutex::new(HashMap::new()),
        })
    }

    fn hardened_shared() -> Arc<Shared> {
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
            hardened: true,
            login_failures: Mutex::new(HashMap::new()),
        })
    }

    fn test_params() -> Params {
        Params {
            port: 0,
            bind: "127.0.0.1".into(),
            no_open: true,
            interval_secs: 30,
            extra_subnets: vec![],
            out_dir: PathBuf::from("output"),
        }
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

    #[test]
    fn credential_api_is_write_only_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = test_params();
        p.out_dir = dir.path().to_path_buf();
        std::env::set_var("NMS_VAULT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let shared = test_shared();
        let body = r#"{"credential_ref":"router-r1","secret":"PRIVATE KEY MATERIAL"}"#;
        let write = String::from_utf8(route_as("POST", "/api/credentials", "", body, None, Some("token:admin-vault"), &shared, &p)).unwrap();
        assert!(write.starts_with("HTTP/1.1 201 Created"));
        assert!(write.contains("router-r1"));
        assert!(!write.contains("PRIVATE KEY MATERIAL"));
        let record = std::fs::read(dir.path().join("credentials/router-r1.json")).unwrap();
        assert!(!String::from_utf8_lossy(&record).contains("PRIVATE KEY MATERIAL"));
        let deleted = String::from_utf8(route_as("DELETE", "/api/credentials/router-r1", "", "", None, Some("token:admin-vault"), &shared, &p)).unwrap();
        assert!(deleted.starts_with("HTTP/1.1 200 OK"));
        assert!(!dir.path().join("credentials/router-r1.json").exists());
        let conn = shared.store.lock();
        let audit_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'credential.%'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(audit_count, 2);
        let actor: String = conn.query_row(
            "SELECT actor FROM audit_log WHERE action='credential.create' ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(actor, "token:admin-vault");
        std::env::remove_var("NMS_VAULT_KEY");
    }

    #[test]
    fn credential_mutations_require_admin_rank() {
        assert_eq!(engine::auth::requirement("POST", "/api/credentials"), Some((2, true)));
        assert_eq!(engine::auth::requirement("DELETE", "/api/credentials/router-r1"), Some((2, true)));
        assert!(!engine::auth::authorized(engine::auth::Role::Operator, true, 2));
        assert!(engine::auth::authorized(engine::auth::Role::Admin, true, 2));
    }

    #[test]
    fn credential_gate_rejects_anonymous_and_operator_but_allows_admin() {
        let shared = test_shared();
        let dir = tempfile::tempdir().unwrap();
        let mut params = test_params();
        params.out_dir = dir.path().to_path_buf();
        std::env::set_var("NMS_VAULT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let add = |name: &str, role: &str| {
            let (raw, hashed) = engine::auth::new_token();
            db::add_api_token(&shared.store.lock(), &hashed, name, role).unwrap();
            (raw, hashed)
        };
        let (operator, _) = add("ops", "operator");
        let (admin, _) = add("vault-admin", "admin");
        let denied = authorization_gate(&shared, "POST", "/api/credentials", None, None).unwrap_err();
        assert!(String::from_utf8(denied).unwrap().starts_with("HTTP/1.1 401"));
        assert!(!dir.path().join("credentials/denied.json").exists());
        let denied = authorization_gate(&shared, "POST", "/api/credentials", Some(&format!("Bearer {operator}")), None).unwrap_err();
        assert!(String::from_utf8(denied).unwrap().starts_with("HTTP/1.1 403"));
        assert!(!dir.path().join("credentials/denied.json").exists());
        let principal = authorization_gate(&shared, "POST", "/api/credentials", Some(&format!("Bearer {admin}")), None).unwrap().unwrap();
        assert_eq!(principal.actor, "token:vault-admin");
        engine::vault::write_secret(dir.path(), "r1", b"secret").unwrap();
        assert!(authorization_gate(&shared, "DELETE", "/api/credentials/r1", Some(&format!("Bearer {operator}")), None).is_err());
        assert!(dir.path().join("credentials/r1.json").exists());
        assert!(authorization_gate(&shared, "DELETE", "/api/credentials/r1", Some(&format!("Bearer {admin}")), None).is_ok());
        std::env::remove_var("NMS_VAULT_KEY");
    }

    #[test]
    fn throttle_allows_below_six_failures_inside_window() {
        assert!(!throttle_decision(0, 1_000, 1_000));
        assert!(!throttle_decision(5, 1_000, 1_000 + LOGIN_WINDOW_SECS - 1));
    }

    #[test]
    fn throttle_blocks_from_sixth_failure_until_window_elapses() {
        assert!(throttle_decision(6, 1_000, 1_000));
        assert!(throttle_decision(6, 1_000, 1_000 + LOGIN_WINDOW_SECS - 1));
        assert!(throttle_decision(9, 1_000, 1_000 + LOGIN_WINDOW_SECS - 1));
        // Lockout lifts once the window has fully elapsed since the last failure.
        assert!(!throttle_decision(6, 1_000, 1_000 + LOGIN_WINDOW_SECS));
        assert!(!throttle_decision(50, 1_000, 1_000 + LOGIN_WINDOW_SECS * 3));
    }

    #[test]
    fn throttle_rejects_before_password_check_and_audits() {
        let shared = hardened_shared();
        let p = test_params();
        let body = "username=ghost&password=wrong";
        for attempt in 0..6 {
            let resp = route("POST", "/login", "", body, None, &shared, &p);
            let text = String::from_utf8(resp).unwrap();
            assert!(
                text.starts_with("HTTP/1.1 200 OK"),
                "attempt {attempt} should pass through: {text}"
            );
            assert!(text.contains("invalid username or password"), "{text}");
        }
        // 7th attempt: throttled regardless of password correctness...
        let resp = route("POST", "/login", "", body, None, &shared, &p);
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 429 Too Many Requests"), "{text}");
        assert!(text.contains("too many failed attempts"), "{text}");
        // ...even with the correct password (unknown user here: still 429).
        let conn = shared.store.lock();
        let throttled: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE action='auth.throttled'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(throttled, 1, "every rejection writes an auth.throttled audit entry");
    }

    #[test]
    fn successful_login_clears_failure_counter() {
        let shared = hardened_shared();
        let p = test_params();
        {
            let conn = shared.store.lock();
            let hash = engine::auth::hash_password("correct horse").unwrap();
            db::create_user(&conn, "alice", &hash, "viewer").unwrap();
        }
        let wrong = "username=alice&password=wrong";
        for _ in 0..3 {
            route("POST", "/login", "", wrong, None, &shared, &p);
        }
        let good = "username=alice&password=correct+horse";
        let resp = route("POST", "/login", "", good, None, &shared, &p);
        assert!(
            String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 303"),
            "valid credentials must log in"
        );
        // Counter cleared by success: 5 further failures must NOT trip the lock.
        for _ in 0..5 {
            let resp = route("POST", "/login", "", wrong, None, &shared, &p);
            assert!(String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 200 OK"));
        }
        assert!(!login_throttled(&shared, "alice", chrono::Utc::now().timestamp()));
        // The 6th failure after the successful login trips it again.
        route("POST", "/login", "", wrong, None, &shared, &p);
        assert!(login_throttled(&shared, "alice", chrono::Utc::now().timestamp()));
    }

    #[test]
    fn open_mode_login_is_not_throttled() {
        let shared = test_shared(); // hardened=false
        let p = test_params();
        let body = "username=ghost&password=wrong";
        for _ in 0..10 {
            let resp = route("POST", "/login", "", body, None, &shared, &p);
            assert!(String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 200 OK"));
        }
    }

    #[test]
    fn pdf_download_requires_valid_existing_artifact() {
        let shared = test_shared();
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(reports.join("daily-2026-08-24.pdf"), b"%PDF-1.7\nfake").unwrap();
        let mut p = test_params();
        p.out_dir = dir.path().to_path_buf();
        let ok = String::from_utf8(route("GET", "/api/report/availability.pdf", "date=2026-08-24", "", None, &shared, &p)).unwrap();
        assert!(ok.starts_with("HTTP/1.1 200 OK"));
        assert!(ok.contains("Content-Type: application/pdf"));
        let absent = String::from_utf8(route("GET", "/api/report/availability.pdf", "date=2026-08-23", "", None, &shared, &p)).unwrap();
        assert!(absent.starts_with("HTTP/1.1 404 Not Found"));
        let invalid = String::from_utf8(route("GET", "/api/report/availability.pdf", "date=not-a-date", "", None, &shared, &p)).unwrap();
        assert!(invalid.starts_with("HTTP/1.1 400 Bad Request"));
    }
}
