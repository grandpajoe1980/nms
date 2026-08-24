use crate::check::{self, Transition};
use crate::db;
use crate::discover;
use rusqlite::Connection;
use crate::engine::ScanParams;
use crate::model::{Model, State};
use crate::report;
use anyhow::Result;
use ipnet::Ipv4Net;
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
    store: Arc<crate::db::Db>,
    last_stats: Mutex<Option<crate::ops::CycleStats>>,
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
    let addr = format!("127.0.0.1:{}", p.port);
    let listener = TcpListener::bind(&addr)?;
    let store = Arc::new(crate::db::Db::open(&p.out_dir.join("ops.db"))?);
    let shared = Arc::new(Shared {
        job: Mutex::new(Job::Idle),
        message: Mutex::new("ready".into()),
        monitoring: Arc::new(AtomicBool::new(false)),
        engine_lock: Mutex::new(()),
        revision: AtomicU64::new(0),
        events: Mutex::new(VecDeque::new()),
        last_stats: Mutex::new(None),
        store,
    });
    let url = format!("http://{addr}");
    println!("[*] NMS control panel: {url}");
    println!("[*] Ctrl+C stops the web server and any in-process monitor loop");
    crate::jobs::start_housekeeping(Arc::clone(&shared.store));
    crate::jobs::start_webhook_sender(Arc::clone(&shared.store));
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
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {
                if let Some(v) = header
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|s| s.trim().parse().ok())
                {
                    content_length = v;
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
    let response = route(method, path, query, &body, &shared, &p);
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

fn route(method: &str, path: &str, query: &str, body: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
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
                crate::ui::availability_csv(&shared.store.lock(), hours.clamp(1, 24 * 45)),
            )
        }
        ("GET", "/api/report/devices.csv") => {
            let hours: i64 = query_param(query, "hours").and_then(|h| h.parse().ok()).unwrap_or(24);
            let site = query_param(query, "site").filter(|s| !s.is_empty());
            text_csv(
                "200 OK",
                crate::ui::devices_csv(&shared.store.lock(), hours.clamp(1, 24 * 45), site.as_deref()),
            )
        }
        ("POST", "/api/settings") => settings_save(body, shared),
        ("POST", "/api/device") => device_action(body, shared),
        ("POST", "/api/event/ack") => event_ack(body, shared),
        ("POST", "/api/webhook/test") => webhook_test(shared),
        ("POST", "/api/diagnose") => diagnose_endpoint(query, shared),
        ("POST", "/api/suggest_wap") => suggest_wap_endpoint(query, shared),
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
                    "progress": crate::progress::snapshot(),
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

fn device_action(body: &str, shared: &Arc<Shared>) -> Vec<u8> {
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
    let diag = match crate::diag::run_burst(ip, count, 25.0, 1000) {
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
    let prof = crate::profile::profile_endpoint(ip, mac_hint.as_deref(), &role_hint);
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
                "service": crate::profile::service_names().get(p).copied().unwrap_or("?"),
            })
        })
        .collect();
    json(
        "200 OK",
        serde_json::json!({
            "diag": diag,
            "hostname": prof.hostname,
            "device_class": prof.device_class,
            "services": services,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        }),
    )
}

fn suggest_wap_endpoint(query: &str, shared: &Arc<Shared>) -> Vec<u8> {
    let Some(ip) = query_param(query, "ip") else {
        return json("400 Bad Request", serde_json::json!({"error":"query parameter ip is required"}));
    };
    let conn = shared.store.lock();
    let Some(dev) = db::device_by_ip(&conn, &ip).ok().flatten() else {
        return json("404 Not Found", serde_json::json!({"error":"unknown device"}));
    };
    match wap_suggestion(&conn, dev.id, dev.site_id) {
        Some((wap_ip, r, n)) => json(
            "200 OK",
            serde_json::json!({"ip": ip, "wap": wap_ip, "correlation": r, "pairs": n}),
        ),
        None => json(
            "200 OK",
            serde_json::json!({"ip": ip, "suggestion": null,
                "note": "not enough aligned latency samples yet"}),
        ),
    }
}

/// Pearson correlation between the endpoint's RTT series and each candidate
/// WAP's series (samples paired within ±2.5 s). High correlation suggests the
/// endpoint rides that AP's radio/link.
fn wap_suggestion(
    conn: &Connection,
    device_id: i64,
    site_id: Option<i64>,
) -> Option<(String, f64, usize)> {
    fn rtt_series(conn: &Connection, id: i64, limit: i64) -> Vec<(i64, f64)> {
        let Ok(mut stmt) = conn.prepare(
            "SELECT ts, rtt_ms FROM samples WHERE device_id=?1 AND up=1 AND rtt_ms IS NOT NULL
             ORDER BY ts DESC LIMIT ?2",
        ) else {
            return Vec::new();
        };
        stmt.query_map(rusqlite::params![id, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?))
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    }

    let ep = rtt_series(conn, device_id, 60);
    if ep.len() < 8 {
        return None;
    }
    let waps: Vec<(i64, String)> = {
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, ip FROM devices WHERE role='wap' AND managed=1
             AND (?1 IS NULL OR site_id = ?1)",
        ) else {
            return None;
        };
        stmt.query_map(rusqlite::params![site_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    };
    let mut best: Option<(String, f64, usize)> = None;
    for (wid, wip) in waps {
        let ws = rtt_series(conn, wid, 120);
        let mut pairs: Vec<(f64, f64)> = Vec::new();
        for &(ets, ertt) in &ep {
            if let Some(&(_, wrtt)) =
                ws.iter().find(|(ts, _)| (ts - ets).abs() <= 2500)
            {
                pairs.push((ertt, wrtt));
            }
        }
        if pairs.len() < 8 {
            continue;
        }
        let n = pairs.len() as f64;
        let mx = pairs.iter().map(|p| p.0).sum::<f64>() / n;
        let my = pairs.iter().map(|p| p.1).sum::<f64>() / n;
        let cov: f64 = pairs.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
        let vx: f64 = pairs.iter().map(|p| (p.0 - mx).powi(2)).sum();
        let vy: f64 = pairs.iter().map(|p| (p.1 - my).powi(2)).sum();
        if vx < 0.01 || vy < 0.01 {
            continue;
        }
        let r = cov / (vx.sqrt() * vy.sqrt());
        if best.as_ref().is_none_or(|(_, br, _)| r.abs() > br.abs()) {
            best = Some((wip, r, pairs.len()));
        }
    }
    best.filter(|(_, r, _)| r.abs() >= 0.7)
}

fn webhook_test(shared: &Arc<Shared>) -> Vec<u8> {    let conn = shared.store.lock();
    let url = db::get_setting_or(&conn, "webhook_url", "");
    if url.is_empty() {
        return json("400 Bad Request", serde_json::json!({"error":"webhook_url is not configured"}));
    }
    let payload = serde_json::json!({
        "type": "nms.test",
        "ts": chrono::Utc::now().to_rfc3339(),
        "message": "NMS webhook connectivity test",
    });
    match crate::jobs::send_webhook(&url, payload) {
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
            deep: true,
        })
        .map(|m| {
            if let Ok(ids) = crate::ops::sync_model(
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
        Job::Check => match crate::ops::run_cycle(&check_params(&p), &shared.store) {
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
            match crate::ops::run_cycle(&check_params(&p), &shared.store) {
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
    let mut pinger = match crate::ping::open(1000, 32) {
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
    if model.devices[device_idx].role != crate::model::Role::Endpoint {
        return json("400 Bad Request", serde_json::json!({"error":"only endpoints can be assigned to a WAP"}));
    }
    if let Some(wap_ip) = wap {
        let valid = model.devices.iter().any(|candidate| {
            candidate.ip == wap_ip
                && candidate.role == crate::model::Role::Wap
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
    for route in crate::routes::read() {
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
                let prefix = crate::netutil::mask_to_prefix(v4.netmask);
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
