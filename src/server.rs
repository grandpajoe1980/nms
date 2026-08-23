use crate::check::{self, Transition};
use crate::discover;
use crate::engine::ScanParams;
use crate::model::{Model, State};
use crate::monitor;
use crate::report;
use anyhow::Result;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
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
    let shared = Arc::new(Shared {
        job: Mutex::new(Job::Idle),
        message: Mutex::new("ready".into()),
        monitoring: Arc::new(AtomicBool::new(false)),
        engine_lock: Mutex::new(()),
        revision: AtomicU64::new(0),
        events: Mutex::new(VecDeque::new()),
    });
    let url = format!("http://{addr}");
    println!("[*] NMS control panel: {url}");
    println!("[*] Ctrl+C stops the web server and any in-process monitor loop");
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
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {}
        }
    }
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let response = route(method, path, query, &shared, &p);
    let _ = writer.write_all(&response);
    let _ = writer.flush();
}

fn route(method: &str, path: &str, query: &str, shared: &Arc<Shared>, p: &Params) -> Vec<u8> {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            match Model::load(&p.out_dir.join("model.json")) {
                Ok(model) => match report::render(&model, 3500) {
                    Ok(page) => response("200 OK", "text/html; charset=utf-8", page.into_bytes()),
                    Err(e) => text("500 Internal Server Error", format!("map render failed: {e}")),
                },
                Err(_) => response("200 OK", "text/html; charset=utf-8", NO_MODEL_HTML.as_bytes().to_vec()),
            }
        }
        ("GET", "/api/model") => match std::fs::read(p.out_dir.join("model.json")) {
            Ok(body) => response("200 OK", "application/json", body),
            Err(_) => json("404 Not Found", serde_json::json!({"error":"no model yet"})),
        },
        ("GET", "/api/status") => {
            let job = *shared.job.lock().unwrap();
            json(
                "200 OK",
                serde_json::json!({
                    "job": job.as_str(),
                    "monitoring": shared.monitoring.load(Ordering::Relaxed),
                    "message": shared.message.lock().unwrap().clone(),
                    "revision": shared.revision.load(Ordering::Relaxed),
                    "events": shared.events.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
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
            budget: Duration::from_secs(45 * 60),
            no_auto: false,
            scan: ScanParams { rate_pps: 600.0, concurrency: 512, timeout_ms: 800, payload_len: 32 },
            out_dir: p.out_dir.clone(),
        })
        .map(|m| format!("discovery complete: {} devices, {} subnets", m.devices.len(), m.subnets.len())),
        Job::Check => check::sweep_once(&check_params(&p)).map(|result| {
            for transition in &result.transitions {
                if transition.from == Some(State::Up) && transition.to == State::Down {
                    monitor::record_down_alert(transition, &p.out_dir);
                }
                push_transition(&shared, transition);
            }
            let (up, down, _, _) = result.model.counts();
            format!("check complete: {up} known up, {down} known down")
        }),
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
    let interval = Duration::from_secs(p.interval_secs.max(5));
    while shared.monitoring.load(Ordering::Relaxed) {
        let started = std::time::Instant::now();
        {
            let _engine = shared.engine_lock.lock().unwrap();
            if !shared.monitoring.load(Ordering::Relaxed) {
                break;
            }
            match check::sweep_once(&check_params(&p)) {
                Ok(result) => {
                    let alerts: Vec<&Transition> = result
                        .transitions
                        .iter()
                        .filter(|t| t.from == Some(State::Up) && t.to == State::Down)
                        .collect();
                    for transition in &alerts {
                        monitor::record_down_alert(transition, &p.out_dir);
                    }
                    for transition in &result.transitions {
                        push_transition(&shared, transition);
                    }
                    shared.revision.fetch_add(1, Ordering::Relaxed);
                    let (up, down, _, _) = result.model.counts();
                    let message = format!(
                        "monitor: {up} known up, {down} known down, {} new alert(s)",
                        alerts.len()
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
