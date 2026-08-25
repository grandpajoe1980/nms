use crate::model::{Model, Role, State};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

#[derive(Serialize)]
struct MapNode {
    id: String,
    label: String,
    kind: String,
    state: String,
    ip: Option<String>,
    subnet: Option<String>,
    rtt: Option<f64>,
    hint: Option<String>,
    mac: Option<String>,
    wap: Option<String>,
    wap_source: Option<String>,
    hostname: Option<String>,
    device_class: Option<String>,
    x: f64,
    y: f64,
    size: f64,
}

#[derive(Serialize)]
struct MapLink {
    s: String,
    t: String,
}

#[derive(Serialize)]
struct MapSubnet {
    cidr: String,
    cx: f64,
    cy: f64,
    r: f64,
    count: usize,
    alive: u64,
    sampled: bool,
    origin: String,
}

#[derive(Serialize)]
struct Counts {
    up: usize,
    down: usize,
    unknown: usize,
    routers: usize,
    waps: usize,
    endpoints: usize,
    subnets: usize,
    hosts: u64,
}

#[derive(Serialize)]
struct MapData {
    generated: String,
    duration_ms: u64,
    backend: String,
    counts: Counts,
    nodes: Vec<MapNode>,
    links: Vec<MapLink>,
    subnets: Vec<MapSubnet>,
}

const GOLDEN: f64 = 2.399963229728653;

pub fn render(model: &Model, cap: usize) -> Result<String> {
    let wap_ips: BTreeSet<Ipv4Addr> = model
        .devices
        .iter()
        .filter(|d| d.role == Role::Wap)
        .map(|d| d.ip)
        .collect();
    let mut subnet_meta: HashMap<String, (u64, bool, String)> = HashMap::new();
    for s in &model.subnets {
        subnet_meta.insert(s.cidr.clone(), (s.alive, s.sampled, s.origin.clone()));
    }

    let mut by_sub: HashMap<String, Vec<usize>> = HashMap::new();
    let mut orphans: Vec<usize> = Vec::new();
    for (i, d) in model.devices.iter().enumerate() {
        match &d.subnet {
            Some(s) if subnet_meta.contains_key(s) => by_sub.entry(s.clone()).or_default().push(i),
            _ => orphans.push(i),
        }
    }

    struct Cluster {
        cidr: String,
        anchor: Option<usize>,
        routers: Vec<usize>,
        waps: Vec<usize>,
        endpoints: Vec<usize>,
        collapsed: bool,
        cx: f64,
        cy: f64,
        r: f64,
    }

    let mut clusters: Vec<Cluster> = Vec::new();
    for (cidr, members) in &by_sub {
        let mut routers: Vec<usize> = Vec::new();
        let mut waps: Vec<usize> = Vec::new();
        let mut endpoints: Vec<usize> = Vec::new();
        for &i in members {
            match model.devices[i].role {
                Role::Router => routers.push(i),
                Role::Wap => waps.push(i),
                Role::Endpoint => endpoints.push(i),
            }
        }
        routers.sort_by_key(|&i| u32::from(model.devices[i].ip));
        let anchor = routers.first().copied();
        clusters.push(Cluster {
            cidr: cidr.clone(),
            anchor,
            routers: if !routers.is_empty() { routers[1..].to_vec() } else { Vec::new() },
            waps,
            endpoints,
            collapsed: false,
            cx: 0.0,
            cy: 0.0,
            r: 0.0,
        });
    }

    let mut core: Option<Cluster> = None;
    if !orphans.is_empty() {
        let mut routers: Vec<usize> = orphans
            .iter()
            .copied()
            .filter(|&i| model.devices[i].role == Role::Router)
            .collect();
        routers.sort_by_key(|&i| u32::from(model.devices[i].ip));
        let others: Vec<usize> = orphans
            .iter()
            .copied()
            .filter(|&i| model.devices[i].role != Role::Router)
            .collect();
        let anchor = routers.first().copied();
        core = Some(Cluster {
            cidr: "core".into(),
            anchor,
            routers: if !routers.is_empty() { routers[1..].to_vec() } else { Vec::new() },
            waps: others
                .iter()
                .copied()
                .filter(|&i| model.devices[i].role == Role::Wap)
                .collect(),
            endpoints: others
                .iter()
                .copied()
                .filter(|&i| model.devices[i].role == Role::Endpoint)
                .collect(),
            collapsed: false,
            cx: 0.0,
            cy: 0.0,
            r: 0.0,
        });
    }
    if let Some(c) = core {
        clusters.push(c);
    }

    let total_nodes: usize = clusters
        .iter()
        .map(|c| c.routers.len() + c.waps.len() + 1 + c.endpoints.len())
        .sum();

    let mut over = total_nodes as i64 - cap as i64;
    if over > 0 {
        let mut order: Vec<usize> = (0..clusters.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(clusters[i].endpoints.len()));
        for i in order {
            if over <= 0 {
                break;
            }
            if clusters[i].endpoints.len() > 4 && !clusters[i].collapsed {
                over -= clusters[i].endpoints.len() as i64 - 1;
                clusters[i].collapsed = true;
            }
        }
    }

    let _k = clusters.len();
    let w = 1900.0f64;
    let h = 1200.0f64;
    for (i, c) in clusters.iter_mut().enumerate() {
        let ang = i as f64 * GOLDEN;
        let rad = 150.0 + 64.0 * (i as f64).sqrt();
        c.cx = w / 2.0 + rad * ang.cos();
        c.cy = h / 2.0 + rad * ang.sin() * 0.72;
        let members = c.routers.len() + c.waps.len() + c.endpoints.len() + 1;
        c.r = 80.0 + 17.0 * ((members as f64).max(1.0).sqrt());
    }
    let mut minx = f64::MAX;
    let mut miny = f64::MAX;
    let mut maxx = f64::MIN;
    let mut maxy = f64::MIN;
    for c in &clusters {
        minx = minx.min(c.cx - c.r);
        maxx = maxx.max(c.cx + c.r);
        miny = miny.min(c.cy - c.r);
        maxy = maxy.max(c.cy + c.r);
    }
    if clusters.is_empty() {
        minx = 0.0;
        miny = 0.0;
        maxx = w;
        maxy = h;
    }
    let margin = 48.0;
    let sx = (w - 2.0 * margin) / (maxx - minx).max(1.0);
    let sy = (h - 2.0 * margin) / (maxy - miny).max(1.0);
    let s = sx.min(sy).min(2.4);
    for c in &mut clusters {
        c.cx = (c.cx - minx) * s + margin;
        c.cy = (c.cy - miny) * s + margin;
        c.r *= s;
    }

    let mut nodes: Vec<MapNode> = Vec::new();
    let mut links: Vec<MapLink> = Vec::new();
    let mut subnets_out: Vec<MapSubnet> = Vec::new();
    let mut link_set: BTreeSet<(String, String)> = BTreeSet::new();

    let push_link = |a: &str, b: &str, links: &mut Vec<MapLink>, set: &mut BTreeSet<(String, String)>| {
        if a != b && set.insert((a.to_string(), b.to_string())) {
            links.push(MapLink { s: a.to_string(), t: b.to_string() });
        }
    };

    for c in &clusters {
        let is_core = c.cidr == "core";
        let anchor_id = match c.anchor {
            Some(a) => model.devices[a].ip.to_string(),
            None => format!("agg:{}", c.cidr),
        };
        if let Some(a) = c.anchor {
            let d = &model.devices[a];
            nodes.push(MapNode {
                id: anchor_id.clone(),
                label: anchor_id.clone(),
                kind: "router".into(),
                state: state_str(d.state),
                ip: Some(d.ip.to_string()),
                subnet: d.subnet.clone(),
                rtt: d.rtt_ms,
                hint: d.hint.clone(),
                mac: d.mac.clone(),
                wap: d.wap.map(|ip| ip.to_string()),
                wap_source: d.wap_source.clone(),
                hostname: d.hostname.clone(),
                device_class: d.device_class.clone(),
                x: c.cx,
                y: c.cy,
                size: 9.0,
            });
        }
        let n = c.routers.len() + c.waps.len() + c.endpoints.len();
        let hash = c.cidr.bytes().map(|b| b as f64).sum::<f64>();
        for (j, &i) in c.routers.iter().enumerate() {
            let ang = j as f64 * GOLDEN + 0.7;
            let rr = c.r * 0.55;
            push_node(
                &mut nodes,
                model,
                i,
                c.cx + rr * ang.cos(),
                c.cy + rr * ang.sin(),
                7.5,
            );
        }
        for (j, &i) in c.waps.iter().enumerate() {
            let ang = j as f64 * GOLDEN + 1.9;
            let rr = c.r * 0.5;
            push_node(
                &mut nodes,
                model,
                i,
                c.cx + rr * ang.cos(),
                c.cy + rr * ang.sin(),
                7.0,
            );
        }
        if c.collapsed && !c.endpoints.is_empty() {
            let id = format!("agg:{}", c.cidr);
            let up = c
                .endpoints
                .iter()
                .filter(|&&i| model.devices[i].state == State::Up)
                .count();
            nodes.push(MapNode {
                id: id.clone(),
                label: format!("{} endpoints", c.endpoints.len()),
                kind: "aggregate".into(),
                state: if up == 0 { "down".into() } else if up == c.endpoints.len() { "up".into() } else { "mixed".into() },
                ip: None,
                subnet: if is_core { None } else { Some(c.cidr.clone()) },
                rtt: None,
                hint: Some(format!("collapsed group: {up} up / {} total", c.endpoints.len())),
                mac: None,
                wap: None,
                wap_source: None,
                hostname: None,
                device_class: None,
                x: c.cx + c.r * 0.72,
                y: c.cy + c.r * 0.72 * (hash * 0.01).sin(),
                size: 8.0 + (c.endpoints.len() as f64 * 0.02).min(6.0),
            });
            push_link(&id, &anchor_id, &mut links, &mut link_set);
        } else {
            for (j, &i) in c.endpoints.iter().enumerate() {
                let ang = j as f64 * GOLDEN + hash * 0.13;
                let rr = (0.34 + 0.62 * ((j as f64) / (n as f64).max(1.0)).sqrt()) * c.r;
                push_node(
                    &mut nodes,
                    model,
                    i,
                    c.cx + rr * ang.cos(),
                    c.cy + rr * ang.sin(),
                    4.5,
                );
            }
        }
        for &i in c.routers.iter().chain(c.waps.iter()) {
            push_link(&model.devices[i].ip.to_string(), &anchor_id, &mut links, &mut link_set);
        }
        if !c.collapsed {
            for &i in &c.endpoints {
                let endpoint = &model.devices[i];
                let parent = endpoint
                    .wap
                    .filter(|ip| wap_ips.contains(ip))
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| anchor_id.clone());
                push_link(&endpoint.ip.to_string(), &parent, &mut links, &mut link_set);
            }
        }
        if !is_core {
            let (alive, sampled, origin) = subnet_meta
                .get(&c.cidr)
                .map(|(a, smp, o)| (*a, *smp, o.clone()))
                .unwrap_or((0, false, String::new()));
            let count = c.routers.len() + c.waps.len() + if c.collapsed { 0 } else { c.endpoints.len() };
            subnets_out.push(MapSubnet {
                cidr: c.cidr.clone(),
                cx: c.cx,
                cy: c.cy,
                r: c.r,
                count,
                alive,
                sampled,
                origin,
            });
        }
    }

    let anchor_of: HashMap<String, String> = clusters
        .iter()
        .filter(|c| c.cidr != "core")
        .filter_map(|c| c.anchor.map(|a| (c.cidr.clone(), model.devices[a].ip.to_string())))
        .collect();
    for d in &model.devices {
        if d.role == Role::Router {
            if let Some(sub) = &d.subnet {
                if let Some(anchor) = anchor_of.get(sub) {
                    push_link(&d.ip.to_string(), anchor, &mut links, &mut link_set);
                }
            }
        }
    }

    subnets_out.sort_by(|a, b| a.cidr.cmp(&b.cidr));

    let up = model.devices.iter().filter(|d| d.state == State::Up).count();
    let down = model.devices.iter().filter(|d| d.state == State::Down).count();
    let unknown = model.devices.iter().filter(|d| d.state == State::Unknown).count();
    let routers = model.devices.iter().filter(|d| d.role == Role::Router).count();
    let waps = model.devices.iter().filter(|d| d.role == Role::Wap).count();
    let endpoints = model.devices.iter().filter(|d| d.role == Role::Endpoint).count();
    let hosts = model.subnets.iter().map(|s| s.hosts).sum();

    let data = MapData {
        generated: model.generated_at.clone(),
        duration_ms: model.scan_duration_ms,
        backend: model.backend.clone(),
        counts: Counts {
            up,
            down,
            unknown,
            routers,
            waps,
            endpoints,
            subnets: model.subnets.len(),
            hosts,
        },
        nodes,
        links,
        subnets: subnets_out,
    };

    let json = serde_json::to_string(&data)?;
    let json = json.replace("</", "<\\/");

    let html = TEMPLATE
        .replace("__DATA__", &json)
        .replace("__GENERATED__", &model.generated_at)
        .replace("__DURATION__", &format_duration(model.scan_duration_ms))
        .replace("__BACKEND__", &html_escape(&model.backend));

    Ok(html)
}

fn push_node(nodes: &mut Vec<MapNode>, model: &Model, i: usize, x: f64, y: f64, size: f64) {
    let d = &model.devices[i];
    nodes.push(MapNode {
        id: d.ip.to_string(),
        label: d.ip.to_string(),
        kind: d.role.label().to_string(),
        state: state_str(d.state),
        ip: Some(d.ip.to_string()),
        subnet: d.subnet.clone(),
        rtt: d.rtt_ms,
        hint: d.hint.clone(),
        mac: d.mac.clone(),
        wap: d.wap.map(|ip| ip.to_string()),
        wap_source: d.wap_source.clone(),
        hostname: d.hostname.clone(),
        device_class: d.device_class.clone(),
        x,
        y,
        size,
    });
}

fn state_str(s: State) -> String {
    match s {
        State::Up => "up".into(),
        State::Down => "down".into(),
        State::Unknown => "unknown".into(),
    }
}

fn format_duration(ms: u64) -> String {
    if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn _unused(_ip: Ipv4Addr) {}

const TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NMS - Network Map</title>
<style>
:root { --bg:#0b1220; --panel:#111a2e; --edge:#1e293b; --text:#e2e8f0; --dim:#94a3b8;
  --router:#fbbf24; --wap:#38bdf8; --up:#34d399; --down:#f87171; --agg:#64748b; --unknown:#94a3b8; }
* { box-sizing: border-box; }
html, body { margin:0; height:100%; background:var(--bg); color:var(--text); font:13px/1.45 "Segoe UI",system-ui,sans-serif; overflow:hidden; }
#app { display:flex; flex-direction:column; height:100%; }
#main { flex:1 1 auto; display:flex; min-height:0; }
#cwrap { flex:1 1 auto; position:relative; min-width:0; }
#topbar { flex:none; height:52px; background:var(--panel); border-bottom:1px solid var(--edge);
  display:flex; align-items:center; gap:18px; padding:0 16px; z-index:10; }
#topbar h1 { font-size:15px; margin:0; letter-spacing:.5px; }
#topbar .stats { display:flex; gap:14px; flex-wrap:wrap; }
.pill { padding:2px 10px; border-radius:12px; background:#0d1526; border:1px solid var(--edge); white-space:nowrap; }
.pill b { font-weight:600; }
.pill.up b { color:var(--up); } .pill.down b { color:var(--down); }
.pill.router b { color:var(--router); } .pill.wap b { color:var(--wap); } .pill.ep b { color:var(--up); }
#meta { margin-left:auto; color:var(--dim); font-size:12px; text-align:right; }
button { background:#1d2a44; color:var(--text); border:1px solid #2b3b5e; border-radius:6px; padding:5px 12px; cursor:pointer; }
button:hover { background:#26365a; }
#controls { flex:none; min-height:42px; background:#0d1526; border-bottom:1px solid var(--edge);
  display:flex; align-items:center; gap:12px; padding:5px 16px; z-index:9; overflow-x:auto; }
#controls label { color:var(--dim); display:flex; align-items:center; gap:5px; cursor:pointer; }
#search { background:#0b1220; border:1px solid var(--edge); color:var(--text); border-radius:6px; padding:5px 10px; width:230px; }
#legend { position:absolute; left:16px; bottom:16px; background:rgba(13,21,38,.92); border:1px solid var(--edge); border-radius:8px;
  padding:10px 14px; z-index:9; font-size:12px; }
#legend div { display:flex; align-items:center; gap:8px; margin:3px 0; color:var(--dim); }
.dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
#side { width:330px; flex:none; background:var(--panel); border-left:1px solid var(--edge);
  z-index:9; display:flex; flex-direction:column; min-height:0; }
#side h3 { margin:0; padding:10px 14px 6px; font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
#detail { padding:0 14px 10px; border-bottom:1px solid var(--edge); min-height:52px; font-size:12px; color:var(--dim); }
#detail b { color:var(--text); }
#activity { max-height:132px; overflow-y:auto; border-bottom:1px solid var(--edge); }
.event { padding:5px 14px; border-top:1px solid #0d1526; font-size:11px; color:var(--dim); }
.event.down { color:var(--down); } .event.new,.event.recovered { color:var(--up); }
.assoc { margin-top:8px; padding-top:8px; border-top:1px solid var(--edge); }
.assoc select { max-width:165px; background:#0b1220; color:var(--text); border:1px solid var(--edge); padding:4px; }
#devlist { overflow-y:auto; flex:1; }
.row { display:flex; align-items:center; gap:8px; padding:5px 14px; cursor:pointer; border-bottom:1px solid #0d1526; }
.row:hover { background:#16213a; }
.row.sel { background:#1b2a4a; }
.row .rip { flex:1; font-family:Consolas,monospace; }
.row .rrole { color:var(--dim); font-size:11px; width:58px; }
.row .rrtt { color:var(--dim); font-size:11px; width:56px; text-align:right; }
#tooltip { position:fixed; pointer-events:none; background:rgba(10,16,30,.96); border:1px solid #2b3b5e; border-radius:6px;
  padding:8px 10px; font-size:12px; z-index:20; display:none; max-width:280px; }
#tooltip b { font-family:Consolas,monospace; }
#tooltip .sub { color:var(--dim); }
#canvas { position:absolute; inset:0; width:100%; height:100%; display:block; cursor:grab; }
body.noside #side { display:none; }
#nav { flex:none; background:#0d1526; border-bottom:1px solid var(--edge);
  display:flex; gap:16px; align-items:center; padding:7px 16px; }
#nav b { letter-spacing:.5px; font-size:13px; }
#nav a { color:var(--dim); text-decoration:none; font-size:13px; }
#nav a:hover { color:var(--text); }
#nav a.on { color:var(--text); box-shadow:inset 0 -2px 0 var(--up); padding-bottom:3px; }
</style>
</head>
<body>
<div id="app">
<div id="nav">
  <b>NMS</b>
  <a href="/map" class="on">Map</a>
  <a href="/console">Console</a>
  <a href="/devices">Devices</a>
  <a href="/events">Events</a>
  <a href="/reports">Reports</a>
  <a href="/audit">Audit</a>
  <a href="/settings">Settings</a>
</div>
<script>
if (location.protocol === "file:") document.getElementById("nav").style.display = "none";
</script>
<div id="topbar">
  <h1>NMS NETWORK MAP</h1>
  <div class="stats">
    <span class="pill up">up <b id="s-up">0</b></span>
    <span class="pill down">down <b id="s-down">0</b></span>
    <span class="pill router">routers <b id="s-rt">0</b></span>
    <span class="pill wap">waps <b id="s-wap">0</b></span>
    <span class="pill ep">endpoints <b id="s-ep">0</b></span>
    <span class="pill">subnets <b id="s-sub">0</b></span>
    <span class="pill">address space <b id="s-hosts">0</b></span>
  </div>
  <div id="meta">__GENERATED__<br>scan took __DURATION__ &middot; __BACKEND__</div>
  <button id="toggleside">Hide panel</button>
  <button id="fit">Fit</button>
  <button id="export">Export JSON</button>
</div>
<div id="controls">
  <label><input type="checkbox" id="f-router" checked> routers</label>
  <label><input type="checkbox" id="f-wap" checked> waps</label>
  <label><input type="checkbox" id="f-endpoint" checked> endpoints</label>
  <label><input type="checkbox" id="f-agg" checked> aggregates</label>
  <label>state
    <select id="f-state">
      <option value="up" selected>active</option>
      <option value="down">down</option>
      <option value="all">all</option>
    </select>
  </label>
  <input id="search" type="text" placeholder="filter by IP / subnet...">
  <span style="color:var(--dim)" id="viscount"></span>
  <span style="flex:1"></span>
  <span class="pill" id="jobpill">idle</span>
  <div id="jobwrap" title="job progress" style="display:none;width:140px;height:6px;border-radius:3px;background:#1b2745;overflow:hidden"><div id="jobbar" style="height:100%;width:0%;background:var(--up)"></div></div>
  <a href="/console"><button title="dashboards, events, reports, settings">Console</button></a>
  <button id="btn-start" title="discover the network, then start continuous monitoring">Start NMS</button>
  <a id="lnk-routes" href="/api/routes" target="_blank"><button>Routes</button></a>
  <a id="lnk-ifaces" href="/api/ifaces" target="_blank"><button>Ifaces</button></a>
  <button id="btn-ping" title="ping the selected device (or enter an address)">Ping</button>
  <button id="btn-discover" title="full crawl: subnets, devices, roles, map rebuild">Discover</button>
  <button id="btn-inspect" title="thorough pass: SNMP identity + interfaces + LLDP/CDP neighbors on every live device">Inspect</button>
  <button id="btn-check" title="fast up/down sweep of everything in the model">Check now</button>
  <button id="btn-monitor" title="toggle continuous monitoring with down-alerts">Monitor</button>
  <span id="servehint" style="color:var(--dim);display:none">actions need “nms serve”</span>
</div>
<div id="main">
<div id="cwrap">
<canvas id="canvas"></canvas>
<div id="legend">
  <div><span class="dot" style="background:var(--router)"></span> router / gateway</div>
  <div><span class="dot" style="background:var(--wap)"></span> wireless AP (OUI heuristic)</div>
  <div><span class="dot" style="background:var(--up)"></span> endpoint up</div>
  <div><span class="dot" style="background:var(--down)"></span> endpoint down</div>
  <div><span class="dot" style="background:var(--agg)"></span> collapsed group</div>
</div>
</div>
<div id="side">
  <h3>Recent activity</h3>
  <div id="activity"><div class="event">No changes recorded in this server session.</div></div>
  <h3>Device details</h3>
  <div id="detail">click a node or row</div>
  <h3>Devices (<span id="listcount">0</span>)</h3>
  <div id="devlist"></div>
</div>
</div>
</div>
<div id="tooltip"></div>
<script>
let DATA = __DATA__;
const C = { router:"#fbbf24", wap:"#38bdf8", up:"#34d399", down:"#f87171", agg:"#64748b", unknown:"#94a3b8" };
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
let W=0, H=0, dpr=1;
let view = { x:0, y:0, k:1 };
let visible = new Set();
let selected = null, hovered = null;
let grid = new Map();
let dragging = false;

function nodeColor(n) {
  if (n.kind === "router") return C.router;
  if (n.kind === "wap") return C.wap;
  if (n.kind === "aggregate") return C.agg;
  if (n.state === "up") return C.up;
  if (n.state === "down") return C.down;
  return C.unknown;
}

function computeVisible() {
  const fr = document.getElementById("f-router").checked;
  const fw = document.getElementById("f-wap").checked;
  const fe = document.getElementById("f-endpoint").checked;
  const fa = document.getElementById("f-agg").checked;
  const st = document.getElementById("f-state").value;
  const q = document.getElementById("search").value.trim().toLowerCase();
  visible = new Set();
  for (const n of DATA.nodes) {
    if (n.kind === "router" && !fr) continue;
    if (n.kind === "wap" && !fw) continue;
    if (n.kind === "endpoint" && !fe) continue;
    if (n.kind === "aggregate" && !fa) continue;
    if (st === "up" && n.state !== "up") continue;
    if (st === "down" && n.state !== "down") continue;
    if (q) {
      const hay = ((n.ip||"") + " " + (n.subnet||"") + " " + n.label).toLowerCase();
      if (!hay.includes(q)) continue;
    }
    visible.add(n.id);
  }
  document.getElementById("viscount").textContent = visible.size + "/" + DATA.nodes.length + " shown";
  renderList();
  draw();
}

function renderList() {
  const el = document.getElementById("devlist");
  el.innerHTML = "";
  let count = 0;
  const frag = document.createDocumentFragment();
  for (const n of DATA.nodes) {
    if (!visible.has(n.id)) continue;
    if (count >= 400) break;
    count++;
    const row = document.createElement("div");
    row.className = "row" + (selected === n.id ? " sel" : "");
    row.dataset.id = n.id;
    const d = document.createElement("span");
    d.className = "dot"; d.style.background = nodeColor(n);
    const ip = document.createElement("span"); ip.className = "rip"; ip.textContent = n.label;
    const role = document.createElement("span"); role.className = "rrole"; role.textContent = n.kind;
    const rtt = document.createElement("span"); rtt.className = "rrtt";
    rtt.textContent = n.rtt != null ? n.rtt.toFixed(1) + "ms" : n.state;
    row.append(d, ip, role, rtt);
    row.onclick = () => selectNode(n.id, true);
    frag.appendChild(row);
  }
  el.appendChild(frag);
  document.getElementById("listcount").textContent = count;
}

function selectNode(id, center) {
  selected = id;
  const n = DATA.nodes.find(x => x.id === id);
  const det = document.getElementById("detail");
  if (n) {
    det.innerHTML = "<b>" + esc(n.label) + "</b><br>" +
      "role: " + n.kind + " &middot; state: " + n.state +
      (n.subnet ? "<br><span class='sub'>subnet: " + esc(n.subnet) + "</span>" : "") +
      (n.rtt != null ? " &middot; rtt " + n.rtt.toFixed(1) + "ms" : "") +
      (n.mac ? " &middot; mac " + n.mac : "") +
      (n.wap ? "<br><span class='sub'>serving WAP: " + esc(n.wap) + " (" + esc(n.wap_source || "assigned") + ")</span>" : "") +
      (n.hint ? "<br><span class='sub'>" + esc(n.hint) + "</span>" : "") +
      associationControls(n);
    if (center) {
      view.x = W/2 - n.x * view.k;
      view.y = H/2 - n.y * view.k;
    }
  } else {
    det.textContent = "click a node or row";
  }
  renderList();
  draw();
}

function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

function associationControls(n) {
  if (!SERVED || n.kind !== "endpoint" || !n.ip) return "";
  const waps = DATA.nodes.filter(x => x.kind === "wap" && x.subnet === n.subnet);
  if (!waps.length) return "<div class='assoc sub'>No detected WAP in this subnet.</div>";
  const options = ["<option value=''>Unknown / clear</option>"]
    .concat(waps.map(w => "<option value='" + esc(w.ip) + "'" + (w.ip === n.wap ? " selected" : "") + ">" + esc(w.ip) + "</option>"));
  return "<div class='assoc'>Serving WAP: <select id='wapselect'>" + options.join("") + "</select> " +
    "<button onclick=\"assignWap('" + esc(n.ip) + "')\">Save</button><br><span class='sub'>Manual assignment; ICMP cannot identify AP associations.</span></div>";
}

async function assignWap(ip) {
  const wap = document.getElementById("wapselect").value;
  try {
    const r = await fetch("/api/associate?device=" + encodeURIComponent(ip) + "&wap=" + encodeURIComponent(wap), { method:"POST" });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    location.reload();
  } catch (e) { alert(e.message); }
}

function renderEvents(events) {
  const el = document.getElementById("activity");
  if (!events || !events.length) return;
  el.innerHTML = events.slice(0, 20).map(e =>
    "<div class='event " + esc(e.kind) + "'><b>" + esc(e.kind.toUpperCase()) + "</b> " + esc(e.ip) +
    " &middot; " + esc(e.message) + "<br>" + esc(e.at) + "</div>"
  ).join("");
}

function resize() {
  dpr = window.devicePixelRatio || 1;
  W = canvas.clientWidth; H = canvas.clientHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  draw();
}

function fit() {
  if (!DATA.nodes.length) return;
  let minx=1e9, miny=1e9, maxx=-1e9, maxy=-1e9;
  for (const n of DATA.nodes) {
    minx=Math.min(minx,n.x); maxx=Math.max(maxx,n.x);
    miny=Math.min(miny,n.y); maxy=Math.max(maxy,n.y);
  }
  const pad = 36;
  const k = Math.max(0.05, Math.min((W-2*pad)/(maxx-minx||1), (H-2*pad)/(maxy-miny||1), 10));
  view.k = k;
  view.x = W/2 - (minx+maxx)/2 * k;
  view.y = H/2 - (miny+maxy)/2 * k;
  draw();
}

function buildGrid() {
  grid = new Map();
  DATA.nodes.forEach((n, i) => {
    const key = Math.floor(n.x/48) + "," + Math.floor(n.y/48);
    if (!grid.has(key)) grid.set(key, []);
    grid.get(key).push(i);
  });
}

function nodeAt(mx, my) {
  const wx = (mx - view.x) / view.k, wy = (my - view.y) / view.k;
  const cx = Math.floor(wx/48), cy = Math.floor(wy/48);
  for (let dx=-1; dx<=1; dx++) for (let dy=-1; dy<=1; dy++) {
    const cell = grid.get((cx+dx) + "," + (cy+dy));
    if (!cell) continue;
    for (const i of cell) {
      const n = DATA.nodes[i];
      const dx2 = n.x - wx, dy2 = n.y - wy;
      if (dx2*dx2 + dy2*dy2 <= Math.pow(n.size + 4, 2)) return n;
    }
  }
  return null;
}

function draw() {
  ctx.setTransform(1,0,0,1,0,0);
  ctx.fillStyle = "#0b1220";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.setTransform(dpr*view.k, 0, 0, dpr*view.k, dpr*view.x, dpr*view.y);

  for (const s of DATA.subnets) {
    ctx.beginPath();
    ctx.arc(s.cx, s.cy, s.r, 0, Math.PI*2);
    ctx.fillStyle = "rgba(148,163,184,0.045)";
    ctx.fill();
    ctx.setLineDash([5,6]);
    ctx.strokeStyle = "rgba(148,163,184,0.22)";
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "rgba(148,163,184,0.55)";
    ctx.font = "10px Consolas,monospace";
    ctx.textAlign = "center";
    const tag = s.cidr + (s.sampled ? " (sampled)" : "");
    ctx.fillText(tag, s.cx, s.cy - s.r - 6);
  }

  ctx.strokeStyle = "rgba(148,163,184,0.28)";
  ctx.lineWidth = 0.8 / view.k;
  ctx.beginPath();
  for (const l of DATA.links) {
    if (!visible.has(l.s) || !visible.has(l.t)) continue;
    const a = DATA.nodeIdx[l.s], b = DATA.nodeIdx[l.t];
    if (!a || !b) continue;
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
  }
  ctx.stroke();

  for (const n of DATA.nodes) {
    if (!visible.has(n.id)) continue;
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.size, 0, Math.PI*2);
    ctx.fillStyle = nodeColor(n);
    if (n.state === "down" && n.kind === "endpoint") {
      ctx.globalAlpha = 0.9;
      ctx.fill();
      ctx.globalAlpha = 1;
    } else {
      ctx.fill();
    }
    if (n.id === selected) {
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.6 / view.k;
      ctx.stroke();
    } else if (n.id === hovered) {
      ctx.strokeStyle = "rgba(255,255,255,0.6)";
      ctx.lineWidth = 1.2 / view.k;
      ctx.stroke();
    }
  }

  if (view.k > 0.75) {
    ctx.font = "10px Consolas,monospace";
    ctx.textAlign = "center";
    for (const n of DATA.nodes) {
      if (!visible.has(n.id)) continue;
      if (n.kind === "router" || n.kind === "aggregate" || n.size >= 7) {
        ctx.fillStyle = "rgba(226,232,240,0.85)";
        ctx.fillText(n.label, n.x, n.y - n.size - 4);
      }
    }
  }
}

const tooltip = document.getElementById("tooltip");
canvas.addEventListener("mousemove", (e) => {
  const r = canvas.getBoundingClientRect();
  const mx = e.clientX - r.left, my = e.clientY - r.top;
  const n = nodeAt(mx, my);
  hovered = n ? n.id : null;
  if (n) {
    tooltip.style.display = "block";
    tooltip.style.left = (e.clientX + 14) + "px";
    tooltip.style.top = (e.clientY + 14) + "px";
    tooltip.innerHTML = "<b>" + esc(n.label) + "</b> <span class='sub'>(" + n.kind + ", " + n.state + ")</span>" +
      (n.subnet ? "<br><span class='sub'>" + esc(n.subnet) + "</span>" : "") +
      (n.rtt != null ? " &middot; " + n.rtt.toFixed(1) + "ms" : "") +
      (n.mac ? "<br><span class='sub'>" + n.mac + "</span>" : "") +
      (n.hint ? "<br><span class='sub'>" + esc(n.hint) + "</span>" : "");
  } else {
    tooltip.style.display = "none";
  }
  if (dragging) {
    view.x += e.movementX; view.y += e.movementY;
  }
  canvas.style.cursor = dragging ? "grabbing" : (n ? "pointer" : "grab");
  draw();
});
canvas.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
canvas.addEventListener("mousedown", () => { dragging = true; });
window.addEventListener("mouseup", () => { dragging = false; });
canvas.addEventListener("click", (e) => {
  const r = canvas.getBoundingClientRect();
  const n = nodeAt(e.clientX - r.left, e.clientY - r.top);
  if (n) selectNode(n.id, false);
});
canvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  const r = canvas.getBoundingClientRect();
  const mx = e.clientX - r.left, my = e.clientY - r.top;
  const f = e.deltaY < 0 ? 1.12 : 1/1.12;
  view.x = mx - (mx - view.x) * f;
  view.y = my - (my - view.y) * f;
  view.k = Math.max(0.05, Math.min(12, view.k * f));
  draw();
}, { passive: false });
canvas.addEventListener("dblclick", fit);

document.getElementById("fit").onclick = fit;
document.getElementById("toggleside").onclick = () => {
  const noside = document.body.classList.toggle("noside");
  document.getElementById("toggleside").textContent = noside ? "Show panel" : "Hide panel";
  setTimeout(() => { resize(); fit(); }, 0);
};
document.getElementById("export").onclick = () => {
  const blob = new Blob([JSON.stringify(DATA, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "network-map.json";
  a.click();
};
for (const id of ["f-router","f-wap","f-endpoint","f-agg"]) {
  document.getElementById(id).onchange = computeVisible;
}
document.getElementById("f-state").onchange = computeVisible;
document.getElementById("search").oninput = computeVisible;

function applyData(d) {
  DATA = d;
  DATA.nodeIdx = {};
  for (const n of DATA.nodes) DATA.nodeIdx[n.id] = n;
  document.getElementById("s-up").textContent = DATA.counts.up;
  document.getElementById("s-down").textContent = DATA.counts.down;
  document.getElementById("s-rt").textContent = DATA.counts.routers;
  document.getElementById("s-wap").textContent = DATA.counts.waps;
  document.getElementById("s-ep").textContent = DATA.counts.endpoints;
  document.getElementById("s-sub").textContent = DATA.counts.subnets;
  document.getElementById("s-hosts").textContent = DATA.counts.hosts.toLocaleString();
  buildGrid();
  resize();
  computeVisible();
  fit();
}
applyData(DATA);
window.addEventListener("resize", () => { resize(); fit(); });

const SERVED = location.protocol === "http:" || location.protocol === "https:";
const btnD = document.getElementById("btn-discover");
const btnI = document.getElementById("btn-inspect");
const btnC = document.getElementById("btn-check");
const btnM = document.getElementById("btn-monitor");
const btnStart = document.getElementById("btn-start");
const btnPing = document.getElementById("btn-ping");
const pill = document.getElementById("jobpill");
let lastJob = null;
let lastRevision = null;
let monitorAfterJob = false;
let refreshing = false;

async function post(p) {
  const r = await fetch(p, { method: "POST" });
  if (!r.ok) { throw new Error(await r.text() || ("HTTP " + r.status)); }
  return r.text();
}
function setBusy(b) { btnD.disabled = b; btnC.disabled = b; btnStart.disabled = b; if (btnI) btnI.disabled = b; }
const jobwrap = document.getElementById("jobwrap");
const jobbar = document.getElementById("jobbar");
async function poll() {
  if (refreshing) return;
  try {
    const s = await (await fetch("/api/status")).json();
    const p = s.progress;
    const busy = s.job !== "idle";
    if (p && p.total > 0) {
      const pct = Math.min(100, Math.round(100 * p.done / p.total));
      pill.textContent = p.label + " " + pct + "%";
      if (jobwrap) jobwrap.style.display = "inline-block";
      if (jobbar) jobbar.style.width = pct + "%";
    } else {
      pill.textContent = busy ? s.job + "..." : (s.monitoring ? "monitoring" : "idle");
      if (jobwrap) jobwrap.style.display = "none";
    }
    pill.title = s.message || "";
    btnM.textContent = s.monitoring ? "Stop monitor" : "Monitor";
    renderEvents(s.events);
    setBusy(busy);
    const jobJustFinished = lastJob && lastJob !== "idle" && !busy;
    const revisionChanged = lastRevision !== null && s.revision !== lastRevision && !busy;
    lastJob = s.job;
    lastRevision = s.revision;
    if (jobJustFinished || revisionChanged) {
      if (jobJustFinished && monitorAfterJob && !s.monitoring) {
        monitorAfterJob = false;
        try { await post("/api/monitor/start"); } catch (e) { alert(e.message); }
      }
      // Refresh the map in place — never reload the page (it kills clicks).
      refreshing = true;
      try {
        const d = await (await fetch("/api/model")).json();
        applyData(d);
      } catch (e) {} finally { refreshing = false; }
    }
  } catch (e) {
    setBusy(false);
  }
}
if (SERVED) {
  btnStart.onclick = async () => {
    monitorAfterJob = true;
    setBusy(true); pill.textContent = "discover...";
    try { await post("/api/discover"); } catch (e) { monitorAfterJob = false; alert(e.message); }
    setTimeout(poll, 400);
  };
  btnD.onclick = async () => {
    setBusy(true); pill.textContent = "queued...";
    try { await post("/api/discover"); } catch (e) { alert(e.message); }
    setTimeout(poll, 400);
  };
  btnI.onclick = async () => {
    setBusy(true); pill.textContent = "queued...";
    try { await post("/api/inspect"); } catch (e) { alert(e.message); }
    setTimeout(poll, 400);
  };
  btnC.onclick = async () => {
    setBusy(true); pill.textContent = "queued...";
    try { await post("/api/check"); } catch (e) { alert(e.message); }
    setTimeout(poll, 400);
  };
  btnM.onclick = async () => {
    try { await post(btnM.textContent.startsWith("Stop") ? "/api/monitor/stop" : "/api/monitor/start"); }
    catch (e) { alert(e.message); }
    setTimeout(poll, 400);
  };
  btnPing.onclick = async () => {
    let ip = null;
    if (selected) {
      const n = DATA.nodes.find(n => n.id === selected);
      if (n && n.ip) ip = n.ip;
    }
    if (!ip) ip = prompt("IPv4 address to ping:");
    if (!ip) return;
    try {
      const r = await fetch("/api/ping?ip=" + encodeURIComponent(ip), { method: "POST" });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
      alert(data.ip + (data.up ? " is UP" : " is DOWN") + (data.rtt_ms == null ? "" : " (" + data.rtt_ms.toFixed(1) + " ms)"));
    } catch (e) { alert(e.message); }
  };
  setInterval(poll, 2500);
  poll();
} else {
  [btnD, btnC, btnM, btnStart, btnPing].forEach(b => b.disabled = true);
  document.getElementById("servehint").style.display = "inline";
  document.getElementById("lnk-routes").style.display = "none";
  document.getElementById("lnk-ifaces").style.display = "none";
}
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Device, Edge, Subnet};

    #[test]
    fn renders_minimal() {
        let m = Model {
            generated_at: "2026-01-01T00:00:00Z".into(),
            scan_duration_ms: 1234,
            backend: "test".into(),
            subnets: vec![Subnet {
                cidr: "192.168.1.0/24".into(),
                origin: "cli".into(),
                sampled: false,
                hosts: 254,
                probed: 254,
                alive: 2,
            }],
            devices: vec![
                Device {
                    ip: "192.168.1.1".parse().unwrap(),
                    mac: None,
                    role: Role::Router,
                    state: State::Up,
                    subnet: Some("192.168.1.0/24".into()),
                    rtt_ms: Some(1.0),
                    reply_ttl: Some(128),
                    hint: None,
                    first_seen: "x".into(),
                    last_seen: "x".into(),
                    down_since: None,
                    ever_up: true,
                    wap: None,
                    wap_source: None,
                    hostname: None,
                    device_class: None,
                },
                Device {
                    ip: "192.168.1.50".parse().unwrap(),
                    mac: None,
                    role: Role::Endpoint,
                    state: State::Down,
                    subnet: Some("192.168.1.0/24".into()),
                    rtt_ms: None,
                    reply_ttl: None,
                    hint: None,
                    first_seen: "x".into(),
                    last_seen: "x".into(),
                    down_since: Some("x".into()),
                    ever_up: true,
                    wap: None,
                    wap_source: None,
                    hostname: None,
                    device_class: None,
                },
            ],
            edges: vec![Edge { src: "192.168.1.50".into(), dst: "192.168.1.1".into(), kind: "member".into() }],
        };
        let html = render(&m, 100).unwrap();
        assert!(!html.contains("__DATA__"));
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("map"));
    }
}
