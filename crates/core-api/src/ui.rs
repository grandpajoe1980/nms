use engine::db;
use rusqlite::Connection;
use std::collections::HashMap;
use std::fmt::Write;

const CSS: &str = r#"
:root{--bg:#0b1020;--bg2:#101a33;--panel:#0e1730;--edge:#22304f;--text:#dbe4f5;--dim:#8fa3c8;
--up:#3ddc84;--down:#ff5470;--warn:#ffb454;--info:#59a7ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.45 system-ui,Segoe UI,sans-serif}
a{color:var(--info);text-decoration:none}a:hover{text-decoration:underline}
.topbar{display:flex;gap:18px;align-items:center;padding:10px 18px;background:var(--bg2);
border-bottom:1px solid var(--edge);flex-wrap:wrap}
.topbar b{letter-spacing:.5px}.topbar a{color:var(--dim)}.topbar a.on{color:var(--text)}
.wrap{padding:18px;max-width:1500px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:12px 16px;min-width:130px}
.card .n{font-size:26px;font-weight:600}.card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
table{border-collapse:collapse;width:100%;margin:8px 0 20px}
th,td{padding:7px 10px;border-bottom:1px solid var(--edge);text-align:left;font-size:13px}
th{color:var(--dim);font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
tr:hover td{background:#111c38}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600}
.b-up{background:#123b2a;color:var(--up)}.b-down{background:#401723;color:var(--down)}
.b-unreachable{background:#3d3013;color:var(--warn)}.b-unknown{background:#232f49;color:var(--dim)}
.b-critical{background:#401723;color:var(--down)}.b-warning{background:#3d3013;color:var(--warn)}
.b-info{background:#16304f;color:var(--info)}.b-closed{opacity:.55}.b-open{background:#401723;color:var(--down)}
input,select,button{background:#0b1220;color:var(--text);border:1px solid var(--edge);
padding:6px 10px;border-radius:6px;font-size:13px}
button{cursor:pointer}button:hover{border-color:var(--info)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:1100px){.grid2{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:14px}
h2{margin:4px 0 10px;font-size:16px}h3{margin:14px 0 6px;font-size:14px;color:var(--dim)}
.muted{color:var(--dim)}.mono{font-family:ui-monospace,Consolas,monospace}
.bar{height:8px;border-radius:4px;background:#1b2745;overflow:hidden;min-width:90px}
.bar i{display:block;height:100%}
form.inline{display:inline}"#;

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn page(conn: &Connection, title: &str, active: &str, body: &str) -> String {
    let mut nav = String::new();
    for (href, label) in [
        ("/map", "Map"),
        ("/console", "Console"),
        ("/devices", "Devices"),
        ("/events", "Events"),
        ("/reports", "Reports"),
        ("/audit", "Audit"),
        ("/settings", "Settings"),
    ] {
        let class = if active == label { "on" } else { "" };
        let _ = write!(nav, "<a href=\"{href}\" class=\"{class}\">{label}</a>");
    }
    let (open, unacked, _) = db::event_counts(conn);
    let mut out = String::new();
    let _ = write!(out,
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{title} \u{b7} NMS</title><style>{CSS}</style></head><body>\
<div class=\"topbar\"><b>NMS</b>{nav}\
<form method=\"get\" action=\"/devices\" style=\"margin-left:auto;display:flex;gap:6px\">\
<input name=\"q\" placeholder=\"search ip/mac/host\u{2026}\" size=\"22\">\
<button type=\"submit\">go</button></form>\
<span class=\"muted\">\
alerts <span style=\"color:var(--down)\">{open}</span> open / {unacked} unacked</span></div>\
<div class=\"wrap\">{body}</div></body></html>");
    out
}

fn badge(text: &str) -> String {
    let t = esc(text);
    format!("<span class=\"badge b-{t}\">{t}</span>")
}

fn closed_badge() -> &'static str {
    "<span class=\"badge b-closed\">closed</span>"
}

fn pct_bar(pct: f64) -> String {
    let color = if pct >= 99.0 {
        "var(--up)"
    } else if pct >= 95.0 {
        "var(--warn)"
    } else {
        "var(--down)"
    };
    let mut s = String::new();
    let _ = write!(
        s,
        "<div class=\"bar\"><i style=\"width:{pct:.1}%;background:{color}\"></i></div><span class=\"muted\">{pct:.2}%</span>"
    );
    s
}

fn ago(ts: i64) -> String {
    let d = chrono::Utc::now().timestamp().saturating_sub(ts);
    match d {
        s if s < 90 => format!("{s}s ago"),
        m if m < 5400 => format!("{}m ago", m / 60),
        h if h < 172_800 => format!("{}h ago", h / 3600),
        d => format!("{}d ago", d / 86_400),
    }
}

fn hhmm(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts.max(0), 0)
        .map(|t| t.format("%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Humanize interface link speed (bps → Gbps/Mbps/kbps), FR-DISC-003.
fn speed_str(bps: Option<i64>) -> String {
    let Some(b) = bps else { return "-".into() };
    if b <= 0 {
        return "-".into();
    }
    if b >= 1_000_000_000 {
        if b % 1_000_000_000 == 0 {
            format!("{} Gbps", b / 1_000_000_000)
        } else {
            format!("{:.1} Gbps", b as f64 / 1e9)
        }
    } else if b >= 1_000_000 {
        format!("{} Mbps", b / 1_000_000)
    } else {
        format!("{} kbps", b / 1_000)
    }
}

/// Colorized admin/oper status chip: up=green, down=red, other values plain.
fn if_status(v: Option<&str>) -> String {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => "-".to_string(),
        Some(s) => {
            let color = match s.to_ascii_lowercase().as_str() {
                "up" => "var(--up)",
                "down" => "var(--down)",
                _ => "",
            };
            if color.is_empty() {
                esc(s)
            } else {
                format!("<span style=\"color:{color}\">{}</span>", esc(s))
            }
        }
    }
}

/// Inline SVG polyline chart, auto-scaled min/max.
fn svg_line(points: &[(i64, f64)], w: u32, h: u32, color: &str, unit: &str) -> String {
    if points.len() < 2 {
        return "<div class=\"muted\">not enough data yet</div>".into();
    }
    let lo = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
    let hi = points.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
    let span = (hi - lo).max(0.001);
    let wf = f64::from(w);
    let hf = f64::from(h);
    let step_x = wf / (points.len() - 1) as f64;
    let mut path = String::new();
    for (i, (_, v)) in points.iter().enumerate() {
        let x = i as f64 * step_x;
        let y = hf - ((v - lo) / span) * (hf - 12.0) - 6.0;
        let _ = write!(path, "{}{x:.1},{y:.1}", if i == 0 { "" } else { " " });
    }
    let mut s = String::new();
    let _ = write!(
        s,
        "<svg width=\"{w}\" height=\"{h}\" style=\"width:100%;height:auto;background:#0b1220;border-radius:6px\">\
<polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" points=\"{path}\"/>\
<text x=\"6\" y=\"14\" fill=\"#8fa3c8\" font-size=\"11\">max {hi:.1}{unit}</text>\
<text x=\"6\" y=\"{}\" fill=\"#8fa3c8\" font-size=\"11\">min {lo:.1}{unit}</text></svg>",
        h - 6
    );
    s
}

// ---------------------------------------------------------------- dashboard

pub fn dashboard(conn: &Connection) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut counts: HashMap<String, i64> = HashMap::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT eff_state, COUNT(*) FROM devices WHERE managed=1 GROUP BY eff_state")
    {
        for row in stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .into_iter()
            .flatten()
            .flatten()
        {
            *counts.entry(row.0).or_default() += row.1;
        }
    }
    let g = |k: &str| counts.get(k).copied().unwrap_or(0);
    let total: i64 = counts.values().sum();
    let degraded: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE managed=1 AND perf_status!='ok'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let sites: i64 =
        conn.query_row("SELECT COUNT(*) FROM sites", [], |r| r.get(0)).unwrap_or(0);

    let trend: Vec<(i64, f64)> = conn
        .prepare(
            "SELECT hour, 100.0*SUM(ups)/MAX(SUM(probes),1) FROM rollup_hourly
             WHERE hour >= ?1 GROUP BY hour ORDER BY hour",
        )
        .ok()
        .and_then(|mut s| {
            s.query_map([now - 86_400], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?)))
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
             GROUP BY r.device_id ORDER BY avg_rtt DESC LIMIT 8",
        )
        .ok()
        .and_then(|mut s| {
            s.query_map([now - 3600], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, f64>(2)?))
            })
            .ok()?
            .flatten()
            .collect::<Vec<_>>()
            .into()
        })
        .unwrap_or_default();

    let evs = db::list_events(conn, false, None, None, 0, 12).unwrap_or_default();

    let mut body = String::new();
    let _ = write!(body,
        "<div class=\"cards\">\
<div class=\"card\"><div class=\"n\">{total}</div><div class=\"l\">managed devices</div></div>\
<div class=\"card\"><div class=\"n\" style=\"color:var(--up)\">{up}</div><div class=\"l\">up</div></div>\
<div class=\"card\"><div class=\"n\" style=\"color:var(--down)\">{down}</div><div class=\"l\">down</div></div>\
<div class=\"card\"><div class=\"n\" style=\"color:var(--warn)\">{unreach}</div><div class=\"l\">unreachable</div></div>\
<div class=\"card\"><div class=\"n\" style=\"color:var(--warn)\">{degraded}</div><div class=\"l\">degraded</div></div>\
<div class=\"card\"><div class=\"n\">{sites}</div><div class=\"l\">sites</div></div></div>",
        up = g("up"),
        down = g("down"),
        unreach = g("unreachable"));

    let trend_chart = svg_line(&trend, 600, 140, "var(--up)", "%");
    let _ = write!(body,
        "<div class=\"grid2\"><div class=\"panel\"><h2>Network availability \u{2014} last 24h</h2>{trend_chart}</div>\
<div class=\"panel\"><h2>Slowest devices \u{2014} last hour (avg RTT ms)</h2><table>\
<tr><th>device</th><th>role</th><th>avg rtt</th></tr>");
    for (ip, role, rtt) in &worst {
        let _ = write!(body,
            "<tr><td><a href=\"/device/{ip}\">{ip}</a></td><td>{role}</td><td class=\"mono\">{rtt:.0} ms</td></tr>");
    }
    body.push_str("</table></div></div>");

    body.push_str("<div class=\"panel\" style=\"margin-top:18px\"><h2>Latest events</h2><table>\
<tr><th>when</th><th>severity</th><th>kind</th><th>device</th><th>message</th><th>state</th></tr>");
    for e in &evs {
        let dev = e.ip.as_deref()
            .map(|ip| format!("<a href=\"/device/{ip}\">{ip}</a>"))
            .unwrap_or_default();
        let st = if e.state == "open" { badge("open") } else { closed_badge().to_string() };
        let _ = write!(body,
            "<tr><td class=\"muted\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{dev}</td><td>{}</td><td>{st}</td></tr>",
            ago(e.created_ts), badge(&e.severity), esc(&e.kind), esc(&e.message));
    }
    body.push_str("</table></div>");
    page(conn, "Console", "Console", &body)
}

// ------------------------------------------------------------------ devices

type DeviceRow = (String, String, String, String, Option<String>, Option<String>, String, String, i64);

pub fn devices_page(conn: &Connection, state: &str, q: &str) -> String {
    let mut sql = String::from(
        "SELECT ip, role, eff_state, perf_status, mac,
            (SELECT name FROM sites WHERE id = devices.site_id) AS site,
            COALESCE(hostname, '') AS hostname, COALESCE(device_class,'') AS class,
            last_seen_ts
         FROM devices WHERE 1=1",
    );
    let mut args: Vec<rusqlite::types::Value> = Vec::new();
    let state = state.trim();
    if !state.is_empty() && state != "all" {
        args.push(rusqlite::types::Value::Text(state.to_string()));
        sql.push_str(&format!(" AND eff_state = ?{}", args.len()));
    }
    if !q.trim().is_empty() {
        args.push(rusqlite::types::Value::Text(format!("%{}%", q.trim())));
        sql.push_str(&format!(" AND (ip LIKE ?{0} OR COALESCE(mac,'') LIKE ?{0})", args.len()));
    }
    sql.push_str(" ORDER BY ip LIMIT 500");
    let rows: Vec<DeviceRow> = conn
        .prepare(&sql)
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params_from_iter(args), |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    r.get(8)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
        })
        .unwrap_or_default();

    let sel = |v: &str, want: &str| if v == want { " selected" } else { "" };
    let mut body = String::from(
        "<form method=\"get\" action=\"/devices\" style=\"display:flex;gap:8px;margin-bottom:10px\">\
<select name=\"state\"><option value=\"\">any state</option>",
    );
    for s in ["up", "down", "unreachable", "unknown", "all"] {
        let _ = write!(body, "<option value=\"{s}\"{}>{s}</option>", sel(state, s));
    }
    let q_esc = esc(q);
    let _ = write!(body,
        "</select><input name=\"q\" placeholder=\"ip or mac contains\u{2026}\" value=\"{q_esc}\">\
<button type=\"submit\">filter</button> <a href=\"/devices\">reset</a></form>\
<table><tr><th>ip</th><th>class</th><th>host</th><th>role</th><th>state</th><th>perf</th><th>mac</th><th>site</th><th>seen</th></tr>");

    for (ip, role, st, perf, mac, site, hostname, class, seen) in rows {
        let perf_disp = if perf == "ok" {
            "-".to_string()
        } else {
            badge(perf.trim_start_matches("latency_").trim_start_matches("loss_"))
        };
        let host_disp = if hostname.is_empty() {
            "-".to_string()
        } else {
            esc(&hostname)
        };
        let class_disp = if class.is_empty() || class == "unknown" {
            "-".to_string()
        } else {
            esc(&class)
        };
        let _ = write!(body,
            "<tr><td><a href=\"/device/{ip}\">{ip}</a></td><td>{class_disp}</td><td>{host_disp}</td><td>{role}</td><td>{}</td><td>{perf_disp}</td>\
<td class=\"mono muted\">{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
            badge(&st),
            mac.as_deref().unwrap_or("-"),
            site.as_deref().unwrap_or("-"),
            ago(seen));
    }
    body.push_str("</table>");
    page(conn, "Devices", "Devices", &body)
}

pub fn device_detail(conn: &Connection, ip: &str) -> String {
    let Some(d) = db::device_by_ip(conn, ip).ok().flatten() else {
        return page(conn, "Unknown device", "", "<h2>unknown device</h2>");
    };
    let now = chrono::Utc::now().timestamp();
    let up24 = db::uptime_pct_window(conn, d.id, now - 86_400);
    let up7d = db::uptime_pct_window(conn, d.id, now - 7 * 86_400);
    let series = db::recent_rtt_series(conn, d.id, 240).unwrap_or_default();
    let segs = db::segments_window(conn, d.id, now - 86_400, 400).unwrap_or_default();
    let evs = db::list_events(conn, false, None, Some(d.id), 0, 15).unwrap_or_default();
    let maint_active = d.maintenance_until_ts.is_some_and(|t| t > now);

    let spark: Vec<(i64, f64)> =
        series.iter().filter_map(|(t, r)| r.map(|v| (*t, v))).collect();

    let parent = d
        .parent_id
        .and_then(|pid| db::device_by_id(conn, pid).ok().flatten())
        .map(|p| format!("<a href=\"/device/{}\">{}</a>", p.ip, p.ip))
        .unwrap_or_else(|| "-".into());
    let maint_disp = if maint_active {
        format!("until {}", hhmm(d.maintenance_until_ts.unwrap()))
    } else {
        "none".into()
    };

    let mut body = String::new();
    let _ = write!(body,
        "<h2 class=\"mono\">{ip}&nbsp;<span class=\"muted\">({role})</span></h2>\
<table><tr><th>field</th><th>value</th></tr>\
<tr><td>effective state</td><td>{}</td></tr>\
<tr><td>perf</td><td>{}</td></tr>\
<tr><td>mac</td><td class=\"mono\">{}</td></tr>\
<tr><td>site</td><td>{}</td></tr>\
<tr><td>hostname</td><td class=\"mono\">{}</td></tr>\
<tr><td>device class</td><td>{}</td></tr>\
<tr><td>parent</td><td>{parent}</td></tr>\
<tr><td>first / last seen</td><td>{} / {}</td></tr>\
<tr><td>flaps (window)</td><td>{}</td></tr>\
<tr><td>maintenance</td><td>{maint_disp}</td></tr>\
<tr><td>uptime 24h / 7d</td><td>{} / {}</td></tr></table>",
        badge(&d.eff_state),
        if d.perf_status == "ok" { "-".to_string() } else { badge(&d.perf_status) },
        d.mac.as_deref().unwrap_or("-"),
        esc(&db::site_name(conn, d.site_id)),
        esc(d.hostname.as_deref().unwrap_or("-")),
        if d.device_class.as_deref().unwrap_or("unknown") == "unknown" {
            "-".to_string()
        } else {
            badge(d.device_class.as_deref().unwrap_or("unknown"))
        },
        hhmm(d.first_seen_ts),
        hhmm(d.last_seen_ts),
        d.flap_count,
        up24.map(|v| format!("{v:.2}%")).unwrap_or_else(|| "-".into()),
        up7d.map(|v| format!("{v:.2}%")).unwrap_or_else(|| "-".into()),
        role = esc(&d.role));

    // actions
    let (mbtn, mval) = if maint_active { ("stop maintenance", "off") } else { ("maintenance 60 min", "60") };
    let (mgbtn, mgval) = if d.managed { ("mark unmanaged", "0") } else { ("mark managed", "1") };
    let ip_js = esc(ip);
    let _ = write!(body,
        "<div class=\"panel\" style=\"margin:10px 0\"><h2>Actions</h2>\
<form class=\"inline\" method=\"post\" action=\"/api/device\">\
<input type=\"hidden\" name=\"ip\" value=\"{ip}\"><input type=\"hidden\" name=\"action\" value=\"maintenance\">\
<input type=\"hidden\" name=\"value\" value=\"{mval}\"><button>{mbtn}</button></form> &nbsp;\
<form class=\"inline\" method=\"post\" action=\"/api/device\">\
<input type=\"hidden\" name=\"ip\" value=\"{ip}\"><input type=\"hidden\" name=\"action\" value=\"site\">\
<input name=\"value\" placeholder=\"site name (blank = auto)\">\
<button>assign site</button></form> &nbsp;\
<form class=\"inline\" method=\"post\" action=\"/api/device\">\
<input type=\"hidden\" name=\"ip\" value=\"{ip}\"><input type=\"hidden\" name=\"action\" value=\"managed\">\
<input type=\"hidden\" name=\"value\" value=\"{mgval}\"><button>{mgbtn}</button></form> &nbsp;\
<form class=\"inline\" method=\"post\" action=\"/api/device\" onsubmit=\"return confirm('Remove {ip_js} from inventory and map? History events are kept.')\">\
<input type=\"hidden\" name=\"ip\" value=\"{ip}\"><input type=\"hidden\" name=\"action\" value=\"remove\">\
<button style=\"color:var(--down)\">remove from inventory</button></form></div>");

    let _ = write!(body,
        "<div class=\"panel\" style=\"margin:10px 0\"><h2>Diagnostics</h2>\
<button onclick=\"runDiag('{ip_js}')\">Run diagnostics</button> &nbsp;\
<button onclick=\"tracePath('{ip_js}')\">Trace path</button> &nbsp;\
<button onclick=\"pingOne()\">Quick ping</button> &nbsp;\
<span id=\"pingone\" class=\"muted\"></span>\
<div id=\"diagout\" class=\"muted\" style=\"margin-top:8px\">burst pings measure loss / jitter / percentiles \u{2014} ICMP responsiveness, not Mbps bandwidth.</div></div>\
<script>
const escHtml = s => {{ const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }};
const fmt1 = v => v == null ? '-' : Number(v).toFixed(1);
async function runDiag(ip) {{
  const el = document.getElementById('diagout');
  el.textContent = 'running burst ping + port probe…';
  try {{
    const r = await fetch('/api/diagnose?ip=' + encodeURIComponent(ip), {{ method: 'POST' }});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    const g = d.diag;
    const svcs = (d.services || []).map(s => s.port + '(' + s.service + ')').join(', ');
    const miss = (d.expected_missing || []);
    el.innerHTML = '<b>score ' + g.score + '/100 (' + g.verdict + ')</b> · loss ' +
      g.loss_pct.toFixed(0) + '% · avg ' + fmt1(g.rtt_avg) + 'ms · min/max ' +
      fmt1(g.rtt_min) + '/' + fmt1(g.rtt_max) + 'ms · p95 ' + fmt1(g.rtt_p95) +
      'ms · jitter ' + fmt1(g.jitter_ms) + 'ms<br>class: <b>' + escHtml(d.device_class) +
      '</b>' + (d.hostname ? ' · host ' + escHtml(d.hostname) : '') +
      (svcs ? ' · open ports ' + escHtml(svcs) : '') +
      (miss.length ? '<br><span style=\\'color:var(--down)\\'>missing expected services: ' +
        escHtml(miss.join(', ')) + '</span>' : '');
  }} catch (e) {{ el.textContent = 'diagnostics failed: ' + e.message; }}
}}
async function tracePath(ip) {{
  const el = document.getElementById('diagout');
  el.textContent = 'tracing path…';
  try {{
    const r = await fetch('/api/trace?ip=' + encodeURIComponent(ip), {{ method: 'POST' }});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    let html = '<table><tr><th>hop</th><th>address</th><th>role</th><th>site</th><th>rtt</th></tr>';
    for (const h of d.hops) {{
      html += '<tr><td>' + h.ttl + '</td><td class=\\'mono\\'>' +
        (h.reached ? '<b>' : '') + escHtml(h.ip || '*') + (h.reached ? '</b> (target)' : '') +
        '</td><td>' + escHtml(h.role || '-') + '</td><td>' + escHtml(h.site || '-') +
        '</td><td>' + fmt1(h.rtt_ms) + ' ms</td></tr>';
    }}
    el.innerHTML = html + '</table>';
  }} catch (e) {{ el.textContent = 'trace failed: ' + e.message; }}
}}
async function pingOne() {{
  try {{
    const r = await fetch('/api/ping?ip=' + encodeURIComponent('{ip_js}'), {{ method: 'POST' }});
    const d = await r.json();
    document.getElementById('pingone').textContent = d.ip + (d.up ? ' UP ' : ' DOWN ') +
      (d.rtt_ms == null ? '' : d.rtt_ms.toFixed(1) + 'ms');
  }} catch (e) {{ document.getElementById('pingone').textContent = 'ping failed'; }}
}}
pingOne();
</script>");

    // dependency impact: what sits behind this device
    let children: Vec<String> = conn
        .prepare("SELECT ip FROM devices WHERE parent_id = ?1 ORDER BY ip LIMIT 500")
        .and_then(|mut s| {
            s.query_map(rusqlite::params![d.id], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .unwrap_or_default();
    if !children.is_empty() {
        let mut list = String::new();
        for c in &children {
            let _ = write!(list, "<a href=\"/device/{c}\">{c}</a> ");
        }
        let _ = write!(body,
            "<div class=\"panel\" style=\"margin:10px 0\"><h2>Depends on this device ({})</h2>{list}</div>",
            children.len());
    }

    // interface inventory (FR-DISC-003)
    let ifaces = db::list_interfaces(conn, d.id).unwrap_or_default();
    if ifaces.is_empty() && d.role == "endpoint" {
        let _ = write!(body,
            "<p class=\"muted\" style=\"margin:10px 0\">No interface inventory collected for this \
             endpoint yet \u{2014} interfaces appear after SNMP/LLDP discovery (FR-DISC-003).</p>");
    } else {
        let mut irows = String::new();
        for i in &ifaces {
            let _ = write!(irows,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td>\
<td>{}</td><td>{}</td><td class=\"mono\">{}</td></tr>",
                i.if_index,
                esc(i.name.as_deref().unwrap_or("-")),
                speed_str(i.speed_bps),
                if_status(i.admin_status.as_deref()),
                if_status(i.oper_status.as_deref()),
                esc(i.mac.as_deref().unwrap_or("-")));
        }
        let table = if irows.is_empty() {
            "<span class=\"muted\">no interfaces discovered yet</span>".to_string()
        } else {
            format!(
                "<table><tr><th>ifIndex</th><th>name</th><th>speed</th><th>admin</th>\
<th>oper</th><th>MAC</th></tr>{irows}</table>"
            )
        };
        let _ = write!(body,
            "<div class=\"panel\" style=\"margin:10px 0\"><h2>Interfaces ({})</h2>{table}</div>",
            ifaces.len());
    }

    // discovered neighbors via LLDP/CDP (FR-DISC-004)
    let nbrs = db::list_neighbors(conn, d.id).unwrap_or_default();
    let nbody = if nbrs.is_empty() {
        "<span class=\"muted\">No LLDP/CDP neighbors reported yet</span>".to_string()
    } else {
        let disp = |v: &Option<String>| {
            esc(v.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("-"))
        };
        let mut rows = String::new();
        for n in &nbrs {
            let proto = n.protocol.trim();
            let proto_cell = if proto.is_empty() {
                "-".to_string()
            } else {
                format!("<span class=\"badge b-info\">{}</span>", esc(proto))
            };
            let _ = write!(rows,
                "<tr><td>{proto_cell}</td><td class=\"mono\">{port}</td>\
<td>{sys}<br><span class=\"mono muted\">{ip} \u{b7} {mac}</span></td><td>{plat}</td></tr>",
                port = disp(&n.local_if_name),
                sys = disp(&n.neighbor_sysname),
                ip = disp(&n.neighbor_ip),
                mac = disp(&n.neighbor_mac),
                plat = disp(&n.neighbor_platform));
        }
        format!(
            "<table><tr><th>proto</th><th>local port</th>\
<th>neighbor (sysname / ip / mac)</th><th>platform</th></tr>{rows}</table>"
        )
    };
    let _ = write!(body,
        "<div class=\"panel\" style=\"margin:10px 0\"><h2>Discovered neighbors ({})</h2>{nbody}</div>",
        nbrs.len());

    let chart = svg_line(&spark, 600, 120, "var(--info)", "ms");
    let timeline = svg_timeline(&segs, now - 86_400, now);
    let _ = write!(body,
        "<div class=\"grid2\"><div class=\"panel\"><h2>RTT (last probes)</h2>{chart}</div>\
<div class=\"panel\"><h2>State timeline \u{2014} 24h</h2>{timeline}</div></div>");

    body.push_str("<h3>Recent events</h3><table><tr><th>when</th><th>sev</th><th>kind</th>\
<th>message</th><th>state</th><th>ack</th></tr>");
    for e in &evs {
        let ack_form = if e.state == "open" {
            let next = if e.acknowledged { "0" } else { "1" };
            let label = if e.acknowledged { "unack" } else { "ack" };
            format!(
                "<form class=\"inline\" method=\"post\" action=\"/api/event/ack\">\
<input type=\"hidden\" name=\"id\" value=\"{}\"><input type=\"hidden\" name=\"ack\" value=\"{next}\">\
<button>{label}</button></form>",
                e.id
            )
        } else {
            "-".to_string()
        };
        let ack_info = if e.acknowledged {
            format!("by {} {}", esc(e.ack_by.as_deref().unwrap_or("?")), ago(e.ack_ts.unwrap_or(0)))
        } else {
            String::new()
        };
        let st = if e.state == "open" { badge("open") } else { closed_badge().to_string() };
        let _ = write!(body,
            "<tr><td class=\"muted\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{st}</td><td>{ack_form} {}</td></tr>",
            ago(e.created_ts), badge(&e.severity), esc(&e.kind), esc(&e.message), ack_info);
    }
    body.push_str("</table>");
    page(conn, ip, "", &body)
}

fn svg_timeline(segs: &[db::Segment], start: i64, end: i64) -> String {
    if segs.is_empty() {
        return "<div class=\"muted\">no segments in window</div>".into();
    }
    let w = 600.0f64;
    let span = (end - start).max(1) as f64;
    let mut out = String::from(
        "<svg viewBox=\"0 0 600 46\" style=\"width:100%;height:auto;background:#0b1220;border-radius:6px\">",
    );
    let mut y = 6.0;
    for s in segs.iter().take(3) {
        let s0 = s.started_ts.max(start);
        let s1 = s.ended_ts.unwrap_or(end).min(end);
        let x = ((s0 - start) as f64 / span) * w;
        let wid = (((s1 - s0) as f64 / span) * w).max(1.5);
        let color = match s.state.as_str() {
            "up" => "#3ddc84",
            "down" => "#ff5470",
            _ => "#ffb454",
        };
        let _ = write!(out, "<rect x=\"{x:.1}\" y=\"{y}\" width=\"{wid:.1}\" height=\"12\" fill=\"{color}\" rx=\"2\"/>");
        y += 14.0;
    }
    out.push_str("</svg>");
    out
}

// ------------------------------------------------------------------- triage

/// NetBrain-style one-click diagnosis: everything relevant to a suspected
/// fault on one screen (FR-UX-005 v0).
pub fn triage_page(conn: &Connection, ip: &str) -> String {
    let Some(d) = db::device_by_ip(conn, ip).ok().flatten() else {
        return page(conn, "Unknown device", "", "<h2>unknown device</h2>");
    };
    let now = chrono::Utc::now().timestamp();

    // Root cause chain: walk parents while they are down/unreachable.
    let mut chain = vec![format!("<b class=\"mono\">{}</b> {}", d.ip, badge(&d.eff_state))];
    let mut cursor = d.parent_id;
    let mut guard = 0;
    while let Some(pid) = cursor {
        guard += 1;
        if guard > 8 {
            break;
        }
        match db::device_by_id(conn, pid).ok().flatten() {
            Some(p) => {
                chain.push(format!(
                    "&uarr; <a href=\"/device/{}\">{}</a> {} ({})",
                    p.ip,
                    p.ip,
                    badge(&p.eff_state),
                    esc(&db::site_name(conn, p.site_id))
                ));
                cursor = p.parent_id;
            }
            None => break,
        }
    }

    // probable root: nearest ancestor that is down, else this device itself
    let _root_ip = {
        let mut cur = Some(d.id);
        let mut found = None;
        let mut hops = 0;
        while let Some(id) = cur {
            hops += 1;
            if hops > 8 {
                break;
            }
            if let Ok(Some(p)) = db::device_by_id(conn, id) {
                let parent = p.parent_id;
                if matches!(p.eff_state.as_str(), "down" | "unreachable") {
                    found = Some(p);
                }
                cur = if found.is_some() { None } else { parent };
            } else {
                break;
            }
        }
        found.map(|p| p.ip).unwrap_or_else(|| d.ip.clone())
    };

    // dependents impacted by this device
    let children: Vec<String> = conn
        .prepare("SELECT ip FROM devices WHERE parent_id=?1 ORDER BY ip LIMIT 500")
        .and_then(|mut s| {
            s.query_map(rusqlite::params![d.id], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .unwrap_or_default();

    let series = db::recent_rtt_series(conn, d.id, 120).unwrap_or_default();
    let spark: Vec<(i64, f64)> =
        series.iter().filter_map(|(t, r)| r.map(|v| (*t, v))).collect();
    let segs = db::segments_window(conn, d.id, now - 6 * 3600, 200).unwrap_or_default();
    let evs = db::list_events(conn, false, None, Some(d.id), 0, 10).unwrap_or_default();
    let diag = db::latest_diag(conn, d.id).ok().flatten();

    let mut body = format!(
        "<h2>Triage \u{2014} <span class=\"mono\">{ip}</span></h2>\
<div class=\"panel\" style=\"margin-bottom:14px\"><h2>Causal chain (this device &rarr; network root)</h2><div>{}</div></div>",
        chain.join("<br>")
    );

    // impact
    if !children.is_empty() {
        let mut list = String::new();
        for c in &children {
            let _ = write!(list, "<a href=\"/device/{c}\">{c}</a> ");
        }
        let _ = write!(
            body,
            "<div class=\"panel\" style=\"margin-bottom:14px\"><h2>Depends on this device ({})</h2>{list}</div>",
            children.len()
        );
    }

    // charts + events side by side
    let chart = svg_line(&spark, 600, 110, "var(--info)", "ms");
    let timeline = svg_timeline(&segs, now - 6 * 3600, now);
    let _ = write!(
        body,
        "<div class=\"grid2\"><div class=\"panel\"><h2>RTT (recent)</h2>{chart}</div>\
<div class=\"panel\"><h2>State timeline \u{2014} 6h</h2>{timeline}</div></div>"
    );

    // latest stored diagnostics summary if any
    if let Some(dg) = &diag {
        let _ = write!(
            body,
            "<div class=\"panel\" style=\"margin:10px 0\"><h2>Last diagnostics</h2><span class=\"muted\">{}</span> \
score {} ({}) · loss {:.0}% · ports {}</div>",
            ago(dg.get("ts").and_then(|v| v.as_i64()).unwrap_or(0)),
            dg.get("score").and_then(|v| v.as_i64()).unwrap_or(-1),
            esc(dg.get("verdict").and_then(|v| v.as_str()).unwrap_or("?")),
            dg.get("loss_pct").and_then(|v| v.as_f64()).unwrap_or(0.0),
            esc(dg.get("open_ports").and_then(|v| v.as_str()).unwrap_or("-"))
        );
    }

    let _ = write!(
        body,
        "<div class=\"panel\" style=\"margin:10px 0\"><h2>Run now</h2>\
<button onclick=\"runDiag('{ip}')\">Diagnostics</button> &nbsp;\
<button onclick=\"tracePath('{ip}')\">Trace path</button> &nbsp;\
<button onclick=\"ackAll('{ip}')\">Acknowledge open alerts</button>\
<div id=\"out\" class=\"muted\" style=\"margin-top:8px\"></div></div>\
<script>
const e = s => {{ const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }};
const f1 = v => v==null ? '-' : Number(v).toFixed(1);
async function runDiag(ip) {{
  const el=document.getElementById('out'); el.textContent='running…';
  try {{
    const r=await fetch('/api/diagnose?ip='+encodeURIComponent(ip),{{method:'POST'}});
    const d=await r.json(); if(!r.ok) throw new Error(d.error||r.status);
    el.innerHTML='<b>'+d.diag.score+'/100 ('+d.diag.verdict+')</b> loss '+d.diag.loss_pct.toFixed(0)+
      '% avg '+f1(d.diag.rtt_avg)+'ms class '+e(d.device_class);
  }} catch(err) {{ el.textContent='failed: '+err.message; }}
}}
async function tracePath(ip) {{
  const el=document.getElementById('out'); el.textContent='tracing…';
  try {{
    const r=await fetch('/api/trace?ip='+encodeURIComponent(ip),{{method:'POST'}});
    const d=await r.json(); if(!r.ok) throw new Error(d.error||r.status);
    el.innerHTML=d.hops.map(h=>h.ttl+': '+(h.reached?'<b>':'')+e(h.ip||'*')+
      (h.reached?'</b>':'')+' '+f1(h.rtt_ms)+'ms').join('<br>');
  }} catch(err) {{ el.textContent='failed: '+err.message; }}
}}
async function ackAll(ip) {{
  try {{
    const list=await (await fetch('/events?view=open&ip='+encodeURIComponent(ip))).text();
    el_text='use Events page to acknowledge individually';
    document.getElementById('out').textContent=el_text;
  }} catch(err) {{ document.getElementById('out').textContent='failed'; }}
}}
</script>",
        ip = esc(ip)
    );

    // recent events table
    body.push_str("<h3>Recent events for this device</h3><table><tr><th>when</th><th>sev</th><th>kind</th><th>message</th><th>state</th></tr>");
    for e in &evs {
        let st = if e.state == "open" { badge("open") } else { closed_badge().to_string() };
        let _ = write!(
            body,
            "<tr><td class=\"muted\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{st}</td></tr>",
            ago(e.created_ts), badge(&e.severity), esc(&e.kind), esc(&e.message)
        );
    }
    body.push_str("</table>");
    page(conn, &format!("Triage {ip}"), "", &body)
}

// ------------------------------------------------------------------- events

pub fn events_page(conn: &Connection, only_open: bool, severity: Option<&str>) -> String {
    let evs = db::list_events(conn, only_open, severity, None, 0, 200).unwrap_or_default();
    let sev_sel = severity.unwrap_or("");
    let view_sel = if only_open { "open" } else { "all" };
    let mut body = format!(
        "<form method=\"get\" action=\"/events\" style=\"display:flex;gap:8px;margin-bottom:10px\">\
<select name=\"view\"><option value=\"all\"{}>all</option><option value=\"open\"{}>open only</option></select>\
<select name=\"severity\"><option value=\"\">any severity</option>",
        if view_sel == "all" { " selected" } else { "" },
        if view_sel == "open" { " selected" } else { "" }
    );
    for s in ["critical", "warning", "info"] {
        let sel = if sev_sel == s { " selected" } else { "" };
        let _ = write!(body, "<option value=\"{s}\"{sel}>{s}</option>");
    }
    let _ = write!(body,
        "</select><button>filter</button></form>\
<table><tr><th>time</th><th>sev</th><th>kind</th><th>device</th><th>message</th>\
<th>state</th><th>ack</th><th></th></tr>");
    for e in &evs {
        let ack_btn = if e.state == "open" {
            let next = if e.acknowledged { "0" } else { "1" };
            let label = if e.acknowledged { "unack" } else { "ack" };
            format!(
                "<form class=\"inline\" method=\"post\" action=\"/api/event/ack\">\
<input type=\"hidden\" name=\"id\" value=\"{}\"><input type=\"hidden\" name=\"ack\" value=\"{next}\">\
<button>{label}</button></form>",
                e.id
            )
        } else {
            String::new()
        };
        let ack_info = if e.acknowledged {
            format!("by {}", esc(e.ack_by.as_deref().unwrap_or("?")))
        } else {
            String::new()
        };
        let dev = e.ip.as_deref()
            .map(|ip| format!("<a href=\"/device/{ip}\">{ip}</a>"))
            .unwrap_or_default();
        let st = if e.state == "open" { badge("open") } else { closed_badge().to_string() };
        let _ = write!(body,
            "<tr><td class=\"mono muted\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{dev}</td>\
<td>{}</td><td>{st}</td><td>{} {}</td><td>{ack_btn}</td></tr>",
            hhmm(e.created_ts), badge(&e.severity), esc(&e.kind), esc(&e.message), ack_info, ago(e.created_ts));
    }
    body.push_str("</table>");
    page(conn, "Events", "Events", &body)
}

// -------------------------------------------------------------------- audit

pub fn audit_page(conn: &Connection) -> String {
    let rows: Vec<(i64, String, String, String, String)> = conn
        .prepare("SELECT ts, actor, action, target, details FROM audit_log ORDER BY id DESC LIMIT 300")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
        })
        .unwrap_or_default();
    let mut body = String::from(
        "<table><tr><th>time</th><th>actor</th><th>action</th><th>target</th><th>details</th></tr>",
    );
    for (ts, actor, action, target, details) in rows {
        let _ = write!(body,
            "<tr><td class=\"mono muted\">{}</td><td>{}</td><td class=\"mono\">{}</td>\
<td class=\"mono\">{}</td><td class=\"mono muted\">{}</td></tr>",
            hhmm(ts), esc(&actor), esc(&action), esc(&target), esc(&details));
    }
    body.push_str("</table>");
    page(conn, "Audit", "Audit", &body)
}

// ----------------------------------------------------------------- settings

pub fn settings_page(conn: &Connection, saved: bool) -> String {
    const FIELDS: &[(&str, &str)] = &[
        ("poll_interval_secs", "monitor sweep interval (seconds; restart monitor after change)"),
        ("rtt_warn_ms", "latency warning threshold (ms)"),
        ("rtt_crit_ms", "latency critical threshold (ms)"),
        ("loss_window", "probes considered for loss/degradation"),
        ("loss_warn_pct", "loss percent that raises a warning"),
        ("flap_window_mins", "flap detection window (minutes)"),
        ("flap_threshold", "transitions within window that flag flapping"),
        ("raw_retention_hours", "raw probe retention (hours)"),
        ("hourly_retention_days", "hourly rollup retention (days)"),
        ("daily_retention_days", "daily rollup retention (days)"),
        ("webhook_url", "outbound webhook URL (ServiceNow-ready JSON POST)"),
        ("webhook_enabled", "enable outbound webhook (1/0)"),
        ("snow_transform", "deliver as ServiceNow incidents via Basic auth (1/0)"),
        ("snow_instance_url", "ServiceNow instance URL (https://inst.service-now.com)"),
        ("snow_username", "ServiceNow service account username"),
        ("site_auto_prefix", "auto-site subnet prefix (16 or 24)"),
    ];
    let mut body = String::new();
    if saved {
        body.push_str("<p style=\"color:var(--up)\">saved &#10003;</p>");
    }
    body.push_str("<form method=\"post\" action=\"/api/settings\"><table>\
<tr><th>setting</th><th>value</th><th>description</th></tr>");
    for (key, desc) in FIELDS {
        let val = db::get_setting_or(conn, key, "");
        let v = esc(&val);
        let _ = write!(body,
            "<tr><td class=\"mono\">{key}</td><td><input name=\"{key}\" value=\"{v}\" size=\"42\"></td>\
<td class=\"muted\">{desc}</td></tr>");
    }
    // ServiceNow password: write-only — never rendered back, blank keeps saved.
    {
        let saved = !db::get_setting_or(conn, "snow_password", "").is_empty();
        let hint = if saved { "saved &#10003; \u{2014} leave blank to keep" } else { "not set" };
        let _ = write!(body,
            "<tr><td class=\"mono\">snow_password</td>\
<td><input type=\"password\" name=\"snow_password\" value=\"\" autocomplete=\"off\" size=\"42\"></td>\
<td class=\"muted\">ServiceNow service account password ({hint}; stored locally, never displayed)</td></tr>");
    }
    body.push_str(
        "</table><button type=\"submit\">save settings</button></form>\
<h3>Outbound webhook test</h3>\
<form class=\"inline\" method=\"post\" action=\"/api/webhook/test\"><button>send test payload</button></form>",
    );
    page(conn, "Settings", "Settings", &body)
}

// ------------------------------------------------------------------ reports

use engine::reports::availability_rows;
pub fn reports_page(conn: &Connection, hours: i64) -> String {
    let rows = availability_rows(conn, hours);
    let since = chrono::Utc::now().timestamp() - hours * 3600;
    let mttr = db::mttr_secs_window(conn, since);
    let mttr_s = mttr.map(|v| format!("{v:.0}s")).unwrap_or_else(|| "-".into());
    let mtta = db::mtta_secs_window(conn, since).ok().flatten();
    let mtta_s = mtta.map(|v| format!("{v:.0}s")).unwrap_or_else(|| "-".into());
    let target: f64 = db::get_setting_or(conn, "sla_target_pct", "99.5")
        .parse()
        .unwrap_or(99.5);
    let open_crit_warn: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE state='open' AND severity IN ('critical','warning')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let resolved_in_window: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE cleared_ts IS NOT NULL AND cleared_ts >= ?1",
            [since],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let sites_total = rows.len();
    let sites_missing_sla = rows
        .iter()
        .filter(|(_, _, _, _, pct, _)| *pct < target)
        .count();
    let worst_site = rows
        .first()
        .map(|(site, _, _, _, pct, _)| format!("{} ({pct:.2}%)", esc(site)))
        .unwrap_or_else(|| "-".into());
    let mut body = String::new();
    let _ = write!(body,
        "<div style=\"display:flex;gap:8px;margin-bottom:10px;align-items:center\">\
<a class=\"badge b-info\" href=\"/reports?hours=24\">24h</a>\
<a class=\"badge b-info\" href=\"/reports?hours=168\">7d</a>\
<a class=\"badge b-info\" href=\"/reports?hours=720\">30d</a>\
<span class=\"muted\">MTTR over window: <b>{mttr_s}</b></span>\
<span class=\"muted\">MTTA over window: <b>{mtta_s}</b></span>\
<span class=\"muted\">SLA target: <b>{target:.2}%</b> (set sla_target_pct in Settings)</span>\
<a style=\"margin-left:auto\" href=\"/api/report/availability.csv?hours={hours}\">download site csv</a></div>\
<table><tr><th>site</th><th>devices</th><th>probes</th><th>uptime</th><th>SLA</th><th>avg rtt</th><th>per-device csv</th></tr>");
    for (site, devs, probes, ups, pct, rtt) in &rows {
        let bar = pct_bar(*pct);
        let enc = urlencode(site);
        let sla = if *pct >= target {
            "<span style=\"color:var(--up)\">met</span>".to_string()
        } else {
            format!(
                "<span style=\"color:var(--down)\">missed by {:.2}%</span>",
                target - pct
            )
        };
        let _ = write!(body,
            "<tr><td>{}</td><td>{devs}</td><td class=\"mono\">{probes} / {ups}</td><td>{bar}</td>\
<td>{sla}</td><td class=\"mono\">{rtt:.1} ms</td><td><a href=\"/api/report/devices.csv?hours={hours}&site={enc}\">csv</a></td></tr>",
            esc(site));
    }
    body.push_str("</table>");
    let _ = write!(body,
        "<div class=\"panel\"><h3 style=\"margin-top:0\">Executive digest</h3><table>\
<tr><th>window</th><th>open criticals / warnings</th><th>resolved in window</th>\
<th>sites missing SLA</th><th>worst site (uptime)</th></tr>\
<tr><td class=\"mono\">{hours}h</td><td class=\"mono\">{open_crit_warn}</td>\
<td class=\"mono\">{resolved_in_window}</td>\
<td class=\"mono\">{sites_missing_sla} / {sites_total}</td><td>{worst_site}</td></tr></table></div>");
    page(conn, "Reports", "Reports", &body)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::db::{Db, DeviceUpdate, IfaceRow, NeighborRow};

    fn upsert(conn: &Connection, ip: &str, role: &str) -> i64 {
        db::upsert_device(
            conn,
            &DeviceUpdate {
                ip,
                mac: None,
                role,
                subnet_site_label: None,
                parent_ip: None,
                state: "up",
                up_now: true,
                rtt_ms: Some(1.0),
                ts: 1_000,
                site_prefix: 24,
                hostname: None,
                device_class: None,
            },
        )
        .unwrap()
        .id
    }

    #[test]
    fn speed_str_humanizes() {
        assert_eq!(speed_str(None), "-");
        assert_eq!(speed_str(Some(0)), "-");
        assert_eq!(speed_str(Some(1_000_000_000)), "1 Gbps");
        assert_eq!(speed_str(Some(10_000_000_000)), "10 Gbps");
        assert_eq!(speed_str(Some(2_500_000_000)), "2.5 Gbps");
        assert_eq!(speed_str(Some(100_000_000)), "100 Mbps");
        assert_eq!(speed_str(Some(10_000_000)), "10 Mbps");
    }

    #[test]
    fn if_status_colors_up_down() {
        assert_eq!(
            if_status(Some("up")),
            "<span style=\"color:var(--up)\">up</span>"
        );
        assert_eq!(
            if_status(Some("down")),
            "<span style=\"color:var(--down)\">down</span>"
        );
        assert_eq!(if_status(Some("testing")), "testing");
        assert_eq!(if_status(None), "-");
        // names/statuses are escaped before embedding
        assert_eq!(if_status(Some("<x>")), "&lt;x&gt;");
    }

    #[test]
    fn endpoint_without_interfaces_shows_muted_line_not_panel() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        upsert(&conn, "10.9.0.1", "endpoint");
        let html = device_detail(&conn, "10.9.0.1");
        assert!(html.contains("No interface inventory collected for this endpoint"));
        assert!(!html.contains("<h2>Interfaces"));
    }

    #[test]
    fn router_always_shows_interface_panel_header() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        upsert(&conn, "10.9.0.2", "router");
        let html = device_detail(&conn, "10.9.0.2");
        assert!(html.contains("<h2>Interfaces (0)</h2>"));
        assert!(html.contains("no interfaces discovered yet"));
    }

    #[test]
    fn interface_rows_render_speed_and_statuses() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        let id = upsert(&conn, "10.9.0.3", "router");
        db::replace_interfaces(
            &conn,
            id,
            &[IfaceRow {
                if_index: 1,
                name: Some("eth<0>".into()),
                speed_bps: Some(1_000_000_000),
                admin_status: Some("up".into()),
                oper_status: Some("down".into()),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
            }],
            1_500,
        )
        .unwrap();
        let html = device_detail(&conn, "10.9.0.3");
        assert!(html.contains("<h2>Interfaces (1)</h2>"));
        assert!(html.contains(">eth&lt;0&gt;<"));
        assert!(html.contains("1 Gbps"));
        assert!(html.contains("color:var(--up)\">up<"));
        assert!(html.contains("color:var(--down)\">down<"));
        assert!(html.contains("aa:bb:cc:dd:ee:ff"));
        assert!(html.contains("<th>ifIndex</th>"));
    }

    #[test]
    fn device_without_neighbors_shows_muted_line_not_table() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        upsert(&conn, "10.9.0.4", "router");
        let html = device_detail(&conn, "10.9.0.4");
        assert!(html.contains("No LLDP/CDP neighbors reported yet"));
        assert!(!html.contains("<th>proto</th>"));
    }

    #[test]
    fn neighbor_rows_render_badge_fields_and_escaping() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        let id = upsert(&conn, "10.9.0.5", "router");
        db::replace_neighbors(
            &conn,
            id,
            &[NeighborRow {
                local_if_name: Some("Gi0/<1>".into()),
                neighbor_ip: Some("10.0.0.2".into()),
                neighbor_mac: Some("aa:bb:cc:dd:ee:01".into()),
                neighbor_sysname: Some("core-sw".into()),
                neighbor_platform: Some("cisco WS-C3750".into()),
                protocol: "lldp".into(),
            }],
            1_600,
        )
        .unwrap();
        let html = device_detail(&conn, "10.9.0.5");
        // panel directly follows the Interfaces panel
        let iface_pos = html.find("<h2>Interfaces (0)</h2>").unwrap();
        let nbr_pos = html.find("<h2>Discovered neighbors (1)</h2>").unwrap();
        assert!(iface_pos < nbr_pos);
        assert!(html.contains("badge b-info\">lldp<"));
        assert!(html.contains(">Gi0/&lt;1&gt;<"));
        assert!(html.contains(">core-sw<"));
        assert!(html.contains("cisco WS-C3750"));
        assert!(html.contains("aa:bb:cc:dd:ee:01"));
        assert!(html.contains("<th>neighbor (sysname / ip / mac)</th>"));

        // blank optional fields render as "-", never raw HTML
        db::replace_neighbors(
            &conn,
            id,
            &[NeighborRow {
                local_if_name: None,
                neighbor_ip: Some("10.0.0.9".into()),
                neighbor_mac: None,
                neighbor_sysname: None,
                neighbor_platform: Some("<script>x</script>".into()),
                protocol: String::new(),
            }],
            1_700,
        )
        .unwrap();
        let html = device_detail(&conn, "10.9.0.5");
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(html.contains("<td>-</td>"));
    }

    #[test]
    fn reports_page_shows_mtta_and_executive_digest() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        upsert(&conn, "10.9.0.7", "router");
        let now = chrono::Utc::now().timestamp();
        let acked = db::create_event(
            &conn,
            Some(1),
            Some("10.9.0.7"),
            "device_down",
            "critical",
            "router down",
            None,
            now - 3_600,
        )
        .unwrap();
        db::ack_event(&conn, acked.id, true, "web", now - 3_540).unwrap();
        let cleared = db::create_event(
            &conn,
            Some(1),
            Some("10.9.0.7"),
            "latency_warn",
            "warning",
            "latency spike",
            None,
            now - 7_200,
        )
        .unwrap();
        db::clear_event(&conn, cleared.id, now - 60).unwrap();
        let html = reports_page(&conn, 24);
        // no segments -> MTTR "-", acked critical -> MTTA 60s
        assert!(html.contains("MTTR over window: <b>-</b>"));
        assert!(html.contains("MTTA over window: <b>60s</b>"));
        // digest: 1 open crit/warn (acked one), 1 resolved in window,
        // 1/1 sites missing SLA (no rollups -> 0.00% uptime), worst site named
        assert!(html.contains("<h3 style=\"margin-top:0\">Executive digest</h3>"));
        assert!(html.contains(">open criticals / warnings<"));
        assert!(html.contains("<td class=\"mono\">1</td>"));
        assert!(html.contains(">resolved in window<"));
        assert!(html.contains("<td class=\"mono\">1 / 1</td>"));
        assert!(html.contains(">sites missing SLA<"));
        assert!(html.contains(">worst site (uptime)<"));
        assert!(html.contains("<td>unassigned (0.00%)</td>"));
    }

    #[test]
    fn reports_page_empty_db_digest_defaults() {
        let dbh = Db::open_memory().unwrap();
        let conn = dbh.lock();
        let html = reports_page(&conn, 168);
        assert!(html.contains("MTTA over window: <b>-</b>"));
        assert!(html.contains("Executive digest"));
        assert!(html.contains("<td class=\"mono\">0</td>"));
        assert!(html.contains("<td class=\"mono\">0 / 0</td>"));
        assert!(html.contains("<td>-</td>")); // worst site placeholder
    }
}
