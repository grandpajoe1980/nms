use crate::check;
use crate::db::{self, Db};
use crate::model::{Model, State};
use anyhow::Result;
use rusqlite::Connection;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct CycleStats {
    pub started_ts: i64,
    pub duration_ms: u64,
    pub probed: usize,
    pub up: usize,
    pub down_root: usize,
    pub unreachable: usize,
    pub degraded: usize,
    pub new_events: usize,
    pub queued: usize,
    pub unprobed: usize,
}

fn setting_i64(conn: &Connection, key: &str, default: i64) -> i64 {
    db::get_setting_or(conn, key, &default.to_string()).parse().unwrap_or(default)
}

fn state_str(s: State) -> &'static str {
    match s {
        State::Up => "up",
        State::Down => "down",
        State::Unknown => "unknown",
    }
}

fn role_str(r: crate::model::Role) -> &'static str {
    match r {
        crate::model::Role::Router => "router",
        crate::model::Role::Wap => "wap",
        crate::model::Role::Endpoint => "endpoint",
    }
}

/// Sync every model device into the inventory (preserves manual fields).
pub fn sync_model(conn: &Connection, model: &Model, site_prefix: u8) -> Result<HashMap<String, i64>> {
    let mut ids = HashMap::new();
    let now = chrono::Utc::now().timestamp();
    // Pass 1: ensure every device row exists so parent lookups resolve.
    for d in &model.devices {
        let site_label =
            db::auto_site_label(&d.ip.to_string(), site_prefix).or_else(|| d.subnet.clone());
        let rec = db::upsert_device(
            conn,
            &db::DeviceUpdate {
                ip: &d.ip.to_string(),
                mac: d.mac.clone(),
                role: role_str(d.role),
                subnet_site_label: site_label,
                parent_ip: None,
                state: state_str(d.state),
                up_now: d.state == State::Up,
                rtt_ms: d.rtt_ms,
                ts: now,
                site_prefix,
            },
        )?;
        ids.insert(rec.ip.clone(), rec.id);
    }
    // Pass 2: attach parents (endpoint->wap, otherwise lowest-IP router in subnet).
    for d in &model.devices {
        let parent_ip: Option<String> = if let Some(w) = d.wap {
            Some(w.to_string())
        } else {
            model
                .devices
                .iter()
                .filter(|c| c.role == crate::model::Role::Router && c.ip != d.ip)
                .filter(|c| c.subnet.is_some() && c.subnet == d.subnet)
                .map(|c| c.ip)
                .min_by_key(|ip| u32::from(*ip))
                .map(|ip| ip.to_string())
        };
        if let Some(pip) = parent_ip {
            if let (Some(child), Some(parent)) = (
                ids.get(&d.ip.to_string()),
                ids.get(&pip),
            ) {
                if child != parent {
                    conn.execute(
                        "UPDATE devices SET parent_id = ?2 WHERE id = ?1",
                        rusqlite::params![child, parent],
                    )?;
                }
            }
        }
    }
    Ok(ids)
}

struct Node {
    ip: String,
    role: String,
    id: i64,
    parent_id: Option<i64>,
    state: String,
    /// effective state after dependency suppression
    eff: String,
    /// previous stored effective state
    eff_prev: String,
    /// nearest DOWN ancestor/root when unreachable
    root: Option<i64>,
    flap: i64,
    maint_until: Option<i64>,
}

/// Resolve effective states with dependency suppression: anything whose
/// parent chain contains a DOWN node becomes `unreachable` and inherits the
/// root-cause device id instead of raising its own outage.
fn resolve_dependencies(devs: Vec<db::DeviceRec>) -> HashMap<i64, Node> {
    let mut nodes: HashMap<i64, Node> = devs
        .into_iter()
        .map(|d| {
            (
                d.id,
                Node {
                    id: d.id,
                    ip: d.ip.clone(),
                    role: d.role.clone(),
                    parent_id: d.parent_id,
                    state: d.state.clone(),
                    eff: d.state.clone(),
                    eff_prev: d.eff_state.clone(),
                    root: None,
                    flap: d.flap_count,
                    maint_until: d.maintenance_until_ts,
                },
            )
        })
        .collect();

    // Iterative fixpoint (chains are shallow: endpoint -> wap -> router).
    for _ in 0..8 {
        let mut changed = false;
        let updates: Vec<(i64, String, Option<i64>)> = nodes
            .values()
            .map(|n| {
                let mut eff = n.eff.clone();
                let mut root = n.root;
                if let Some(pid) = n.parent_id {
                    if let Some(p) = nodes.get(&pid) {
                        if p.state == "down" || p.eff == "unreachable" {
                            eff = "unreachable".into();
                            root = p.root.or(Some(p.id));
                        }
                    }
                }
                (n.id, eff, root)
            })
            .filter(|(id, eff, root)| {
                nodes.get(id).is_some_and(|n| {
                    n.eff != *eff || n.root != *root
                })
            })
            .collect();
        for (id, eff, root) in updates {
            if let Some(n) = nodes.get_mut(&id) {
                n.eff = eff;
                n.root = root;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    nodes
}

type PerfEvent = (&'static str, &'static str, String);

fn classify_perf(
    conn: &Connection,
    device_id: i64,
    window: usize,
    warn_ms: f64,
    crit_ms: f64,
    loss_pct_warn: f64,
) -> Result<(String, Option<PerfEvent>)> {
    let mut stmt = conn.prepare(
        "SELECT up, rtt_ms FROM samples WHERE device_id = ?1 ORDER BY ts DESC LIMIT ?2",
    )?;
    let rows: Vec<(bool, Option<f64>)> = stmt
        .query_map(rusqlite::params![device_id, window as i64], |r| {
            Ok((r.get::<_, i64>(0)? != 0, r.get(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(("ok".into(), None));
    }
    let ups = rows.iter().filter(|(u, _)| *u).count();
    if ups == 0 {
        return Ok(("ok".into(), None)); // availability handled by down/unreachable logic
    }
    let loss_pct = 100.0 * (rows.len() - ups) as f64 / rows.len() as f64;
    let rtts: Vec<f64> = rows.iter().filter_map(|(_, r)| *r).collect();
    let avg_rtt = rtts.iter().sum::<f64>() / rtts.len().max(1) as f64;
    let status = if avg_rtt >= crit_ms {
        "latency_crit"
    } else if avg_rtt >= warn_ms {
        "latency_warn"
    } else if loss_pct >= loss_pct_warn {
        "loss_warn"
    } else {
        "ok"
    };
    let ev = match status {
        "latency_crit" => Some((
            "perf_latency",
            "critical",
            format!("average latency {avg_rtt:.0} ms exceeds critical threshold {crit_ms:.0} ms"),
        )),
        "latency_warn" => Some((
            "perf_latency",
            "warning",
            format!("average latency {avg_rtt:.0} ms exceeds warning threshold {warn_ms:.0} ms"),
        )),
        "loss_warn" => Some((
            "perf_loss",
            "warning",
            format!("packet loss {loss_pct:.0}% over last {} probes", rows.len()),
        )),
        _ => None,
    };
    Ok((status.into(), ev))
}

fn n_flaps(conn: &Connection, device_id: i64, since: i64) -> Result<i64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM segments WHERE device_id = ?1 AND started_ts >= ?2 AND state = 'down'",
        rusqlite::params![device_id, since],
        |r| r.get(0),
    )?;
    Ok(n)
}

/// Core analysis: persist probes, resolve dependencies, drive segments,
/// events, flapping and outbound queueing. Idempotent per sweep.
#[allow(clippy::too_many_lines)]
pub fn process_result(dbh: &Arc<Db>, res: &check::RunResult, out_dir: &Path) -> Result<CycleStats> {
    let t0 = std::time::Instant::now();
    let conn = dbh.lock();
    let now = chrono::Utc::now().timestamp();
    let site_prefix = setting_i64(&conn, "site_auto_prefix", 24) as u8;
    let warn_ms = f64::from(setting_i64(&conn, "rtt_warn_ms", 150) as i32);
    let crit_ms = f64::from(setting_i64(&conn, "rtt_crit_ms", 400) as i32);
    let loss_window = setting_i64(&conn, "loss_window", 6) as usize;
    let loss_warn_pct = f64::from(setting_i64(&conn, "loss_warn_pct", 33) as i32);
    let flap_window_mins = setting_i64(&conn, "flap_window_mins", 30);
    let flap_threshold = setting_i64(&conn, "flap_threshold", 5);

    let mut stats = CycleStats { started_ts: now, probed: res.probes.len(), unprobed: res.unprobed, ..Default::default() };

    let tx = conn.unchecked_transaction()?;
    let ids = sync_model(&tx, &res.model, site_prefix)?;

    // ---- samples + hourly rollups for touched devices
    let millis_now = chrono::Utc::now().timestamp_millis();
    let hour = db::epoch_hour(millis_now);
    let mut sample_devs: HashSet<i64> = HashSet::new();
    let samples: Vec<db::Sample> = res
        .probes
        .iter()
        .filter_map(|p| {
            ids.get(&p.ip.to_string()).copied().map(|id| {
                sample_devs.insert(id);
                db::Sample { device_id: id, ts_millis: millis_now, up: p.up, rtt_ms: p.rtt_ms }
            })
        })
        .collect();
    db::insert_samples(&tx, &samples)?;
    for dev_id in &sample_devs {
        db::recompute_hourly_rollup(&tx, *dev_id, hour)?;
    }

    // ---- dependency-aware states over managed devices
    let all = db::all_devices(&tx)?;
    let nodes = resolve_dependencies(all.into_iter().filter(|d| d.managed).collect());
    stats.up = nodes.values().filter(|n| n.eff == "up").count();
    stats.down_root = nodes.values().filter(|n| n.eff == "down").count();
    stats.unreachable = nodes.values().filter(|n| n.eff == "unreachable").count();

    let mut impacted: HashMap<i64, usize> = HashMap::new();
    for n in nodes.values() {
        if n.eff == "unreachable" {
            if let Some(r) = n.root {
                *impacted.entry(r).or_insert(0) += 1;
            }
        }
    }

    let transitioned: HashSet<i64> = res
        .transitions
        .iter()
        .filter_map(|t| ids.get(&t.ip.to_string()).copied())
        .collect();

    let mut fresh_alerts: Vec<EventOut> = Vec::new();
    let mut n_flap_store: HashMap<i64, i64> = HashMap::new();

    for n in nodes.values() {
        if n.eff_prev != n.eff {
            db::open_segment(&tx, n.id, &n.eff, now)?;
        }
        let in_maint = n.maint_until.is_some_and(|until| until > now);

        let mut perf_status = "ok".to_string();
        let mut perf_ev: Option<(&'static str, &'static str, String)> = None;

        match n.eff.as_str() {
            "up" => {
                let cleared = db::clear_open_events_of_kind(
                    &tx, n.id, &["device_down", "site_outage", "perf_latency", "perf_loss"], now,
                )?;
                if cleared > 0 {
                    let ev = db::create_event(&tx, Some(n.id), Some(&n.ip), "device_up",
                        "info", "device responded again", None, now)?;
                    db::clear_event(&tx, ev.id, now)?;
                }
                let (st, ev) = classify_perf(&tx, n.id, loss_window, warn_ms, crit_ms, loss_warn_pct)?;
                perf_status = st;
                perf_ev = ev;
            }
            "down" => {
                let impacted_n = impacted.get(&n.id).copied().unwrap_or(0);
                let details = json!({ "impacted": impacted_n, "maintenance": in_maint }).to_string();
                match db::open_event_for(&tx, n.id, "device_down")? {
                    None => {
                        let sev = if in_maint { "info" } else { "critical" };
                        let msg = if impacted_n > 0 {
                            format!("{} {} down — {impacted_n} dependent device(s) unreachable", n.role, n.ip)
                        } else {
                            format!("{} {} down", n.role, n.ip)
                        };
                        let ev = db::create_event(&tx, Some(n.id), Some(&n.ip), "device_down",
                            sev, &msg, Some(&details), now)?;
                        if !in_maint {
                            crate::monitor::record_down_alert_line(
                                out_dir, &n.role, &n.ip, None,
                            );
                            fresh_alerts.push(EventOut { id: ev.id, ip: n.ip.clone(), sev: sev.into() });
                        }
                    }
                    Some(e) => db::update_event_details(&tx, e.id, &details, now)?,
                }
            }
            _ => {}
        }

        // ---- flapping (only recompute for devices that moved this sweep)
        if transitioned.contains(&n.id) {
            let count = n_flaps(&tx, n.id, now - flap_window_mins * 60)?;
            let open_flap = db::open_event_for(&tx, n.id, "flapping")?.is_some();
            if count >= flap_threshold && !open_flap && !in_maint {
                let ev = db::create_event(&tx, Some(n.id), Some(&n.ip), "flapping",
                    "warning",
                    &format!("state changed {count} times in {flap_window_mins} min"),
                    None, now)?;
                fresh_alerts.push(EventOut { id: ev.id, ip: n.ip.clone(), sev: "warning".into() });
            } else if count < flap_threshold.saturating_sub(1) && open_flap {
                db::clear_open_events_of_kind(&tx, n.id, &["flapping"], now)?;
            }
            n_flap_store.insert(n.id, count);
        }

        // ---- perf event lifecycle
        if let Some((kind, sev, msg)) = perf_ev {
            if db::open_event_for(&tx, n.id, kind)?.is_none() {
                let ev = db::create_event(&tx, Some(n.id), Some(&n.ip), kind,
                    sev, &msg, None, now)?;
                fresh_alerts.push(EventOut { id: ev.id, ip: n.ip.clone(), sev: sev.into() });
            }
        }

        let down_since: Option<i64> = if matches!(n.eff.as_str(), "down" | "unreachable") {
            Some(tx.query_row(
                "SELECT COALESCE(down_since_ts, ?1) FROM devices WHERE id = ?2",
                rusqlite::params![now, n.id], |r| r.get(0),
            ).unwrap_or(now))
        } else {
            None
        };
        let flap_val = n_flap_store.get(&n.id).copied().unwrap_or(n.flap);
        db::set_device_fields(&tx, n.id, &n.eff, &perf_status, down_since, flap_val)?;
        if perf_status != "ok" {
            stats.degraded += 1;
        }
    }

    // ---- queue outbound notifications (ServiceNow-ready JSON)
    let webhook_enabled = db::get_setting_or(&tx, "webhook_enabled", "0") == "1";
    for a in &fresh_alerts {
        if !(a.sev == "critical" || a.sev == "warning") || !webhook_enabled {
            continue;
        }
        if let Ok(Some(ev)) = db::event_by_id(&tx, a.id) {
            let (site, role) = db::device_by_ip(&tx, &a.ip).ok().flatten()
                .map(|d| (db::site_name(&tx, d.site_id), d.role))
                .unwrap_or_else(|| ("-".into(), "-".into()));
            let payload = json!({
                "type": "nms.event",
                "ts": chrono::Utc::now().to_rfc3339(),
                "event": {
                    "id": ev.id, "kind": ev.kind, "severity": ev.severity,
                    "message": ev.message, "details": ev.details, "created_ts": ev.created_ts,
                },
                "device": { "ip": a.ip, "role": role, "site": site },
            }).to_string();
            db::queue_outbound(&tx, a.id, &payload, now)?;
            stats.queued += 1;
        }
    }

    tx.commit()?;
    stats.new_events = fresh_alerts.len();
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    Ok(stats)
}

struct EventOut {
    id: i64,
    ip: String,
    sev: String,
}

/// One full monitoring cycle: sweep, persist, analyze, alert.
pub fn run_cycle(params: &check::Params, dbh: &Arc<Db>) -> Result<(check::RunResult, CycleStats)> {
    let res = check::sweep_once(params)?;
    let stats = process_result(dbh, &res, &params.out_dir)?;
    Ok((res, stats))
}
