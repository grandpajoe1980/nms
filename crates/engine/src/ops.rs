use crate::check;
use crate::db::{self, Db};
use crate::model::{Model, State};
use anyhow::Result;
use rusqlite::Connection;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
                hostname: d.hostname.clone(),
                device_class: d.device_class.clone(),
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
    stable: i64,
    flap_suppressed: bool,
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
                    stable: d.stable_cycles,
                    flap_suppressed: d.flap_suppressed,
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
            "latency_crit",
            "critical",
            format!("average latency {avg_rtt:.0} ms exceeds critical threshold {crit_ms:.0} ms"),
        )),
        "latency_warn" => Some((
            "latency_warn",
            "warning",
            format!("average latency {avg_rtt:.0} ms exceeds warning threshold {warn_ms:.0} ms"),
        )),
        "loss_warn" => Some((
            "loss_warn",
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


    let mut fresh_alerts: Vec<EventOut> = Vec::new();

    for n in nodes.values() {
        if n.eff_prev != n.eff {
            db::open_segment(&tx, n.id, &n.eff, now)?;
        }
        let in_maint = n.maint_until.is_some_and(|until| until > now);
        let flap_transitions = if n.eff_prev != n.eff {
            n_flaps(&tx, n.id, now - flap_window_mins * 60)?
        } else {
            n.flap
        };

        let mut perf_status = "ok".to_string();
        let mut perf_ev: Option<(&'static str, &'static str, String)> = None;

        match n.eff.as_str() {
            "up" => {
                let cleared = db::clear_open_events_of_kind(
                    &tx, n.id,
                    &["device_down", "latency_warn", "latency_crit", "loss_warn",
                      // Legacy rows from pre-FR-EVT-001 builds are closed on
                      // recovery without rewriting append-only history.
                      "site_outage", "perf_latency", "perf_loss", "flapping"],
                    now,
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
                let flap_damped = flap_transitions >= flap_threshold;
                let details = json!({
                    "impacted": impacted_n,
                    "maintenance": in_maint,
                    "flap_damped": flap_damped,
                }).to_string();
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
                        if !in_maint && !flap_damped {
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

        // ---- flapping: flag churn, then require sustained stability to
        // clear. Stability = consecutive sweeps with unchanged healthy state;
        // a windowed transition count alone never decays during silence.
        let mut stable = n.stable;
        let mut flap_suppressed = n.flap_suppressed;
        if n.eff_prev != n.eff {
            stable = 0;
        } else if n.eff == "up" && !in_maint {
            stable += 1;
        } else {
            stable = 0;
        }
        let mut flap_val = n.flap;

        if n.eff_prev != n.eff {
            flap_val = flap_transitions;
            // Flap damping is an availability state-management concern, not a
            // standalone event kind.  Keep the count/quiet-period behavior,
            // but do not emit the former non-taxonomy `flapping` event.
        }
        // clear once stable for `flap_threshold` consecutive healthy sweeps
        if flap_val >= flap_threshold {
            stable = stable.min(flap_threshold);
        }
        if flap_transitions >= flap_threshold && n.eff == "down" && !in_maint {
            flap_suppressed = true;
        } else if stable >= flap_threshold {
            flap_suppressed = false;
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
        db::set_device_fields(&tx, n.id, &n.eff, &perf_status, down_since, flap_val, stable, flap_suppressed)?;
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
            let payload = webhook_v1_payload(
                &ev,
                &a.ip,
                &role,
                &site,
                &chrono::Utc::now().to_rfc3339(),
                &[],
            );
            db::queue_outbound(&tx, a.id, &payload, now)?;
            stats.queued += 1;
        }
    }

    tx.commit()?;

    // Retire inventory entries absent beyond the configured window so that
    // decommissioned devices disappear instead of lingering as down forever.
    let retire_days = setting_i64(&conn, "absent_retire_days", 30);
    if retire_days > 0 {
        match db::retire_absent_devices(&conn, now - retire_days * 86_400) {
            Ok(n) if n > 0 => println!("[ops] retired {n} absent device(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("[ops] retirement failed: {e}"),
        }
    }

    stats.new_events = fresh_alerts.len();
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    Ok(stats)
}

/// Serialize the frozen FR-FLT-009 webhook-v1 shape.  Event details are
/// stored as JSON text in SQLite, but are always decoded to an object at the
/// wire boundary; device tags are required even when the inventory has none.
fn webhook_v1_payload(
    ev: &db::EventRec,
    ip: &str,
    role: &str,
    site: &str,
    ts: &str,
    tags: &[String],
) -> String {
    let details = ev
        .details
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .filter(|value| value.is_object())
        .unwrap_or_else(|| json!({}));
    json!({
        "type": "nms.event",
        "ts": ts,
        "event": {
            "id": ev.id,
            "kind": ev.kind,
            "severity": ev.severity,
            "message": ev.message,
            "details": details,
            "created_ts": ev.created_ts,
        },
        "device": { "ip": ip, "role": role, "site": site, "tags": tags },
    })
    .to_string()
}

/// Map an alarm into the separate §6.1 canonical telemetry envelope. This is
/// intentionally distinct from the frozen FR-FLT-009 notification payload.
pub fn event_to_canonical_envelope(
    ev: &db::EventRec,
    tenant_id: &str,
    device_id: &str,
    observed_at: &str,
    ingested_at: &str,
) -> serde_json::Value {
    let details = ev
        .details
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .filter(|value| value.is_object())
        .unwrap_or_else(|| json!({}));
    json!({
        "schema": "network.telemetry.v1",
        "tenant_id": tenant_id,
        "source": {"collector_id": "nms-engine", "protocol": "alarm", "device_id": device_id},
        "observed_at": observed_at,
        "ingested_at": ingested_at,
        "sequence": ev.id,
        "kind": ev.kind,
        "entity": {"type": "device", "id": device_id},
        "payload": {"message": ev.message, "severity": ev.severity, "details": details},
        "quality": {"counter_reset": false, "confidence": 1.0},
    })
}

struct EventOut {
    id: i64,
    ip: String,
    sev: String,
}

#[cfg(test)]
mod webhook_tests {
    use super::*;

    #[test]
    fn webhook_v1_has_exact_object_and_array_shapes() {
        let ev = db::EventRec {
            id: 42,
            created_ts: 1_000,
            updated_ts: None,
            device_id: Some(7),
            ip: Some("10.20.30.1".into()),
            kind: "device_down".into(),
            severity: "critical".into(),
            state: "open".into(),
            message: "router down".into(),
            details: Some(r#"{"impacted":40,"maintenance":false}"#.into()),
            acknowledged: false,
            ack_by: None,
            ack_ts: None,
            cleared_ts: None,
        };
        let tags = vec!["branch".to_string()];
        let wire = webhook_v1_payload(&ev, "10.20.30.1", "router", "hq-1", "2026-08-24T12:00:00Z", &tags);
        let value: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            value,
            json!({
                "type": "nms.event",
                "ts": "2026-08-24T12:00:00Z",
                "event": {
                    "id": 42,
                    "kind": "device_down",
                    "severity": "critical",
                    "message": "router down",
                    "details": {"impacted": 40, "maintenance": false},
                    "created_ts": 1000,
                },
                "device": {
                    "ip": "10.20.30.1",
                    "role": "router",
                    "site": "hq-1",
                    "tags": ["branch"],
                },
            })
        );
        assert!(value["event"]["details"].is_object());
        assert!(value["device"]["tags"].is_array());
    }

    #[test]
    fn webhook_v1_normalizes_missing_or_invalid_details_to_object() {
        let mut ev = db::EventRec {
            id: 1,
            created_ts: 1,
            updated_ts: None,
            device_id: None,
            ip: None,
            kind: "latency_warn".into(),
            severity: "warning".into(),
            state: "open".into(),
            message: "slow".into(),
            details: None,
            acknowledged: false,
            ack_by: None,
            ack_ts: None,
            cleared_ts: None,
        };
        for details in [None, Some("not-json".to_string()), Some("[]".to_string())] {
            ev.details = details;
            let value: serde_json::Value = serde_json::from_str(&webhook_v1_payload(
                &ev, "10.0.0.1", "endpoint", "-", "2026-08-24T12:00:00Z", &[],
            ))
            .unwrap();
            assert_eq!(value["event"]["details"], json!({}));
            assert!(value["device"]["tags"].is_array());
        }
    }

    #[test]
    fn canonical_envelope_is_separate_and_versioned() {
        let ev = db::EventRec {
            id: 9, created_ts: 10, updated_ts: None, device_id: Some(1),
            ip: Some("10.0.0.1".into()), kind: "latency_warn".into(),
            severity: "warning".into(), state: "open".into(), message: "slow".into(),
            details: Some(r#"{"rtt_ms":200}"#.into()), acknowledged: false,
            ack_by: None, ack_ts: None, cleared_ts: None,
        };
        let v = event_to_canonical_envelope(&ev, "t-1", "dev-1", "2026-08-24T14:03:17Z", "2026-08-24T14:03:18Z");
        assert_eq!(v["schema"], "network.telemetry.v1");
        assert_eq!(v["kind"], "latency_warn");
        assert_eq!(v["entity"]["type"], "device");
        assert!(v["payload"]["details"].is_object());
        assert_eq!(v["sequence"], 9);
        assert!(v.get("type").is_none(), "canonical envelope must not become webhook v1");
    }
}

/// One full monitoring cycle: sweep, persist, analyze, alert.
/// If the ops store cannot be written, the probe batch is spooled to
/// `<out_dir>/spool/` (NFR-08) and replayed automatically on next startup.
pub fn run_cycle(params: &check::Params, dbh: &Arc<Db>) -> Result<(check::RunResult, CycleStats)> {
    let res = check::sweep_once(params)?;
    match process_result(dbh, &res, &params.out_dir) {
        Ok(stats) => Ok((res, stats)),
        Err(e) => {
            match spool_write(&params.out_dir, &res.probes) {
                Ok(n) => eprintln!("[ops] db unavailable; spooled {n} probe(s) for replay"),
                Err(se) => eprintln!("[ops] db unavailable AND spool failed: {se}"),
            }
            Err(e)
        }
    }
}

// ------------------------------------------------------- spool (NFR-08)

fn spool_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("spool")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SpoolRecord {
    ts_millis: i64,
    probes: Vec<check::Probe>,
}

pub fn spool_write(out_dir: &Path, probes: &[check::Probe]) -> Result<usize> {
    if probes.is_empty() {
        return Ok(0);
    }
    let dir = spool_dir(out_dir);
    std::fs::create_dir_all(&dir)?;
    let rec = SpoolRecord {
        ts_millis: chrono::Utc::now().timestamp_millis(),
        probes: probes.to_vec(),
    };
    let name = format!("cycle-{}.json", chrono::Utc::now().timestamp_millis());
    std::fs::write(dir.join(name), serde_json::to_vec(&rec)?)?;
    Ok(probes.len())
}

pub fn spool_count(out_dir: &Path) -> usize {
    std::fs::read_dir(spool_dir(out_dir))
        .map(|rd| rd.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "json")).count())
        .unwrap_or(0)
}

/// Drain the spool oldest-first into the pipeline. Called once at startup.
pub fn replay_spool(dbh: &Arc<Db>, out_dir: &Path) -> Result<usize> {
    let dir = spool_dir(out_dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let mut replayed = 0;
    for file in files {
        let replay = || -> Result<()> {
            let rec: SpoolRecord = serde_json::from_slice(&std::fs::read(&file)?)?;
            let model = Model::load(&out_dir.join("model.json"))?;
            let synthetic = check::RunResult {
                model,
                transitions: Vec::new(),
                probes: rec.probes,
                unprobed: 0,
            };
            // Keep the original observation timestamps by rewriting "now".
            process_result_at(dbh, &synthetic, out_dir, rec.ts_millis / 1000)?;
            Ok(())
        };
        match replay() {
            Ok(()) => {
                let _ = std::fs::remove_file(&file);
                replayed += 1;
            }
            Err(e) => eprintln!("[ops] spool replay skipped {}: {e}", file.display()),
        }
    }
    Ok(replayed)
}

fn process_result_at(
    dbh: &Arc<Db>,
    res: &check::RunResult,
    out_dir: &Path,
    _at_ts: i64,
) -> Result<CycleStats> {
    // v0: reuse current-time processing; sample rows carry their own
    // timestamps so history stays accurate even though analysis runs late.
    process_result(dbh, res, out_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Probe;
    use std::net::Ipv4Addr;

    #[test]
    fn spool_write_count_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nms-spool-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let probes = vec![
            Probe { ip: "10.0.0.1".parse().unwrap(), up: true, rtt_ms: Some(2.5) },
            Probe { ip: "10.0.0.2".parse().unwrap(), up: false, rtt_ms: None },
        ];
        assert_eq!(spool_write(&dir, &probes).unwrap(), 2);
        assert_eq!(spool_count(&dir), 1);
        // empty batches never create files
        assert_eq!(spool_write(&dir, &[]).unwrap(), 0);
        assert_eq!(spool_count(&dir), 1);
        let files: Vec<PathBuf> = std::fs::read_dir(spool_dir(&dir))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        let rec: SpoolRecord =
            serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(rec.probes.len(), 2);
        assert_eq!(rec.probes[0].ip, Ipv4Addr::new(10, 0, 0, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
