//! Fixture-driven scenario tests for the fault/alarm pipeline (PRD §12,
//! AC-FLT-004 pattern): dependency root-cause suppression, incident dedupe,
//! recovery auto-clear, flap damping. These encode the "no alert storms"
//! contract that must survive every future refactor of ops.rs.

use engine::check::{Probe, RunResult};
use engine::db::Db;
use engine::model::{Device, Model, Role, State};
use engine::ops;
use std::sync::Arc;

fn dev(ip: &str, role: Role, state: State) -> Device {
    Device {
        ip: ip.parse().unwrap(),
        mac: None,
        role,
        state,
        subnet: Some("10.20.30.0/24".into()),
        rtt_ms: None,
        reply_ttl: None,
        hint: None,
        first_seen: chrono::Utc::now().to_rfc3339(),
        last_seen: chrono::Utc::now().to_rfc3339(),
        down_since: None,
        ever_up: true,
        wap: None,
        wap_source: None,
        hostname: None,
        device_class: None,
    }
}

/// Build a synthetic sweep result: every managed address probed, `down_ips`
/// reported as not-responding, everything else up at 5 ms.
fn run_for(model: &Model, down_ips: &[&str]) -> RunResult {
    let mut m = model.clone();
    let probes: Vec<Probe> = m
        .devices
        .iter()
        .map(|d| {
            let down = down_ips.contains(&&d.ip.to_string()[..]);
            Probe {
                ip: d.ip,
                up: !down,
                rtt_ms: if down { None } else { Some(5.0) },
            }
        })
        .collect();
    for d in &mut m.devices {
        let down = down_ips.contains(&&d.ip.to_string()[..]);
        d.state = if down { State::Down } else { State::Up };
    }
    RunResult { model: m, transitions: Vec::new(), probes, unprobed: 0 }
}

fn setup() -> (Arc<Db>, Model, tempfile::TempDir) {
    let dbh = Arc::new(Db::open_memory().unwrap());
    let mut model = Model::new();
    model.backend = "test".into();
    model.devices.push(dev("10.20.30.1", Role::Router, State::Up));
    model.devices.push(dev("10.20.30.50", Role::Endpoint, State::Up));
    model.devices.push(dev("10.20.30.51", Role::Endpoint, State::Up));
    model.devices.push(dev("10.20.30.52", Role::Endpoint, State::Up));
    let dir = tempfile::TempDir::new().unwrap();
    (dbh, model, dir)
}

fn open_criticals(dbh: &Arc<Db>) -> Vec<(String, String)> {
    // (kind, message) of open critical events
    dbh.lock()
        .prepare("SELECT kind, message FROM events WHERE state='open' AND severity='critical'")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .flatten()
        .collect()
}

#[test]
fn ac_flt_004_router_failure_yields_one_incident_with_impacted_children() {
    let (dbh, model, dir) = setup();

    // Cycle 1: healthy baseline
    let r1 = run_for(&model, &[]);
    let s1 = ops::process_result(&dbh, &r1, dir.path()).unwrap();
    assert_eq!(s1.down_root, 0);
    assert_eq!(s1.unreachable, 0);
    assert!(open_criticals(&dbh).is_empty(), "healthy baseline must raise nothing");

    // Cycle 2: router dies; children also miss their pings
    let r2 = run_for(&model, &["10.20.30.1", "10.20.30.50", "10.20.30.51", "10.20.30.52"]);
    let s2 = ops::process_result(&dbh, &r2, dir.path()).unwrap();
    assert_eq!(s2.down_root, 1, "only the router counts as a root outage");
    assert_eq!(s2.unreachable, 3, "children suppressed as unreachable");

    let crit = open_criticals(&dbh);
    assert_eq!(crit.len(), 1, "exactly one critical incident, never one per child");
    assert_eq!(crit[0].0, "device_down");
    assert!(crit[0].1.contains("3 dependent"), "impacted roll-up present: {}", crit[0].1);

    // Children stored as unreachable, not independently down
    let conn = dbh.lock();
    for ip in ["10.20.30.50", "10.20.30.51", "10.20.30.52"] {
        let eff: String = conn
            .query_row("SELECT eff_state FROM devices WHERE ip=?1", [ip], |r| r.get(0))
            .unwrap();
        assert_eq!(eff, "unreachable", "{ip}");
    }
    drop(conn);

    // Cycle 3: everything recovers -> incident auto-closes, no criticals remain
    let r3 = run_for(&model, &[]);
    let s3 = ops::process_result(&dbh, &r3, dir.path()).unwrap();
    assert_eq!(s3.down_root, 0);
    assert_eq!(s3.unreachable, 0);
    assert!(
        open_criticals(&dbh).is_empty(),
        "recovery must auto-clear the router incident"
    );
}

#[test]
fn flap_damping_raises_one_warning_then_stays_quiet() {
    let (dbh, model, dir) = setup();
    let target = "10.20.30.50";

    // Baseline up
    ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();

    // Flap the endpoint 8 times (well past default flap_threshold=5)
    for i in 0..16 {
        let down = i % 2 == 0;
        let ips: &[&str] = if down { &[target] } else { &[] };
        ops::process_result(&dbh, &run_for(&model, ips), dir.path()).unwrap();
    }

    let flap_warnings: i64 = dbh
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind='flapping' AND severity='warning' AND device_id =
                 (SELECT id FROM devices WHERE ip=?1)",
            [target],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        (1..=2).contains(&flap_warnings),
        "flapping must be flagged once (damped), got {flap_warnings}"
    );

    // Stability clears it: several quiet cycles later the flap event closes
    for _ in 0..8 {
        ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();
    }
    let open_flaps: i64 = dbh
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind='flapping' AND state='open'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(open_flaps, 0, "stable device must clear its flapping flag");
}
