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

/// Site power blip: every device drops together and recovers next cycle,
/// five times in a row. Storm-suppression contract (AC-FLT-004 pattern):
/// one critical per outage episode for the root cause, zero per-endpoint
/// criticals while children are merely unreachable, clean board afterwards.
#[test]
fn site_power_blip_yields_one_root_critical_per_episode_and_zero_endpoint_storm() {
    let (dbh, model, dir) = setup();
    let router = "10.20.30.1";
    let endpoints = ["10.20.30.50", "10.20.30.51", "10.20.30.52"];
    let site_blackout: &[&str] =
        &[router, endpoints[0], endpoints[1], endpoints[2]];

    // Baseline: healthy site raises nothing.
    let base = ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();
    assert_eq!(base.down_root, 0);
    assert!(open_criticals(&dbh).is_empty(), "healthy baseline must raise nothing");

    // Five down/up pairs simulating power blips at the site PDU.
    for i in 0..5 {
        let out = ops::process_result(&dbh, &run_for(&model, site_blackout), dir.path())
            .unwrap();
        assert_eq!(out.down_root, 1, "blip {i}: only the router is a root outage");
        assert_eq!(out.unreachable, 3, "blip {i}: children suppressed as unreachable");

        let back = ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();
        assert_eq!(back.down_root, 0, "blip {i}: recovery cycle");
        assert_eq!(back.unreachable, 0, "blip {i}: recovery cycle");
    }

    // Final stable up cycle.
    ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();

    // (a) Deduped router criticals: exactly one per outage episode, never
    // re-created on every cycle of an ongoing outage.
    let router_criticals: i64 = dbh
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind='device_down' AND severity='critical'
                 AND device_id = (SELECT id FROM devices WHERE ip=?1)",
            [router],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        (5..=6).contains(&router_criticals),
        "expected ~one device_down critical per episode, got {router_criticals} \
         (>6 means re-alerting while down; <5 means missing episodes)"
    );

    // (b) Zero per-endpoint criticals ever: suppressed as unreachable.
    let endpoint_criticals: i64 = dbh
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE severity='critical'
                 AND device_id IN (?1, ?2, ?3)",
            [endpoints[0], endpoints[1], endpoints[2]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        endpoint_criticals, 0,
        "unreachable endpoints must never raise critical events"
    );

    // (c) After the final stable cycle, no open criticals remain.
    assert!(
        open_criticals(&dbh).is_empty(),
        "stable site must auto-clear every critical"
    );
}

#[test]
fn flap_damping_tracks_churn_without_noncanonical_events() {
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

    let noncanonical: i64 = dbh
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind IN ('site_outage', 'perf_latency', 'perf_loss', 'flapping') AND device_id =
                 (SELECT id FROM devices WHERE ip=?1)",
            [target],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(noncanonical, 0, "noncanonical event kinds must never be emitted");

    let flap_count: i64 = dbh
        .lock()
        .query_row("SELECT flap_count FROM devices WHERE ip=?1", [target], |r| r.get(0))
        .unwrap();
    assert!(flap_count >= 5, "flap damping must still track transition count");
    let alert_lines = std::fs::read_to_string(dir.path().join("alerts.log"))
        .unwrap_or_default()
        .lines()
        .count();
    assert_eq!(alert_lines, 4, "flap damping must suppress repeated down pages");

    // Stability clears the damping state after several quiet cycles.
    for _ in 0..8 {
        ops::process_result(&dbh, &run_for(&model, &[]), dir.path()).unwrap();
    }
    let stable_cycles: i64 = dbh
        .lock()
        .query_row(
            "SELECT stable_cycles FROM devices WHERE ip=?1",
            [target],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stable_cycles >= 5, "stable device must leave damping state");
}
