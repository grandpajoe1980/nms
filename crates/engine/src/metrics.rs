//! Prometheus text-format exposition of platform gauges (FR-INTG-003).
//! Scrape `/metrics` with a viewer-role bearer token in hardened mode.

use rusqlite::Connection;

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0)
}

/// Render the full metrics page in Prometheus text format v0.0.4.
pub fn render(conn: &Connection) -> String {
    let mut out = String::new();
    let push = |out: &mut String, name: &str, help: &str, value: String| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        // values beginning with '{' carry labels: emit name{labels} value
        if value.starts_with('{') {
            out.push_str(&format!("{name}{value}\n"));
        } else {
            out.push_str(&format!("{name} {value}\n"));
        }
    };
    for state in ["up", "down", "unreachable", "unknown"] {
        let v = count(
            conn,
            &format!(
                "SELECT COUNT(*) FROM devices WHERE managed=1 AND eff_state='{state}'"
            ),
        );
        push(
            &mut out,
            &format!("nms_devices_{state}"),
            &format!("managed devices in effective state '{state}'"),
            v.to_string(),
        );
    }

    push(
        &mut out,
        "nms_devices_total",
        "all managed devices",
        count(conn, "SELECT COUNT(*) FROM devices WHERE managed=1").to_string(),
    );
    push(
        &mut out,
        "nms_devices_degraded",
        "devices with perf_status != ok",
        count(
            conn,
            "SELECT COUNT(*) FROM devices WHERE managed=1 AND perf_status!='ok'",
        )
        .to_string(),
    );
    push(
        &mut out,
        "nms_sites",
        "known sites",
        count(conn, "SELECT COUNT(*) FROM sites").to_string(),
    );
    push(
        &mut out,
        "nms_interfaces_total",
        "known interfaces",
        count(conn, "SELECT COUNT(*) FROM interfaces").to_string(),
    );
    push(
        &mut out,
        "nms_interfaces_oper_up",
        "interfaces with oper_status 'up'",
        count(conn, "SELECT COUNT(*) FROM interfaces WHERE oper_status='up'").to_string(),
    );

    out.push_str("# HELP nms_alarms_open open alarms by severity\n# TYPE nms_alarms_open gauge\n");
    for sev in ["critical", "warning", "info"] {
        let v = count(
            conn,
            &format!("SELECT COUNT(*) FROM events WHERE state='open' AND severity='{sev}'"),
        );
        out.push_str(&format!("nms_alarms_open{{severity=\"{sev}\"}} {v}\n"));
    }

    push(
        &mut out,
        "nms_alarms_unacked",
        "open unacknowledged critical/warning alarms",
        count(
            conn,
            "SELECT COUNT(*) FROM events WHERE state='open' AND acknowledged=0 \
             AND severity IN ('critical','warning')",
        )
        .to_string(),
    );
    push(
        &mut out,
        "nms_outbound_pending",
        "queued webhook deliveries",
        count(conn, "SELECT COUNT(*) FROM outbound WHERE status='pending'").to_string(),
    );
    push(
        &mut out,
        "nms_spool_pending_files",
        "spooled sweep files awaiting replay (collector-local counter)",
        "0".to_string(),
    );
    push(
        &mut out,
        "nms_build_info",
        "build metadata; value is always 1",
        format!("{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION")),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_expected_gauges_on_empty_store() {
        let db = crate::db::Db::open_memory().unwrap();
        let c = db.lock();
        let m = render(&c);
        assert!(m.contains("nms_devices_up 0"));
        assert!(m.contains("nms_devices_total 0"));
        assert!(m.contains("nms_sites 0"));
        assert!(m.contains("nms_interfaces_total 0"));
        assert!(m.contains("nms_interfaces_oper_up 0"));
        assert!(m.contains("nms_alarms_open{severity=\"critical\"} 0"));
        assert!(m.contains(&format!("nms_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"))));
        assert!(m.starts_with("# HELP nms_devices_up "));
    }
}
