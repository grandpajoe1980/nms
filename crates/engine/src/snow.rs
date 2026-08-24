//! ServiceNow incident payload transform (FR-INTG-001a v0).
//!
//! Consumes the FROZEN webhook-v1 event JSON (PRD §4.3 FLT-009) and produces
//! ServiceNow Table API incident bodies. Transform only: HTTP delivery reuses
//! the outbound worker (`jobs::send_webhook`). Missing/odd fields degrade to
//! defaults — this layer never panics on malformed events.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

/// ServiceNow incident `state` value for Closed (Complete).
pub const STATE_CLOSED: &str = "7";

/// Build a ServiceNow Table API incident body from a webhook-v1 event.
///
/// Mapping: severity `critical` → impact "1"/urgency "1", everything else
/// → impact "2"/urgency "2" (PRD §10 severity model). The real CMDB CI lookup
/// by IP is deferred; the device IP rides in the placeholder field
/// `u_device_ip` for a ServiceNow-side business rule / future lookup.
pub fn to_incident_payload(event: &Value) -> Result<Value> {
    let ev = obj(event, "event");
    let dev = obj(event, "device");

    let id = str_field(ev, "id", "unknown");
    let kind = str_field(ev, "kind", "unknown");
    let severity = str_field(ev, "severity", "info").to_lowercase();
    let message = str_field(ev, "message", "(no message)");
    let site = str_field(dev, "site", "-");
    let ip = str_field(dev, "ip", "-");
    let ts = str_field(event, "ts", "");

    let critical = severity == "critical";
    let impact = if critical { "1" } else { "2" };
    let urgency = if critical { "1" } else { "2" };

    let mut description = format!(
        "severity: {}\nkind: {}\nsite: {}\nip: {}\n\n{}",
        severity, kind, site, ip, message
    );
    if let Some(details) = ev.get("details") {
        match serde_json::to_string_pretty(details) {
            Ok(pretty) => description.push_str(&format!("\n\ndetails:\n{pretty}")),
            Err(e) => description.push_str(&format!("\n\ndetails: <unrenderable: {e}>")),
        }
    }

    Ok(json!({
        "short_description": truncate(
            &format!("[{}] {} @ {} ({}) - {}", severity.to_uppercase(), kind, site, ip, message),
            160,
        ),
        "description": description,
        "impact": impact,
        "urgency": urgency,
        "u_device_ip": ip,
        "work_notes": format!("{} nms event from site {}", ts, site),
        "correlation_id": format!("nms-{id}"),
    }))
}

/// Build a ServiceNow close/update patch for recovery-style events.
///
/// v0 maps closures only: `device_up` and any `*_cleared` kind (PRD §10,
/// FLT-005 auto-resolve on recovery) produce `{state: "7", close_notes}`;
/// anything else is rejected — open/update mapping lands with FR-INTG-001a v1.
pub fn resolve_patch(event: &Value) -> Result<Value> {
    let kind = str_field(obj(event, "event"), "kind", "");
    if !is_recovery_kind(&kind) {
        return Err(anyhow!(
            "snow resolve_patch: only closure events map to a state patch \
             (device_up / *_cleared); got kind '{kind}'"
        ));
    }
    let site = str_field(obj(event, "device"), "site", "-");
    let ts = str_field(event, "ts", "");
    Ok(json!({
        "state": STATE_CLOSED,
        "close_notes": format!("Auto-resolved by nms at {ts} (site {site})"),
    }))
}

fn is_recovery_kind(kind: &str) -> bool {
    kind == "device_up" || kind.ends_with("_cleared")
}

fn obj<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key)
        .filter(|val| val.is_object())
        .unwrap_or(&Value::Null)
}

fn str_field(v: &Value, key: &str, default: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => default.to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_event(severity: &str) -> Value {
        json!({
            "type": "nms.event",
            "ts": "2026-08-24T12:00:00Z",
            "event": {
                "id": 42,
                "kind": "device_down",
                "severity": severity,
                "message": "ICMP down after 3 confirm probes",
                "details": {"confirm_probes": 3, "last_rtt_ms": null},
                "created_ts": 1771900000i64,
            },
            "device": {"ip": "10.20.30.40", "role": "router", "site": "hq-1"},
        })
    }

    #[test]
    fn full_payload_severity_matrix() {
        for (sev, want_impact, want_urgency) in [
            ("critical", "1", "1"),
            ("major", "2", "2"),
            ("warning", "2", "2"),
            ("info", "2", "2"),
            ("bogus", "2", "2"),
        ] {
            let p = to_incident_payload(&full_event(sev)).expect("payload");
            assert_eq!(p["impact"], want_impact, "impact for {sev}");
            assert_eq!(p["urgency"], want_urgency, "urgency for {sev}");
            assert_eq!(p["correlation_id"], json!("nms-42"));
            assert_eq!(p["u_device_ip"], json!("10.20.30.40"));
        }
    }

    #[test]
    fn full_payload_description_and_notes() {
        let p = to_incident_payload(&full_event("major")).expect("payload");
        let desc = p["description"].as_str().unwrap();
        assert!(desc.contains("severity: major"));
        assert!(desc.contains("kind: device_down"));
        assert!(desc.contains("site: hq-1"));
        assert!(desc.contains("ip: 10.20.30.40"));
        assert!(desc.contains("ICMP down after 3 confirm probes"));
        assert!(desc.contains("\"confirm_probes\": 3"));
        let notes = p["work_notes"].as_str().unwrap();
        assert!(notes.contains("2026-08-24T12:00:00Z"));
        assert!(notes.contains("hq-1"));
        let short = p["short_description"].as_str().unwrap();
        assert!(short.starts_with("[MAJOR] device_down @ hq-1"));
    }

    #[test]
    fn minimal_payload_degrades() {
        let p = to_incident_payload(&json!({})).expect("degrades");
        assert_eq!(p["impact"], json!("2"));
        assert_eq!(p["urgency"], json!("2"));
        assert_eq!(p["correlation_id"], json!("nms-unknown"));
        assert_eq!(p["u_device_ip"], json!("-"));
        assert!(!p["short_description"].as_str().unwrap().is_empty());
    }

    #[test]
    fn odd_types_do_not_panic() {
        let p = to_incident_payload(&json!([1, 2, 3])).expect("array input degrades");
        assert_eq!(p["impact"], json!("2"));
        let p = to_incident_payload(&json!({"event": {"id": "evt-7", "severity": "CRITICAL"}}))
            .expect("string id + uppercase severity");
        assert_eq!(p["correlation_id"], json!("nms-evt-7"));
        assert_eq!(p["impact"], json!("1"));
        assert_eq!(p["urgency"], json!("1"));
    }

    #[test]
    fn resolve_on_recovery_kinds() {
        assert!(
            resolve_patch(&full_event("info")).is_err(),
            "device_down fixture must not map to a closure"
        );
        let up = json!({"type": "nms.event", "ts": "2026-08-24T13:00:00Z",
            "event": {"id": 42, "kind": "device_up"},
            "device": {"ip": "10.20.30.40", "role": "router", "site": "hq-1"}});
        let p = resolve_patch(&up).expect("device_up resolves");
        assert_eq!(p["state"], json!(STATE_CLOSED));
        assert!(p["close_notes"].as_str().unwrap().contains("Auto-resolved"));

        let cleared = json!({"event": {"kind": "unreachable_cleared"}, "device": {}, "ts": "t"});
        assert!(resolve_patch(&cleared).is_ok());
    }

    #[test]
    fn reject_non_recovery_kinds() {
        for kind in ["device_down", "latency_warn", "config_changed", ""] {
            let ev = json!({"event": {"kind": kind}, "device": {}, "ts": "t"});
            assert!(resolve_patch(&ev).is_err(), "kind '{kind}' must not map");
        }
    }
}
