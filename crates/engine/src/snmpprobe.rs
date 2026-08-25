//! SNMP identity probing (FR-PRF-003 v0 / FR-DISC-002 enrichment): fetch
//! sysName/sysDescr/sysUpTime from a device and derive vendor/OS hints.
//! Uses the `snmp` protocol crate (crates/collector-snmp).

use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;

const OID_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const OID_SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const OID_SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SnmpIdentity {
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    /// centiseconds since boot (sysUpTime)
    pub uptime_cs: Option<i64>,
}

fn value_to_text(v: &snmp::SnmpValue) -> Option<String> {
    match v {
        snmp::SnmpValue::Str(b) => String::from_utf8(b.clone())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        snmp::SnmpValue::Oid(o) => Some(o.clone()),
        _ => None,
    }
}

/// One GET for the system identity group, retried three times (many agents
/// drop a single lost datagram quietly, and Windows caches ICMP
/// unreachables per destination). Callers sweep many devices with small
/// timeouts. `addr` includes the port (standard SNMP = 161).
pub fn probe_identity(addr: SocketAddr, community: &str, timeout_ms: u64) -> Result<SnmpIdentity> {
    let t = timeout_ms.clamp(100, 3000);
    let mut last_err = None;
    for attempt in 0..3u8 {
        // Fresh ephemeral socket per attempt: Windows caches ICMP
        // port-unreachable state per destination and would otherwise fail
        // subsequent sends on a reused connection even once the agent lives.
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(25));
        }
        match snmp::get(
            addr,
            community,
            &[OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME],
            t,
            1000 + attempt as i32,
        ) {
            Ok(vbs) => {
                let mut id = SnmpIdentity::default();
                for (oid, val) in vbs {
                    match oid.as_str() {
                        OID_SYS_NAME => id.sys_name = value_to_text(&val),
                        OID_SYS_DESCR => id.sys_descr = value_to_text(&val),
                        OID_SYS_UPTIME => {
                            if let snmp::SnmpValue::Int(cs) = val {
                                id.uptime_cs = Some(cs);
                            }
                        }
                        _ => {}
                    }
                }
                return Ok(id);
            }
            Err(e) => {
                #[cfg(test)]
                eprintln!("[snmpprobe] attempt {attempt} to {addr} failed: {e}");
                last_err = Some(e)
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("snmp probe failed")))
}

/// Collect interface inventory using SNMP GETBULK when supported, with the
/// collector's GETNEXT fallback for older agents (FR-PRF-003,
/// FR-DISC-003). The explicit engine entry point keeps all deep-inspection
/// consumers on the capability-aware path.
pub fn walk_interfaces_bulk(
    addr: SocketAddr,
    community: &str,
    timeout_ms: u64,
    max_ifaces: usize,
) -> Result<Vec<snmp::IfaceEntry>> {
    snmp::walk_if_table_bulk(addr, community, timeout_ms, max_ifaces)
}

/// Map well-known sysDescr markers to (vendor, os) hints.
pub fn classify_os(descr: &str) -> Option<(&'static str, &'static str)> {
    let d = descr.to_lowercase();
    let rules: &[(&str, &str, &str)] = &[
        ("routeros", "MikroTik", "RouterOS"),
        ("cisco ios", "Cisco", "IOS"),
        ("ios-xe", "Cisco", "IOS-XE"),
        ("ios xr", "Cisco", "IOS-XR"),
        ("nx-os", "Cisco", "NX-OS"),
        ("aruba", "Aruba", "AOS-CX"),
        ("procurve", "HPE", "ProCurve"),
        ("fortigate", "Fortinet", "FortiOS"),
        ("pfsense", "Netgate", "pfSense"),
        ("opnsense", "OPNsense", "OPNsense"),
        ("unifi", "Ubiquiti", "UniFi"),
        ("edgeos", "Ubiquiti", "EdgeOS"),
        ("juniper", "Juniper", "Junos"),
        ("mikrotik", "MikroTik", "RouterOS"),
        ("linux", "Linux", "Linux"),
        ("microsoft windows", "Microsoft", "Windows"),
    ];
    rules
        .iter()
        .find(|(marker, _, _)| d.contains(marker))
        .map(|(_, vendor, os)| (*vendor, *os))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn classify_os_rules() {
        assert_eq!(
            classify_os("RouterOS 7.14 CCR2004"),
            Some(("MikroTik", "RouterOS"))
        );
        assert_eq!(
            classify_os("Cisco IOS Software, C2960"),
            Some(("Cisco", "IOS"))
        );
        assert_eq!(classify_os("some weird appliance"), None);
    }

    #[test]
    fn probe_identity_against_mock_agent() {
        use snmp::mock;
        let mut table = HashMap::new();
        table.insert(
            OID_SYS_DESCR.to_string(),
            snmp::SnmpValue::Str(b"RouterOS 7.14 test".to_vec()),
        );
        table.insert(OID_SYS_UPTIME.to_string(), snmp::SnmpValue::Int(4242));
        table.insert(
            OID_SYS_NAME.to_string(),
            snmp::SnmpValue::Str(b"core-sw".to_vec()),
        );
        let agent = mock::spawn("public", table).unwrap();

        let id = probe_identity(agent.addr, "public", 500).unwrap();
        assert_eq!(id.sys_name.as_deref(), Some("core-sw"));
        assert_eq!(id.sys_descr.as_deref(), Some("RouterOS 7.14 test"));
        assert_eq!(id.uptime_cs, Some(4242));
        assert_eq!(
            id.sys_descr.as_deref().and_then(classify_os),
            Some(("MikroTik", "RouterOS"))
        );
    }

    #[test]
    fn probe_fails_cleanly_without_agent() {
        // port 9 on loopback: nothing listening on UDP -> clean error path
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(probe_identity(addr, "public", 120).is_err());
    }

    #[test]
    fn bulk_interface_walk_is_equivalent_and_uses_fewer_packets() {
        use snmp::mock;
        let table = interface_fixture();
        let bulk_agent = mock::spawn("public", table.clone()).unwrap();
        let bulk = walk_interfaces_bulk(bulk_agent.addr, "public", 500, 64).unwrap();
        let bulk_packets = bulk_agent.request_counts();

        let next_agent = mock::spawn("public", table).unwrap();
        let next = snmp::walk_if_table(next_agent.addr, "public", 500, 64).unwrap();
        let next_packets = next_agent.request_counts();

        assert_eq!(bulk, next);
        assert!(bulk_packets.getbulk > 0);
        assert_eq!(bulk_packets.getnext, 0);
        let bulk_total = bulk_packets.get + bulk_packets.getnext + bulk_packets.getbulk;
        let next_total = next_packets.get + next_packets.getnext + next_packets.getbulk;
        assert!(
            bulk_total * 2 <= next_total,
            "bulk={bulk_total}, getnext={next_total}"
        );
    }

    #[test]
    fn bulk_interface_walk_falls_back_for_unsupported_agent() {
        use snmp::mock;
        let agent = mock::spawn_with_getbulk("public", interface_fixture(), false).unwrap();
        let actual = walk_interfaces_bulk(agent.addr, "public", 500, 64).unwrap();
        let packets = agent.request_counts();
        assert_eq!(actual.len(), 2);
        assert!(packets.getbulk > 0);
        assert!(packets.getnext > 0);
    }

    fn interface_fixture() -> HashMap<String, snmp::SnmpValue> {
        let mut table = HashMap::new();
        table.insert(
            "1.3.6.1.2.1.31.1.1.1.1.1".into(),
            snmp::SnmpValue::Str(b"eth0".to_vec()),
        );
        table.insert(
            "1.3.6.1.2.1.31.1.1.1.1.2".into(),
            snmp::SnmpValue::Str(b"eth1".to_vec()),
        );
        table.insert(
            "1.3.6.1.2.1.31.1.1.1.15.1".into(),
            snmp::SnmpValue::Int(1000),
        );
        table.insert(
            "1.3.6.1.2.1.31.1.1.1.15.2".into(),
            snmp::SnmpValue::Int(100),
        );
        table.insert("1.3.6.1.2.1.2.2.1.7.1".into(), snmp::SnmpValue::Int(1));
        table.insert("1.3.6.1.2.1.2.2.1.7.2".into(), snmp::SnmpValue::Int(1));
        table.insert("1.3.6.1.2.1.2.2.1.8.1".into(), snmp::SnmpValue::Int(1));
        table.insert("1.3.6.1.2.1.2.2.1.8.2".into(), snmp::SnmpValue::Int(2));
        table.insert(
            "1.3.6.1.2.1.2.2.1.6.1".into(),
            snmp::SnmpValue::Str(vec![0xaa, 0xbb, 0xcc, 0, 0, 1]),
        );
        table.insert(
            "1.3.6.1.2.1.2.2.1.6.2".into(),
            snmp::SnmpValue::Str(vec![0xaa, 0xbb, 0xcc, 0, 0, 2]),
        );
        table
    }
}
