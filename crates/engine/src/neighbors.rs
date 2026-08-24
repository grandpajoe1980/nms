//! SNMP neighbor collection (FR-DISC-004): LLDP-MIB remote-table walks plus
//! legacy Cisco CDP cache walks, joined per neighbor-table instance and mapped
//! onto [`crate::db::NeighborRow`] for persistence via
//! [`crate::db::replace_neighbors`].
//!
//! Pragmatic MIB arcs (see PRD FR-DISC-004 / FR-TOP-002 edge feed): each
//! column subtree is walked independently and rows are joined on the shared
//! SNMP instance suffix, which encodes the local ifIndex plus a neighbor
//! index. Per-column walk failures (timeout, noSuchName, unsupported MIB) are
//! non-fatal by design: a device answering neither LLDP nor CDP yields an
//! empty vector, never an error.
//!
//! Provenance note: the port id columns describe the *remote-advertised*
//! interface identifier; until local ifIndex→ifName resolution lands they are
//! surfaced in `local_if_name` as the best available interface hint.

use crate::db::NeighborRow;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

/// lldpRemPortId column root.
pub const LLDP_PORT_ID: &str = "1.0.8802.1.1.2.1.4.1.1.5";
/// lldpRemSysName column root.
pub const LLDP_SYS_NAME: &str = "1.0.8802.1.1.2.1.4.1.1.7";
/// lldpRemSysDesc column root.
pub const LLDP_SYS_DESC: &str = "1.0.8802.1.1.2.1.4.1.1.8";
/// lldpRemManAddr column root.
pub const LLDP_MAN_ADDR: &str = "1.0.8802.1.1.2.1.4.1.1.10";

/// cdpCacheDeviceId column root.
pub const CDP_DEVICE_ID: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.6";
/// cdpCacheAddress column root.
pub const CDP_ADDRESS: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.7";
/// cdpCachePlatform column root.
pub const CDP_PLATFORM: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.8";
/// cdpCacheDevicePort column root.
pub const CDP_DEVICE_PORT: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.17";

/// Safety cap per column walk; neighbor tables are small but agents lie.
const MAX_ROWS_PER_COLUMN: usize = 512;

type ColumnMap = BTreeMap<String, snmp::SnmpValue>;

/// Collect every LLDP + CDP neighbor observation visible on `addr`.
///
/// Walk failures are absorbed per protocol/column; the result concatenates
/// whatever decoded cleanly (LLDP rows first, then CDP). Rows carrying no
/// usable identifier (no IP and no sysname) are dropped here so callers can
/// hand the output straight to `db::replace_neighbors`.
pub fn collect(
    addr: SocketAddr,
    community: &str,
    timeout_ms: u64,
) -> Result<Vec<NeighborRow>> {
    let mut out = lldp_neighbors(addr, community, timeout_ms);
    out.extend(cdp_neighbors(addr, community, timeout_ms));
    Ok(out.into_iter().filter(identifiable).collect())
}

/// True when a row carries at least one correlatable identifier — mirrors the
/// skip rule inside `db::replace_neighbors`.
fn identifiable(r: &NeighborRow) -> bool {
    r.neighbor_ip.is_some() || r.neighbor_sysname.is_some() || r.neighbor_mac.is_some()
}

fn lldp_neighbors(addr: SocketAddr, community: &str, timeout_ms: u64) -> Vec<NeighborRow> {
    let ports = walk_column(addr, community, LLDP_PORT_ID, timeout_ms);
    let names = walk_column(addr, community, LLDP_SYS_NAME, timeout_ms);
    let descs = walk_column(addr, community, LLDP_SYS_DESC, timeout_ms);
    let addrs = walk_column(addr, community, LLDP_MAN_ADDR, timeout_ms);
    union_keys([&ports, &names, &descs, &addrs])
        .into_iter()
        .map(|inst| NeighborRow {
            local_if_name: ports.get(&inst).and_then(port_text),
            neighbor_ip: addrs.get(&inst).and_then(decode_lldp_man_addr),
            neighbor_mac: None,
            neighbor_sysname: names.get(&inst).and_then(text_value),
            neighbor_platform: descs.get(&inst).and_then(text_value),
            protocol: "lldp".to_string(),
        })
        .collect()
}

fn cdp_neighbors(addr: SocketAddr, community: &str, timeout_ms: u64) -> Vec<NeighborRow> {
    let ids = walk_column(addr, community, CDP_DEVICE_ID, timeout_ms);
    let addrs = walk_column(addr, community, CDP_ADDRESS, timeout_ms);
    let platforms = walk_column(addr, community, CDP_PLATFORM, timeout_ms);
    let ports = walk_column(addr, community, CDP_DEVICE_PORT, timeout_ms);
    union_keys([&ids, &addrs, &platforms, &ports])
        .into_iter()
        .map(|inst| NeighborRow {
            local_if_name: ports.get(&inst).and_then(port_text),
            neighbor_ip: addrs.get(&inst).and_then(decode_cdp_addr),
            neighbor_mac: None,
            neighbor_sysname: ids.get(&inst).and_then(text_value),
            neighbor_platform: platforms.get(&inst).and_then(text_value),
            protocol: "cdp".to_string(),
        })
        .collect()
}

/// Walk one column subtree into `instance-suffix -> value`, swallowing any
/// transport/agent error (an unreachable or non-speaking device contributes
/// nothing rather than failing the whole collection).
fn walk_column(addr: SocketAddr, community: &str, root: &str, timeout_ms: u64) -> ColumnMap {
    match snmp::walk(addr, community, root, timeout_ms, MAX_ROWS_PER_COLUMN) {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|(oid, val)| {
                let rest = oid.strip_prefix(root)?;
                let suffix = rest.strip_prefix('.')?;
                Some((suffix.to_string(), val))
            })
            .collect(),
        Err(_) => BTreeMap::new(),
    }
}

/// Deterministic row order: sorted shared instance prefixes across all four
/// column maps of one protocol.
fn union_keys(maps: [&ColumnMap; 4]) -> Vec<String> {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for m in maps {
        keys.extend(m.keys().cloned());
    }
    keys.into_iter().collect()
}

/// Printable text from an octet-string varbind (names, descriptions).
fn text_value(v: &snmp::SnmpValue) -> Option<String> {
    match v {
        snmp::SnmpValue::Str(b) => std::str::from_utf8(b)
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        _ => None,
    }
}

/// Port identifiers additionally arrive as integer subtypes (ifIndex-style).
fn port_text(v: &snmp::SnmpValue) -> Option<String> {
    match v {
        snmp::SnmpValue::Int(n) if *n >= 0 => Some(n.to_string()),
        _ => text_value(v),
    }
}

/// lldpRemManAddr octet string: `[address-subtype][address bytes]`
/// (subtype 1 = IPv4, 2 = IPv6); anything else stays visibly absent.
fn decode_lldp_man_addr(v: &snmp::SnmpValue) -> Option<String> {
    let b = match v {
        snmp::SnmpValue::Str(b) => b.as_slice(),
        _ => return None,
    };
    match b.split_first()? {
        (&1, rest) => decode_ipv4(rest),
        (&2, rest) => decode_ipv6(rest),
        _ => None,
    }
}

/// cdpCacheAddress octet string: either bare 4-byte IPv4, the classic
/// `[0x01][IPv4]` NLPID form, or `[0x02][16 bytes]` IPv6.
fn decode_cdp_addr(v: &snmp::SnmpValue) -> Option<String> {
    let b = match v {
        snmp::SnmpValue::Str(b) => b.as_slice(),
        _ => return None,
    };
    match b {
        [a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        [0x01, a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        [0x02, rest @ ..] => decode_ipv6(rest),
        _ => None,
    }
}

fn decode_ipv4(b: &[u8]) -> Option<String> {
    match b {
        [a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        _ => None,
    }
}

fn decode_ipv6(b: &[u8]) -> Option<String> {
    <[u8; 16]>::try_from(b)
        .ok()
        .map(|a| std::net::Ipv6Addr::from(a).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snmp::mock;
    use std::collections::HashMap;

    const COMMUNITY: &str = "public";
    const TIMEOUT_MS: u64 = 500;

    /// Field-projection for equality asserts (`NeighborRow` itself does not
    /// derive `PartialEq`; db.rs is outside this task's file scope).
    type RowTup = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        &'static str,
    );

    fn tup(r: &NeighborRow) -> RowTup {
        (
            r.local_if_name.clone(),
            r.neighbor_ip.clone(),
            r.neighbor_sysname.clone(),
            r.neighbor_platform.clone(),
            match r.protocol.as_str() {
                "lldp" => "lldp",
                _ => "cdp",
            },
        )
    }

    fn s(v: &str) -> snmp::SnmpValue {
        snmp::SnmpValue::Str(v.as_bytes().to_vec())
    }

    /// Two LLDP neighbors (instance suffixes `0.1.5`, `0.25.6`; the second
    /// lacks a management address) plus two CDP neighbors (`1.1`, `2.1`)
    /// exercising both cdpCacheAddress encodings.
    fn neighbor_fixture() -> HashMap<String, snmp::SnmpValue> {
        let mut t = HashMap::new();
        t.insert(format!("{LLDP_PORT_ID}.0.1.5"), s("Gi0/1"));
        t.insert(format!("{LLDP_SYS_NAME}.0.1.5"), s("core-sw"));
        t.insert(format!("{LLDP_SYS_DESC}.0.1.5"), s("Cisco IOS Software, C3750"));
        t.insert(
            format!("{LLDP_MAN_ADDR}.0.1.5"),
            snmp::SnmpValue::Str(vec![1, 10, 0, 0, 2]),
        );
        t.insert(format!("{LLDP_PORT_ID}.0.25.6"), s("Te1/0/2"));
        t.insert(format!("{LLDP_SYS_NAME}.0.25.6"), s("edge-sw"));
        t.insert(format!("{LLDP_SYS_DESC}.0.25.6"), s("ArubaOS 8.10"));

        t.insert(format!("{CDP_DEVICE_ID}.1.1"), s("wan-gw.example"));
        t.insert(
            format!("{CDP_ADDRESS}.1.1"),
            snmp::SnmpValue::Str(vec![0x01, 10, 0, 0, 1]),
        );
        t.insert(format!("{CDP_PLATFORM}.1.1"), s("cisco ISR4451"));
        t.insert(format!("{CDP_DEVICE_PORT}.1.1"), s("Gi0/0/3"));

        t.insert(format!("{CDP_DEVICE_ID}.2.1"), s("ap-lounge"));
        t.insert(
            format!("{CDP_ADDRESS}.2.1"),
            snmp::SnmpValue::Str(vec![10, 1, 2, 3]),
        );
        t.insert(format!("{CDP_PLATFORM}.2.1"), s("cisco AIR-AP2802"));
        t.insert(format!("{CDP_DEVICE_PORT}.2.1"), s("Gi0/0/24"));
        t
    }

    #[test]
    fn collect_decodes_lldp_and_cdp_rows() {
        let a = mock::spawn(COMMUNITY, neighbor_fixture()).unwrap();
        let rows = collect(a.addr(), COMMUNITY, TIMEOUT_MS).unwrap();
        assert_eq!(rows.len(), 4);
        let got: Vec<RowTup> = rows.iter().map(tup).collect();
        assert_eq!(
            got,
            vec![
                (
                    Some("Gi0/1".into()),
                    Some("10.0.0.2".into()),
                    Some("core-sw".into()),
                    Some("Cisco IOS Software, C3750".into()),
                    "lldp",
                ),
                (
                    Some("Te1/0/2".into()),
                    None,
                    Some("edge-sw".into()),
                    Some("ArubaOS 8.10".into()),
                    "lldp",
                ),
                (
                    Some("Gi0/0/3".into()),
                    Some("10.0.0.1".into()),
                    Some("wan-gw.example".into()),
                    Some("cisco ISR4451".into()),
                    "cdp",
                ),
                (
                    Some("Gi0/0/24".into()),
                    Some("10.1.2.3".into()),
                    Some("ap-lounge".into()),
                    Some("cisco AIR-AP2802".into()),
                    "cdp",
                ),
            ]
        );
        // The management-address-less LLDP row survives via sysname; a
        // platform-only row would be dropped as unidentifiable.
        assert!(rows.iter().all(identifiable));
    }

    #[test]
    fn device_answering_nothing_yields_empty_vec() {
        let a = mock::spawn(COMMUNITY, HashMap::new()).unwrap();
        let rows = collect(a.addr(), COMMUNITY, TIMEOUT_MS).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn unreachable_agent_yields_empty_vec_not_error() {
        let addr = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let rows = collect(addr, COMMUNITY, TIMEOUT_MS).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn address_decoders_cover_all_encodings() {
        let v4 = |b: &[u8]| snmp::SnmpValue::Str(b.to_vec());
        assert_eq!(
            decode_lldp_man_addr(&v4(&[1, 192, 168, 7, 1])),
            Some("192.168.7.1".to_string())
        );
        assert_eq!(
            decode_lldp_man_addr(&v4(&[
                2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(decode_lldp_man_addr(&v4(&[3, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])), None);
        assert_eq!(decode_lldp_man_addr(&snmp::SnmpValue::Int(4)), None);

        assert_eq!(
            decode_cdp_addr(&v4(&[0x01, 10, 0, 0, 1])),
            Some("10.0.0.1".to_string())
        );
        assert_eq!(
            decode_cdp_addr(&v4(&[10, 1, 2, 3])),
            Some("10.1.2.3".to_string())
        );
        assert_eq!(decode_cdp_addr(&v4(&[0x09, 1, 2])), None);
    }

    #[test]
    fn column_strip_is_arc_boundary_aware() {
        // `.1` must not strip-prefix a `.17` instance (arc-boundary check in
        // walk_column), while genuine suffixes survive intact.
        let a = mock::spawn(COMMUNITY, neighbor_fixture()).unwrap();
        let ports = walk_column(a.addr(), COMMUNITY, CDP_DEVICE_PORT, TIMEOUT_MS);
        assert_eq!(
            ports.keys().cloned().collect::<Vec<_>>(),
            vec!["1.1".to_string(), "2.1".to_string()]
        );
        assert_eq!(ports.get("2.1").and_then(port_text).as_deref(), Some("Gi0/0/24"));
    }
}
