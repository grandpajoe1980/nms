//! Deep device inspection (PRD §4.1 FR-DISC-002/003, §3.1.1 "progressively
//! deep"): an explicit, opt-in pass that runs the thorough battery — SNMP
//! identity (sysName/sysDescr/sysUpTime), ifTable interface inventory, and
//! LLDP/CDP neighbor discovery — against every live device in the model.
//! Runs only when asked for (CLI `nms inspect` or POST /api/inspect), never
//! as a side effect of discovery.

use crate::db::{self, Db};
use crate::model::State;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct InspectStats {
    pub devices: usize,
    pub snmp_ok: usize,
    pub interfaces: usize,
    pub neighbors: usize,
    pub duration_ms: u64,
}

/// Run `f` over (absolute_index, item) pairs width-wide in parallel,
/// collecting Some(results). Keeps original indices stable.
fn chunked_map<T, R, F>(items: &[(usize, T)], width: usize, f: F) -> Vec<(usize, R)>
where
    T: Copy + Send + Sync + 'static,
    R: Send + 'static,
    F: Fn((usize, T)) -> Option<R> + Send + Sync + 'static,
{
    let mut out = Vec::new();
    for chunk in items.chunks(width.max(1)) {
        let collected: std::sync::Mutex<Vec<(usize, R)>> = std::sync::Mutex::new(Vec::new());
        let f = &f;
        std::thread::scope(|s| {
            for &(idx, item) in chunk {
                let collected = &collected;
                s.spawn(move || {
                    if let Some(r) = f((idx, item)) {
                        collected.lock().unwrap().push((idx, r));
                    }
                });
            }
        });
        out.extend(collected.into_inner().unwrap());
    }
    out
}

/// Run the full inspection battery over live model devices.
pub fn run(
    dbh: &Arc<Db>,
    out_dir: &Path,
    community: &str,
    timeout_ms: u64,
    port: u16,
    max_devices: usize,
) -> Result<InspectStats> {
    let t0 = std::time::Instant::now();
    let mut stats = InspectStats::default();

    let mut model = crate::model::Model::load(&out_dir.join("model.json"))?;
    let targets: Vec<(usize, std::net::Ipv4Addr)> = model
        .devices
        .iter()
        .enumerate()
        .filter(|(_, d)| d.state == State::Up)
        .map(|(i, d)| (i, d.ip))
        .take(max_devices.max(1))
        .collect();
    if targets.is_empty() {
        return Ok(stats);
    }
    let total = targets.len();
    let community = community.to_string();
    let community_p1 = community.clone();
    let community_p2 = community.clone();
    crate::progress::begin("inspect", total * 3);

    // ---- resolve device rows once (ids needed for persistence)
    let ids: HashMap<std::net::Ipv4Addr, i64> = {
        let conn = dbh.lock();
        targets
            .iter()
            .filter_map(|&(_, ip)| {
                db::device_by_ip(&conn, &ip.to_string()).ok().flatten().map(|d| (ip, d.id))
            })
            .collect()
    };

    // ---- phase 1: SNMP identity
    let identities: HashMap<usize, crate::snmpprobe::SnmpIdentity> =
        chunked_map(&targets, 32, move |(_idx, ip)| {
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            crate::snmpprobe::probe_identity(addr, &community_p1, timeout_ms).ok()
        })
        .into_iter()
        .collect();
    stats.snmp_ok = identities.len();
    for (i, id) in &identities {
        let d = &mut model.devices[*i];
        if d.hostname.is_none() {
            d.hostname = id.sys_name.clone();
        }
        if let Some(descr) = &id.sys_descr {
            let tag = match crate::snmpprobe::classify_os(descr) {
                Some((vendor, os)) => format!("[SNMP] {vendor} {os}"),
                None => format!("[SNMP] {}", descr.chars().take(60).collect::<String>()),
            };
            match &mut d.hint {
                Some(h) if !h.contains("[SNMP]") => h.push_str(&format!(" {tag}")),
                Some(_) => {}
                none => *none = Some(tag),
            }
        }
    }
    // count ticks for identity phase
    for _ in 0..total {
        crate::progress::tick(1);
    }

    // persist hostname/hints into the ops store via the standard sync path
    {
        let conn = dbh.lock();
        let prefix: u8 = db::get_setting_or(&conn, "site_auto_prefix", "24")
            .parse()
            .unwrap_or(24);
        drop(conn);
        crate::ops::sync_model(&dbh.lock(), &model, prefix)?;
    }

    let id_of = |ip: std::net::Ipv4Addr| -> Option<i64> { ids.get(&ip).copied() };

    let community = community.clone();
    // ---- phase 2: ifTable interfaces
    let iface_results: Vec<(usize, Vec<snmp::IfaceEntry>)> =
        chunked_map(&targets, 24, move |(_idx, ip)| {
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            snmp::walk_if_table(addr, &community_p2, timeout_ms.max(400), 64)
                .ok()
                .filter(|v| !v.is_empty())
        })
        .into_iter()
        .collect();
    {
        let conn = dbh.lock();
        let now_ts = chrono::Utc::now().timestamp();
        for (idx, entries) in &iface_results {
            let ip = model.devices[*idx].ip;
            let Some(dev_id) = id_of(ip) else { continue };
            let rows: Vec<db::IfaceRow> = entries.iter().map(map_iface).collect();
            stats.interfaces += rows.len();
            db::replace_interfaces(&conn, dev_id, rows.as_slice(), now_ts)?;
        }
    }
    for _ in 0..total {
        crate::progress::tick(1);
    }

    let community = community.clone();
    // ---- phase 3: LLDP/CDP neighbors
    let nb_results: Vec<(usize, Vec<crate::db::NeighborRow>)> =
        chunked_map(&targets, 24, move |(_idx, ip)| {
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            crate::neighbors::collect(addr, &community, timeout_ms.max(500))
                .ok()
                .filter(|v| !v.is_empty())
        })
        .into_iter()
        .collect();
    {
        let conn = dbh.lock();
        let now_ts = chrono::Utc::now().timestamp();
        for (idx, rows) in &nb_results {
            let ip = model.devices[*idx].ip;
            let Some(dev_id) = id_of(ip) else { continue };
            stats.neighbors += rows.len();
            db::replace_neighbors(&conn, dev_id, rows, now_ts)?;
        }
    }
    for _ in 0..total {
        crate::progress::tick(1);
    }
    crate::progress::clear();

    // ---- persist hostname/hints back into model.json so map/console show them
    model.generated_at = chrono::Utc::now().to_rfc3339();
    model.save(&out_dir.join("model.json"))?;
    if let Ok(html) = crate::report::render(&model, 3500) {
        let _ = std::fs::write(out_dir.join("map.html"), html);
    }

    stats.devices = total;
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    Ok(stats)
}

fn map_iface(e: &snmp::IfaceEntry) -> db::IfaceRow {
    db::IfaceRow {
        if_index: e.if_index,
        name: e.name.clone(),
        speed_bps: e.speed_bps,
        admin_status: e.admin_status.clone(),
        oper_status: e.oper_status.clone(),
        mac: e.mac.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_entry_maps_all_fields() {
        let row = map_iface(&snmp::IfaceEntry {
            if_index: 3,
            name: Some("Gi0/1".into()),
            speed_bps: Some(1_000_000_000),
            admin_status: Some("up".into()),
            oper_status: Some("down".into()),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
        });
        assert_eq!(row.if_index, 3);
        assert_eq!(row.name.as_deref(), Some("Gi0/1"));
        assert_eq!(row.speed_bps, Some(1_000_000_000));
        assert_eq!(row.admin_status.as_deref(), Some("up"));
        assert_eq!(row.oper_status.as_deref(), Some("down"));
        assert_eq!(row.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }
}
