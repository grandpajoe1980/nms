//! Temporal topology graph (FR-TOP-002): promotes raw neighbor observations
//! into deduplicated, provenance-tracked edges. Provides BFS path finding.

use crate::db::{self, Db};
use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Promote LLDP/CDP neighbor rows into deduplicated graph edges.
pub fn promote_neighbors(conn: &Connection, now: i64) -> Result<usize> {
    let neighbors: Vec<(i64, Option<String>, Option<String>, String)> = {
        let Ok(mut stmt) = conn.prepare(
            "SELECT n.device_id, n.neighbor_ip, n.neighbor_mac, n.protocol
             FROM neighbors n JOIN devices d ON d.id = n.device_id
             WHERE d.managed = 1",
        ) else { return Ok(0) };
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        }).map(|rows| rows.flatten().collect()).unwrap_or_default()
    };

    let mut promoted = 0usize;
    for (device_id, nb_ip, nb_mac, protocol) in &neighbors {
        let dst_id = resolve_device_id(conn, nb_ip.as_deref(), nb_mac.as_deref());
        let Some(dst_id) = dst_id else { continue };
        if dst_id == *device_id { continue; }
        db::upsert_edge(conn, &db::GraphEdgeUpsert {
            src: *device_id, dst: dst_id, edge_type: protocol,
            local_port: None, remote_port: None, source: protocol,
            confidence: 0.9,
        }, now)?;
        promoted += 1;
    }
    Ok(promoted)
}

fn resolve_device_id(conn: &Connection, ip: Option<&str>, mac: Option<&str>) -> Option<i64> {
    if let Some(ip) = ip {
        if let Ok(Some(d)) = db::device_by_ip(conn, ip) { return Some(d.id); }
    }
    if let Some(mac) = mac {
        if let Ok(mut stmt) = conn.prepare("SELECT id FROM devices WHERE mac=?1 LIMIT 1") {
            return stmt.query_row([mac], |r| r.get(0)).optional().ok().flatten();
        }
    }
    None
}

use rusqlite::OptionalExtension;

/// BFS shortest path between two device IDs.
pub fn bfs_path(conn: &Connection, src: i64, dst: i64) -> Vec<i64> {
    if src == dst { return vec![src]; }
    let Ok(edges) = db::all_edges(conn) else { return vec![] };
    let mut adj: HashMap<i64, Vec<i64>> = HashMap::new();
    for e in &edges {
        adj.entry(e.src_device_id).or_default().push(e.dst_device_id);
        adj.entry(e.dst_device_id).or_default().push(e.src_device_id);
    }
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([(src, vec![src])]);
    while let Some((node, path)) = queue.pop_front() {
        if node == dst { return path; }
        if !visited.insert(node) { continue; }
        for &next in adj.get(&node).into_iter().flatten() {
            if !visited.contains(&next) {
                let mut p = path.clone(); p.push(next); queue.push_back((next, p));
            }
        }
    }
    Vec::new()
}

#[derive(Debug, Clone, Serialize)]
pub struct PathHop { pub device_ip: String, pub role: String }

pub fn resolve_path(dbh: &Arc<Db>, path_ids: &[i64]) -> Vec<PathHop> {
    let conn = dbh.lock();
    path_ids.iter().filter_map(|&id| {
        crate::db::device_by_id(&conn, id).ok().flatten().map(|d| PathHop {
            device_ip: d.ip.clone(), role: d.role,
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn setup() -> Arc<Db> {
        let dbh = Arc::new(Db::open_memory().unwrap());
        let c = dbh.lock();
        c.execute_batch("
            INSERT INTO devices(id,ip,role,first_seen_ts,last_seen_ts)
            VALUES (1,'10.0.0.1','router',1,2),(2,'10.0.0.2','switch',1,2),
                   (3,'10.0.0.3','endpoint',1,2),(4,'10.0.0.4','endpoint',1,2);
        ").unwrap();
        drop(c);
        dbh
    }

    #[test]
    fn edge_upsert_dedupes_and_updates() {
        let dbh = setup();
        let c = dbh.lock();
        db::upsert_edge(&c, &db::GraphEdgeUpsert { src:1, dst:2, edge_type:"lldp", local_port:Some("Gi0/1"), remote_port:None, source:"lldp", confidence:1.0 }, 100).unwrap();
        db::upsert_edge(&c, &db::GraphEdgeUpsert { src:1, dst:2, edge_type:"lldp", local_port:Some("Gi0/1"), remote_port:None, source:"lldp", confidence:1.0 }, 200).unwrap();
        assert_eq!(db::all_edges(&c).unwrap().len(), 1);
        let e = &db::all_edges(&c).unwrap()[0];
        assert_eq!(e.last_seen_ts, 200);
    }

    #[test]
    fn bfs_finds_shortest_path() {
        let dbh = setup();
        let c = dbh.lock();
        for (a,b,p) in [(1i64,2i64,"lldp"),(2,3,"lldp"),(2,4,"cdp")] {
            db::upsert_edge(&c, &db::GraphEdgeUpsert { src:a, dst:b, edge_type:p, local_port:None, remote_port:None, source:p, confidence:1.0 }, 100).unwrap();
        }
        let path = bfs_path(&c, 3, 4);
        assert_eq!(path, vec![3, 2, 4]);
        assert!(bfs_path(&c, 1, 99).is_empty());
    }

    #[test]
    fn stale_detection_lowers_confidence() {
        let dbh = setup();
        let c = dbh.lock();
        db::upsert_edge(&c, &db::GraphEdgeUpsert { src:1, dst:2, edge_type:"lldp", local_port:None, remote_port:None, source:"lldp", confidence:1.0 }, 100).unwrap();
        db::stale_graph_edges(&c, 200).unwrap();
        let e = &db::all_edges(&c).unwrap()[0];
        assert!((e.confidence - 0.3).abs() < f64::EPSILON);
    }
}
