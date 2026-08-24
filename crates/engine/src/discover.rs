use crate::arp;
use crate::engine::{sweep, Progress, ScanParams, Target};
use crate::model::{Device, Edge, Model, Role, State, Subnet};
use crate::netutil::{self, gateway_candidates, host_count, is_scannable};
use crate::oui;
use crate::ping;
use crate::report;
use crate::routes;
use anyhow::{bail, Result};
use chrono::Utc;
use ipnet::Ipv4Net;
use rand::seq::IteratorRandom;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Params {
    pub extra_subnets: Vec<Ipv4Net>,
    pub full: bool,
    pub big_threshold: u64,
    pub sample: u32,
    pub budget: Duration,
    pub no_auto: bool,
    pub scan: ScanParams,
    pub out_dir: PathBuf,
    /// max TTL-walk paths probed during classification (0 disables)
    pub walk_budget: usize,
    /// profile live endpoints: reverse-DNS names, TCP port fingerprint, class
    pub deep: bool,
    /// SNMPv2c community for identity probing; empty disables SNMP enrichment
    pub snmp_community: String,
    /// drop previously-seen devices unseen longer than this many days
    pub retire_days: u64,
}

struct Acc {
    probed: bool,
    up: bool,
    rtt_ms: Option<f64>,
    reply_ttl: Option<u8>,
    mac: Option<[u8; 6]>,
}

fn ttl_walk(ip: Ipv4Addr, scan: &ScanParams, deadline: Instant, max_hops: u8) -> (Option<u8>, Option<Ipv4Addr>) {
    let mut small = scan.clone();
    small.concurrency = 16;
    for k in 1..=max_hops {
        if Instant::now() >= deadline {
            break;
        }
        let targets = [Target::with_ttl(ip, k)];
        let res = match sweep(&targets, &small, Some(deadline), None) {
            Ok(r) => r,
            Err(_) => break,
        };
        let r = &res[0];
        if !r.probed {
            break;
        }
        if r.up {
            return (Some(k), None);
        }
        if let Some(resp) = r.responder {
            if resp != ip {
                return (None, Some(resp));
            }
        }
    }
    (None, None)
}

pub fn run(p: Params) -> Result<Model> {
    let t0 = Instant::now();
    let deadline = t0 + p.budget;
    println!("[*] icmp backend: {}", ping::backend_name());
    println!(
        "[*] discovery budget: {}m (hard deadline enforced)",
        p.budget.as_secs() / 60
    );

    let mut seeds: BTreeMap<String, (Ipv4Net, String)> = BTreeMap::new();
    if !p.no_auto {
        match if_addrs::get_if_addrs() {
            Ok(ifaces) => {
                let mut n_ifaces = 0;
                for i in ifaces {
                    if let if_addrs::IfAddr::V4(v4) = i.addr {
                        let prefix = netutil::mask_to_prefix(v4.netmask);
                        if let Ok(n) = Ipv4Net::new(v4.ip, prefix) {
                            let n = n.trunc();
                            let wanted = is_scannable(n)
                                || p.extra_subnets.iter().any(|e| e.contains(&v4.ip));
                            if wanted {
                                seeds.insert(n.to_string(), (n, "interface".into()));
                                n_ifaces += 1;
                            }
                        }
                    }
                }
                println!("[*] local interfaces contributed {n_ifaces} subnet(s)");
            }
            Err(e) => eprintln!("[!] interface enumeration failed: {e}"),
        }
        let rt = routes::read();
        let mut n_routes = 0;
        for r in &rt {
            if is_scannable(r.prefix) && !seeds.contains_key(&r.prefix.to_string()) {
                seeds.insert(r.prefix.to_string(), (r.prefix, "route".into()));
                n_routes += 1;
            }
        }
        println!("[*] routing table contributed {n_routes} additional subnet(s)");
    }
    for n in &p.extra_subnets {
        seeds.insert(n.to_string(), (*n, "cli".into()));
    }
    if seeds.is_empty() {
        bail!("no scannable subnets found; pass them explicitly with --subnets");
    }

    let mut gateways: HashSet<Ipv4Addr> = HashSet::new();
    for r in routes::read() {
        if let Some(gw) = r.next_hop {
            gateways.insert(gw);
        }
    }

    let mut subnet_list: Vec<(Ipv4Net, String, String)> = Vec::new();
    let mut all_targets: Vec<Target> = Vec::new();
    let mut seen_ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    for (cidr, (n, origin)) in &seeds {
        let (hosts, _sampled) = netutil::host_targets(*n, p.full, p.big_threshold, p.sample);
        let mut set: BTreeSet<Ipv4Addr> = hosts.into_iter().collect();
        for g in gateway_candidates(*n) {
            if n.contains(&g) {
                set.insert(g);
            }
        }
        subnet_list.push((*n, cidr.clone(), origin.clone()));
        for ip in set {
            if seen_ips.insert(ip) {
                all_targets.push(Target::new(ip));
            }
        }
    }
    netutil::shuffle(&mut all_targets);

    println!(
        "[*] crawling {} address(es) across {} subnet(s) | rate<={:.0}pps workers={} timeout={}ms",
        all_targets.len(),
        subnet_list.len(),
        p.scan.rate_pps,
        p.scan.concurrency,
        p.scan.timeout_ms
    );
    if p.budget.as_secs() < 3600 {
        println!("[*] oversized subnets (>{} hosts) are sampled; use --full for complete sweeps", p.big_threshold);
    }

    let prog = Progress::start("discover", all_targets.len());
    let outcomes = sweep(&all_targets, &p.scan, Some(deadline), Some(&prog.done))?;
    prog.finish();

    let unprobed = outcomes.iter().filter(|o| !o.probed).count();
    if unprobed > 0 {
        println!("[!] stopped early: {unprobed} address(es) left unprobed (budget)");
    }

    let mut acc: HashMap<Ipv4Addr, Acc> = HashMap::new();
    for o in &outcomes {
        let e = acc.entry(o.ip).or_insert(Acc {
            probed: false,
            up: false,
            rtt_ms: o.rtt_ms,
            reply_ttl: o.reply_ttl,
            mac: None,
        });
        e.probed |= o.probed;
        if o.up {
            e.up = true;
            if let Some(rt) = o.rtt_ms {
                e.rtt_ms = Some(e.rtt_ms.map_or(rt, |old: f64| old.min(rt)));
            }
            e.reply_ttl = o.reply_ttl;
        }
    }
    let arps = arp::read();
    println!("[*] arp cache: {} mac mapping(s)", arps.len());
    for (ip, mac) in arps {
        if let Some(e) = acc.get_mut(&ip) {
            e.mac = Some(mac);
        }
    }

    let mut sorted_subnets: Vec<(Ipv4Net, &String, &String)> = subnet_list
        .iter()
        .map(|(n, c, o)| (*n, c, o))
        .collect();
    sorted_subnets.sort_by_key(|a| std::cmp::Reverse(a.0.prefix_len()));
    let subnet_of = |ip: Ipv4Addr| -> Option<String> {
        sorted_subnets
            .iter()
            .find(|(n, _, _)| n.contains(&ip))
            .map(|(_, c, _)| (*c).clone())
    };

    let mut subnet_stats: Vec<Subnet> = Vec::new();
    let mut base_ttl: HashMap<String, u8> = HashMap::new();
    for (n, cidr, origin) in &subnet_list {
        let mut probed = 0u64;
        let mut alive = 0u64;
        let mut max_ttl: u8 = 0;
        for (ip, e) in &acc {
            if n.contains(ip) {
                if e.probed {
                    probed += 1;
                }
                if e.up {
                    alive += 1;
                    if let Some(t) = e.reply_ttl {
                        max_ttl = max_ttl.max(t);
                    }
                }
            }
        }
        if max_ttl > 0 {
            base_ttl.insert(cidr.clone(), max_ttl);
        }
        let (_, sampled) = netutil::host_targets(*n, p.full, p.big_threshold, p.sample);
        subnet_stats.push(Subnet {
            cidr: cidr.clone(),
            origin: origin.clone(),
            sampled,
            hosts: host_count(*n),
            probed,
            alive,
        });
    }

    let mut walk_routers: HashSet<Ipv4Addr> = HashSet::new();
    let mut hops_of: HashMap<Ipv4Addr, u8> = HashMap::new();
    let mut walked = 0usize;
    println!("[*] ttl-hop walking (silent traceroute-lite)...");
    'outer: for (n, _cidr, _) in &subnet_list {
        let candidates: Vec<Ipv4Addr> = acc
            .iter()
            .filter(|(ip, e)| e.up && n.contains(*ip) && !gateways.contains(*ip))
            .map(|(ip, _)| *ip)
            .collect();
        let picks = candidates.into_iter().choose_multiple(&mut rand::thread_rng(), 3);
        for c in picks {
            if walked >= p.walk_budget || Instant::now() >= deadline {
                break 'outer;
            }
            walked += 1;
            let (hops, router_ip) = ttl_walk(c, &p.scan, deadline, 8);
            if let Some(h) = hops {
                hops_of.insert(c, h);
            }
            if let Some(r) = router_ip {
                walk_routers.insert(r);
            }
        }
    }
    println!("[*] ttl walks: {walked} path(s), {} intermediate router(s) found", walk_routers.len());

    let mut routers_all: HashSet<Ipv4Addr> = HashSet::new();
    routers_all.extend(gateways.iter().copied());
    routers_all.extend(walk_routers.iter().copied());
    for (n, _, _) in &subnet_list {
        let has_router = routers_all.iter().any(|r| n.contains(r));
        if !has_router {
            for g in gateway_candidates(*n) {
                if n.contains(&g) && acc.get(&g).is_some_and(|e| e.up) {
                    routers_all.insert(g);
                    break;
                }
            }
        }
    }

    let prior = Model::load(&p.out_dir.join("model.json")).ok();
    let now_str = Utc::now().to_rfc3339();

    let mut devices: Vec<Device> = Vec::new();
    for (ip, e) in &acc {
        if !e.probed || !e.up {
            continue;
        }
        let role = if routers_all.contains(ip) {
            Role::Router
        } else if e.mac.and_then(|m| oui::wifi_vendor(&m)).is_some() {
            Role::Wap
        } else {
            Role::Endpoint
        };
        let mut hint: Option<String> = None;
        if let Some(ttl) = e.reply_ttl {
            let init: u8 = if (65..=128).contains(&ttl) {
                128
            } else if (33..=64).contains(&ttl) {
                64
            } else if ttl > 192 {
                255
            } else {
                0
            };
            if init > 0 {
                let extra = init - ttl;
                if extra >= 2 {
                    hint = Some(format!("~{extra} extra L3 hop(s) behind this address"));
                }
            }
        }
        if hint.is_none() {
            if let Some(h) = hops_of.get(ip) {
                if *h > 1 {
                    hint = Some(format!("~{} IP hop(s) from scanner", h));
                }
            }
        }
        if hint.is_none() {
            if let Some(m) = e.mac {
                if let Some(vendor) = oui::router_vendor(&m) {
                    if !routers_all.contains(ip) {
                        hint = Some(format!("{vendor} OUI; not confirmed as L3 hop"));
                    }
                }
            }
        }
        devices.push(Device {
            ip: *ip,
            mac: e.mac.map(|m| oui::mac_str(&m)),
            role,
            state: State::Up,
            subnet: subnet_of(*ip),
            rtt_ms: e.rtt_ms,
            reply_ttl: e.reply_ttl,
            hint,
            first_seen: now_str.clone(),
            last_seen: now_str.clone(),
            down_since: None,
            ever_up: true,
            wap: None,
            wap_source: None,
            hostname: None,
            device_class: None,
        });
    }

    if let Some(pm) = prior {
        let retire_cutoff = Utc::now() - chrono::Duration::days(p.retire_days.max(1) as i64);
        for d in pm.devices {
            // Retire devices that have been absent far too long.
            if let Ok(seen) = chrono::DateTime::parse_from_rfc3339(&d.last_seen) {
                if seen.with_timezone(&Utc) < retire_cutoff && d.wap.is_none() {
                    continue;
                }
            }
            match devices.iter_mut().find(|x| x.ip == d.ip) {
                Some(nd) => {
                    nd.first_seen = d.first_seen;
                    nd.down_since = None;
                    nd.ever_up = true;
                    nd.wap = d.wap;
                    nd.wap_source = d.wap_source;
                    if nd.role == Role::Endpoint && d.role != Role::Endpoint {
                        nd.role = d.role;
                    }
                    if nd.mac.is_none() {
                        nd.mac = d.mac;
                    }
                    if nd.hint.is_none() {
                        nd.hint = d.hint;
                    }
                }
                None => {
                    let mut old = d;
                    let legacy_placeholder = !old.ever_up
                        && old.state == State::Down
                        && old.role == Role::Endpoint
                        && old.mac.is_none()
                        && old.wap.is_none()
                        && old.hint.is_none()
                        && old.rtt_ms.is_none();
                    if legacy_placeholder {
                        continue;
                    }
                    old.ever_up = old.ever_up
                        || old.state == State::Up
                        || old.mac.is_some();
                    if !old.ever_up {
                        continue;
                    }
                    if acc.get(&old.ip).is_some_and(|e| e.probed) {
                        if old.state != State::Down {
                            old.down_since = Some(now_str.clone());
                        }
                        old.state = State::Down;
                        old.rtt_ms = None;
                    }
                    devices.push(old);
                }
            }
        }
    }
    devices.sort_by_key(|d| u32::from(d.ip));

    if p.deep {
        let live: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.state == State::Up && d.role == Role::Endpoint)
            .map(|(i, _)| i)
            .collect();
        println!("[*] deep discovery: profiling {} live endpoint(s)", live.len());
        let profiles: std::sync::Mutex<HashMap<Ipv4Addr, crate::profile::Profile>> =
            std::sync::Mutex::new(HashMap::new());
        for chunk in live.chunks(32) {
            std::thread::scope(|s| {
                for &i in chunk {
                    let (ip, mac) = {
                        let d = &devices[i];
                        (d.ip, d.mac.clone())
                    };
                    let profiles = &profiles;
                    s.spawn(move || {
                        let prof = crate::profile::profile_endpoint(
                            ip,
                            mac.as_deref(),
                            "endpoint",
                        );
                        profiles.lock().unwrap().insert(ip, prof);
                    });
                }
            });
        }
        let map = profiles.into_inner().unwrap();
        for d in devices.iter_mut() {
            if let Some(prof) = map.get(&d.ip) {
                d.hostname = prof.hostname.clone();
                d.device_class = Some(prof.device_class.clone());
                let summary = crate::profile::summarize(prof);
                if !summary.is_empty() {
                    d.hint = Some(summary);
                }
            }
        }
        println!("[*] profiled {} host(s)", map.len());
    }

    // ---- SNMP identity enrichment (FR-PRF-003 v0): sysName/sysDescr
    if !p.snmp_community.is_empty() {
        let live: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.state == State::Up)
            .map(|(i, _)| i)
            .collect();
        println!(
            "[*] snmp: probing {} live host(s) (community '{}')",
            live.len(),
            if p.snmp_community == "public" { "public" } else { "***" }
        );
        let mut enriched = 0usize;
        let community = p.snmp_community.clone();
        for chunk in live.chunks(32) {
            let results: std::sync::Mutex<HashMap<usize, crate::snmpprobe::SnmpIdentity>> =
                std::sync::Mutex::new(HashMap::new());
            std::thread::scope(|s| {
                for &i in chunk {
                    let ip = devices[i].ip;
                    let results = &results;
                    let community = &community;
                    s.spawn(move || {
                        let addr =
                            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 161);
                        if let Ok(id) = crate::snmpprobe::probe_identity(
                            addr,
                            community,
                            400,
                        ) {
                            results.lock().unwrap().insert(i, id);
                        }
                    });
                }
            });
            for (i, id) in results.into_inner().unwrap() {
                let d = &mut devices[i];
                if d.hostname.is_none() {
                    d.hostname = id.sys_name.clone();
                }
                if let Some(descr) = &id.sys_descr {
                    let tag = match crate::snmpprobe::classify_os(descr) {
                        Some((vendor, os)) => format!("[SNMP] {vendor} {os}"),
                        None => format!(
                            "[SNMP] {}",
                            descr.chars().take(60).collect::<String>()
                        ),
                    };
                    match &mut d.hint {
                        Some(h) if !h.contains("[SNMP]") => h.push_str(&format!(" {tag}")),
                        Some(_) => {}
                        none => *none = Some(tag),
                    }
                    enriched += 1;
                } else if d.hostname.is_some() {
                    enriched += 1;
                }
            }
        }
        println!("[*] snmp enrichment applied to {enriched} host(s)");

        // ---- interface inventory via ifTable walk (FR-DISC-003 v0):
        // routers/WAPs first-class, but any live host is walked; failures are
        // per-device and non-fatal.
        use crate::db;
        let now_ts = chrono::Utc::now().timestamp();
        let mut if_total = 0usize;
        let mut iface_rows: HashMap<Ipv4Addr, Vec<db::IfaceRow>> = HashMap::new();
        for chunk in live.chunks(32) {
            let collected: std::sync::Mutex<Vec<(Ipv4Addr, Vec<db::IfaceRow>)>> =
                std::sync::Mutex::new(Vec::new());
            std::thread::scope(|s| {
                for &i in chunk {
                    let ip = devices[i].ip;
                    let collected = &collected;
                    let community = &p.snmp_community;
                    s.spawn(move || {
                        let addr =
                            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 161);
                        if let Ok(entries) =
                            snmp::walk_if_table(addr, community, 600, 64)
                        {
                            let rows: Vec<db::IfaceRow> = entries.into_iter().map(iface_entry_to_row).collect();
                            if !rows.is_empty() {
                                collected.lock().unwrap().push((ip, rows));
                            }
                        }
                    });
                }
            });
            for (ip, rows) in collected.into_inner().unwrap() {
                if_total += rows.len();
                iface_rows.insert(ip, rows);
            }
        }
        if !iface_rows.is_empty() {
            match db::Db::open(&p.out_dir.join("ops.db")) {
                Ok(store) => {
                    let conn = store.lock();
                    for (ip, rows) in &iface_rows {
                        if let Ok(Some(dev)) = db::device_by_ip(&conn, &ip.to_string()) {
                            let _ = db::replace_interfaces(&conn, dev.id, rows, now_ts);
                        }
                    }
                    drop(conn);
                    println!(
                        "[*] snmp: stored {} interface(s) across {} host(s)",
                        if_total,
                        iface_rows.len()
                    );
                }
                Err(e) => eprintln!("[!] snmp interfaces: store unavailable: {e}"),
            }
        }
    }

    let mut edges: BTreeSet<(String, String, String)> = BTreeSet::new();
    for (n, _cidr, _) in &subnet_list {
        let anchors: Vec<Ipv4Addr> = {
            let mut v: Vec<Ipv4Addr> =
                routers_all.iter().copied().filter(|r| n.contains(r)).collect();
            v.sort_by_key(|r| (!gateways.contains(r), u32::from(*r)));
            v
        };
        if let Some(a) = anchors.first() {
            let a_s = a.to_string();
            for d in &devices {
                if d.role != Role::Router && n.contains(&d.ip) {
                    edges.insert((d.ip.to_string(), a_s.clone(), "member".into()));
                }
            }
            for r in &anchors {
                if r != a {
                    edges.insert((r.to_string(), a_s.clone(), "transit".into()));
                }
            }
        }
    }
    let edges: Vec<Edge> = edges
        .into_iter()
        .map(|(src, dst, kind)| Edge { src, dst, kind })
        .collect();

    let backend = ping::backend_name().to_string();
    let model = Model {
        generated_at: Utc::now().to_rfc3339(),
        scan_duration_ms: t0.elapsed().as_millis() as u64,
        backend,
        subnets: subnet_stats,
        devices,
        edges,
    };

    std::fs::create_dir_all(&p.out_dir)?;
    let model_path = p.out_dir.join("model.json");
    model.save(&model_path)?;
    let html = report::render(&model, 3500)?;
    std::fs::write(p.out_dir.join("map.html"), html)?;
    println!("[*] wrote {}", model_path.display());
    println!("[*] wrote {}", p.out_dir.join("map.html").display());
    Ok(model)
}

/// Convert a collector-snmp ifTable entry into a storable row (unit-tested
/// seam between the protocol crate and the ops store).
fn iface_entry_to_row(e: snmp::IfaceEntry) -> crate::db::IfaceRow {
    crate::db::IfaceRow {
        if_index: e.if_index,
        name: e.name,
        speed_bps: e.speed_bps,
        admin_status: e.admin_status,
        oper_status: e.oper_status,
        mac: e.mac,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_entry_maps_all_fields() {
        let row = iface_entry_to_row(snmp::IfaceEntry {
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
        assert_eq!(row.oper_status.as_deref(), Some("down"));
        assert!(row.mac.is_some());
    }
}
