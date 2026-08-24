use crate::engine::{sweep, Progress, ScanParams, Target};
use crate::model::{Device, Model, Role, State};
use crate::netutil::{self, gateway_candidates};
use crate::report;
use crate::routes;
use anyhow::{bail, Result};
use chrono::Utc;
use ipnet::Ipv4Net;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Instant;

pub struct Params {
    pub extra_subnets: Vec<Ipv4Net>,
    pub scan: ScanParams,
    pub out_dir: PathBuf,
    pub max_targets: u64,
    pub budget_secs: u64,
    pub confirm_down: u32,
}

#[derive(Clone, Debug)]
pub struct Transition {
    pub ip: Ipv4Addr,
    pub role: Role,
    pub subnet: Option<String>,
    pub from: Option<State>,
    pub to: State,
}

#[derive(Clone, Debug)]
pub struct Probe {
    pub ip: Ipv4Addr,
    pub up: bool,
    pub rtt_ms: Option<f64>,
}

pub struct RunResult {
    pub model: Model,
    pub transitions: Vec<Transition>,
    pub probes: Vec<Probe>,
    pub unprobed: usize,
}

pub fn sweep_once(p: &Params) -> Result<RunResult> {
    let t0 = Instant::now();
    let deadline = t0 + std::time::Duration::from_secs(p.budget_secs);

    let mut model = match Model::load(&p.out_dir.join("model.json")) {
        Ok(m) => m,
        Err(_) => Model::new(),
    };

    let mut known: BTreeSet<String> = model.subnets.iter().map(|s| s.cidr.clone()).collect();
    for n in &p.extra_subnets {
        if known.insert(n.to_string()) {
            model.subnets.push(crate::model::Subnet {
                cidr: n.to_string(),
                origin: "cli".into(),
                sampled: false,
                hosts: netutil::host_count(*n),
                probed: 0,
                alive: 0,
            });
        }
    }
    if model.subnets.is_empty() {
        bail!("nothing to check: no existing model and no --subnets given");
    }

    let gateways: std::collections::HashSet<Ipv4Addr> =
        routes::read().iter().filter_map(|r| r.next_hop).collect();

    let n_subs = model.subnets.len() as u64;
    let budget_per = (p.max_targets / n_subs).clamp(1, u32::MAX as u64);
    let mut target_set: BTreeSet<Ipv4Addr> = BTreeSet::new();
    for s in &mut model.subnets {
        let n: Ipv4Net = match s.cidr.parse() {
            Ok(x) => x,
            Err(_) => continue,
        };
        let (hosts, sampled) = netutil::host_targets(n, false, budget_per, budget_per as u32);
        s.sampled = sampled;
        for h in hosts {
            target_set.insert(h);
        }
        for g in gateway_candidates(n) {
            if n.contains(&g) {
                target_set.insert(g);
            }
        }
    }
    for d in &model.devices {
        target_set.insert(d.ip);
    }

    let mut targets: Vec<Target> = target_set.into_iter().map(Target::new).collect();
    netutil::shuffle(&mut targets);

    let prog = Progress::start("check", targets.len());
    let mut outcomes = sweep(&targets, &p.scan, Some(deadline), Some(&prog.done))?;
    prog.finish();

    let mut confirmed_up: std::collections::HashSet<Ipv4Addr> = Default::default();
    let idx = model.device_index();
    if p.confirm_down > 0 {
        let mut pending: Vec<Target> = outcomes
            .iter()
            .filter(|o| o.probed && !o.up)
            .filter(|o| idx.get(&o.ip).is_some_and(|&i| model.devices[i].state == State::Up))
            .map(|o| Target::new(o.ip))
            .collect();
        let mut cscan = p.scan.clone();
        cscan.rate_pps = (cscan.rate_pps * 2.0).max(200.0);
        for _ in 0..p.confirm_down {
            if pending.is_empty() {
                break;
            }
            if let Ok(res) = sweep(&pending, &cscan, None, None) {
                pending.retain(|t| {
                    let still_down = res.iter().find(|r| r.ip == t.ip).is_none_or(|r| !r.up);
                    if !still_down {
                        confirmed_up.insert(t.ip);
                    }
                    still_down
                });
            }
        }
        for o in &mut outcomes {
            if confirmed_up.contains(&o.ip) {
                o.up = true;
            }
        }
    }

    let now_str = Utc::now().to_rfc3339();
    let mut new_devices: Vec<Device> = Vec::new();
    let mut transitions: Vec<Transition> = Vec::new();
    for o in &outcomes {
        if !o.probed {
            continue;
        }
        match idx.get(&o.ip) {
            Some(&i) => {
                let d = &mut model.devices[i];
                let prev = d.state;
                if o.up {
                    d.state = State::Up;
                    d.ever_up = true;
                    d.last_seen = now_str.clone();
                    d.rtt_ms = o.rtt_ms;
                    d.reply_ttl = o.reply_ttl;
                    d.down_since = None;
                } else {
                    if d.state != State::Down {
                        d.down_since = Some(now_str.clone());
                    }
                    d.state = State::Down;
                    d.rtt_ms = None;
                }
                if prev != d.state {
                    transitions.push(Transition {
                        ip: d.ip,
                        role: d.role,
                        subnet: d.subnet.clone(),
                        from: Some(prev),
                        to: d.state,
                    });
                }
            }
            None => {
                if o.up {
                    let role = if gateways.contains(&o.ip) { Role::Router } else { Role::Endpoint };
                    new_devices.push(Device {
                        ip: o.ip,
                        mac: None,
                        role,
                        state: State::Up,
                        subnet: model
                            .subnets
                            .iter()
                            .find(|s| s.cidr.parse::<Ipv4Net>().is_ok_and(|n| n.contains(&o.ip)))
                            .map(|s| s.cidr.clone()),
                        rtt_ms: o.rtt_ms,
                        reply_ttl: o.reply_ttl,
                        hint: None,
                        first_seen: now_str.clone(),
                        last_seen: now_str.clone(),
                        down_since: None,
                        ever_up: true,
                        wap: None,
                        wap_source: None,
                        hostname: None,
                        device_class: None,
                    });
                    transitions.push(Transition {
                        ip: o.ip,
                        role,
                        subnet: None,
                        from: None,
                        to: State::Up,
                    });
                }
            }
        }
    }
    model.devices.extend(new_devices);
    model.devices.sort_by_key(|d| u32::from(d.ip));

    let unprobed = outcomes.iter().filter(|o| !o.probed).count();
    let probes: Vec<Probe> = outcomes
        .iter()
        .filter(|o| o.probed)
        .map(|o| Probe { ip: o.ip, up: o.up, rtt_ms: if o.up { o.rtt_ms } else { None } })
        .collect();

    model.generated_at = Utc::now().to_rfc3339();
    model.scan_duration_ms = t0.elapsed().as_millis() as u64;
    if model.backend.is_empty() {
        model.backend = crate::ping::backend_name().to_string();
    }

    std::fs::create_dir_all(&p.out_dir)?;
    let model_path = p.out_dir.join("model.json");
    model.save(&model_path)?;
    let html = report::render(&model, 3500)?;
    std::fs::write(p.out_dir.join("map.html"), html)?;

    Ok(RunResult { model, transitions, probes, unprobed })
}

