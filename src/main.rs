mod arp;
mod check;
mod db;
mod discover;
mod engine;
mod jobs;
mod model;
mod monitor;
mod netutil;
mod ops;
mod oui;
mod ping;
mod progress;
mod report;
mod routes;
mod server;
mod ui;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use model::{Model, Role, State};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "nms",
    version,
    about = "Silent ICMP network discovery + status monitoring with an HTML map"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "crawl the network: find subnets, hosts, routers, waps; build model + map")]
    Discover {
        #[arg(long, value_delimiter = ',', help = "extra CIDRs to crawl (e.g. 10.20.0.0/16)")]
        subnets: Option<Vec<String>>,
        #[arg(long, default_value_t = 400.0, help = "max probes per second")]
        rate: f64,
        #[arg(long, default_value_t = 512, help = "parallel ping workers")]
        concurrency: usize,
        #[arg(long, default_value_t = 1000, help = "per-ping timeout (ms)")]
        timeout_ms: u64,
        #[arg(long, default_value_t = 45, help = "hard discovery deadline (minutes; must stay < 60)")]
        budget_mins: u64,
        #[arg(long, default_value_t = 4096, help = "subnets larger than this get sampled")]
        big_threshold: u64,
        #[arg(long, default_value_t = 2048, help = "random sample size for oversized subnets")]
        sample: u32,
        #[arg(long, help = "sweep every subnet completely (ignores 1h budget safety)")]
        full: bool,
        #[arg(long, default_value_t = 150, help = "max TTL-walk paths for router discovery (0 disables)")]
        walks: usize,
        #[arg(long, help = "do not auto-seed from local interfaces/routes")]
        no_auto: bool,
        #[arg(long, default_value = "output", help = "output directory")]
        out: PathBuf,
    },
    #[command(about = "fast up/down status sweep of everything in the model (50k in ~1-2min)")]
    Check {
        #[arg(long, value_delimiter = ',')]
        subnets: Option<Vec<String>>,
        #[arg(long, default_value_t = 1500.0)]
        rate: f64,
        #[arg(long, default_value_t = 1024)]
        concurrency: usize,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 200000, help = "cap on total probes per run")]
        max_targets: u64,
        #[arg(long, default_value_t = 115, help = "hard deadline (seconds)")]
        budget_secs: u64,
        #[arg(long, default_value_t = 0, help = "re-probe N times before trusting a down result")]
        confirm_down: u32,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "continuous monitoring: re-sweep on an interval, alert when devices go down")]
    Monitor {
        #[arg(long, default_value_t = 60, help = "seconds between sweep cycles")]
        interval_secs: u64,
        #[arg(long, help = "command to run on DOWN alert; placeholders {ip} {role} {subnet} {state}")]
        exec: Option<String>,
        #[arg(long, value_delimiter = ',')]
        subnets: Option<Vec<String>>,
        #[arg(long, default_value_t = 1500.0)]
        rate: f64,
        #[arg(long, default_value_t = 1024)]
        concurrency: usize,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 200000)]
        max_targets: u64,
        #[arg(long, default_value_t = 115)]
        budget_secs: u64,
        #[arg(long, default_value_t = 1, help = "re-probe N times before alerting a device down")]
        confirm_down: u32,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "regenerate map.html from the stored model")]
    Map {
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "serve the map with clickable Discover/Check/Monitor controls")]
    Serve {
        #[arg(long, default_value_t = 8765)]
        port: u16,
        #[arg(long, help = "do not open the browser automatically")]
        no_open: bool,
        #[arg(long, default_value_t = 60, help = "monitor loop interval when started from the UI")]
        interval_secs: u64,
        #[arg(long, value_delimiter = ',')]
        subnets: Option<Vec<String>>,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "print the IPv4 routing table as seen by the scanner")]
    Routes,
    #[command(about = "print local IPv4 interfaces/subnets")]
    Ifaces,
    #[command(about = "single ICMP probe (debug)")]
    Ping {
        ip: String,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        #[arg(long)]
        ttl: Option<u8>,
        #[arg(long, help = "route through the sweep engine instead of direct backend")]
        engine: bool,
        #[arg(long, default_value_t = 512, requires = "engine")]
        concurrency: usize,
    },
}

fn parse_subnets(v: Option<Vec<String>>) -> Result<Vec<Ipv4Net>> {
    match v {
        None => Ok(Vec::new()),
        Some(parts) => netutil::parse_cidrs(&parts.join(",")),
    }
}

fn print_summary(m: &Model) {
    let (up, down, routers, waps) = m.counts();
    let endpoints = m.devices.iter().filter(|d| d.role == Role::Endpoint).count();
    let sampled = m.subnets.iter().filter(|s| s.sampled).count();
    println!();
    println!("================ summary ================");
    println!(
        "subnets: {} ({} sampled) | address space: {}",
        m.subnets.len(),
        sampled,
        m.subnets.iter().map(|s| s.hosts).sum::<u64>()
    );
    println!(
        "devices: {} total | up: {up} | down: {down} | routers: {routers} | waps: {waps} | endpoints: {endpoints}",
        m.devices.len()
    );
    println!("scan duration: {:.1}s | backend: {}", m.scan_duration_ms as f64 / 1000.0, m.backend);
    let mut downs: Vec<_> = m.devices.iter().filter(|d| d.state == State::Down).collect();
    downs.sort_by_key(|d| std::cmp::Reverse(d.down_since.clone().unwrap_or_default()));
    if !downs.is_empty() {
        println!("recently/known down (first 15):");
        for d in downs.iter().take(15) {
            let extra = match (d.role.label(), d.subnet.as_deref()) {
                ("endpoint", Some(s)) => format!(" [{s}]"),
                (_, Some(s)) => format! (" [{} {s}]", d.role.label()),
                (_, None) => String::new(),
            };
            println!("  {}{}", d.ip, extra);
        }
        if downs.len() > 15 {
            println!("  ... and {} more", downs.len() - 15);
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Discover {
            subnets,
            rate,
            concurrency,
            timeout_ms,
            budget_mins,
            big_threshold,
            sample,
            full,
            walks,
            no_auto,
            out,
        } => {
            if !full && budget_mins >= 60 {
                bail!("--budget-mins must stay under 60 (discovery requirement); use --full to override at your own risk");
            }
            let m = discover::run(discover::Params {
                extra_subnets: parse_subnets(subnets)?,
                full,
                big_threshold,
                sample,
                budget: std::time::Duration::from_secs(budget_mins * 60),
                no_auto,
                scan: engine::ScanParams {
                    rate_pps: rate,
                    concurrency,
                    timeout_ms,
                    payload_len: 32,
                },
                out_dir: out.clone(),
                walk_budget: walks,
            })?;
            let store = db::Db::open(&out.join("ops.db"))?;
            {
                let c = store.lock();
                let prefix: u8 = db::get_setting_or(&c, "site_auto_prefix", "24")
                    .parse()
                    .unwrap_or(24);
                match ops::sync_model(&c, &m, prefix) {
                    Ok(ids) => println!("[*] inventory synced: {} device(s)", ids.len()),
                    Err(e) => eprintln!("[!] inventory sync failed: {e}"),
                }
            }
            print_summary(&m);
        }
        Cmd::Check {
            subnets,
            rate,
            concurrency,
            timeout_ms,
            max_targets,
            budget_secs,
            confirm_down,
            out,
        } => {
            let params = check::Params {
                extra_subnets: parse_subnets(subnets)?,
                scan: engine::ScanParams {
                    rate_pps: rate,
                    concurrency,
                    timeout_ms,
                    payload_len: 32,
                },
                out_dir: out.clone(),
                max_targets,
                budget_secs,
                confirm_down,
            };
            let store = Arc::new(db::Db::open(&out.join("ops.db"))?);
            let (res, stats) = ops::run_cycle(&params, &store)?;
            println!(
                "[ops] up={up} down_root={down} unreachable={unreach} degraded={deg} \
                     events=+{ev} queued={q} in {ms} ms",
                up = stats.up,
                down = stats.down_root,
                unreach = stats.unreachable,
                deg = stats.degraded,
                ev = stats.new_events,
                q = stats.queued,
                ms = stats.duration_ms
            );
            print_summary(&res.model);
        }
        Cmd::Monitor { interval_secs, exec, subnets, rate, concurrency, timeout_ms, max_targets, budget_secs, confirm_down, out } => {
            let store = Arc::new(db::Db::open(&out.join("ops.db"))?);
            jobs::start_housekeeping(Arc::clone(&store));
            jobs::start_webhook_sender(Arc::clone(&store));
            monitor::run(monitor::Params {
                check: check::Params {
                    extra_subnets: parse_subnets(subnets)?,
                    scan: engine::ScanParams {
                        rate_pps: rate,
                        concurrency,
                        timeout_ms,
                        payload_len: 32,
                    },
                    out_dir: out,
                    max_targets,
                    budget_secs,
                    confirm_down,
                },
                interval_secs,
                exec,
            })?;
        }
        Cmd::Map { out } => {
            let path = out.join("model.json");
            let m = Model::load(&path).map_err(|e| anyhow::anyhow!("cannot load {}: {e}", path.display()))?;
            std::fs::create_dir_all(&out)?;
            let html = report::render(&m, 3500)?;
            let dest = out.join("map.html");
            std::fs::write(&dest, html)?;
            println!("[*] wrote {}", dest.display());
        }
        Cmd::Serve { port, no_open, interval_secs, subnets, out } => {
            server::run(server::Params {
                port,
                no_open,
                interval_secs,
                extra_subnets: parse_subnets(subnets)?,
                out_dir: out,
            })?;
        }
        Cmd::Routes => {
            let rt = routes::read();
            println!("{:<20} {:<16} metric", "prefix", "next-hop");
            for r in &rt {
                println!("{:<20} {:<16} {}", r.prefix.to_string(), r.next_hop.map_or("-".into(), |g| g.to_string()), r.metric);
            }
            if rt.is_empty() {
                println!("(no IPv4 routes found)");
            }
        }
        Cmd::Ifaces => {
            let ifs = if_addrs::get_if_addrs()?;
            for i in ifs {
                if let if_addrs::IfAddr::V4(v4) = i.addr {
                    let prefix = netutil::mask_to_prefix(v4.netmask);
                    let net = Ipv4Net::new(v4.ip, prefix).map(|n| n.trunc());
                    println!(
                        "{:<14} {:<16}/{:<2} -> {}",
                        i.name,
                        v4.ip.to_string(),
                        prefix,
                        net.map(|n| n.to_string()).unwrap_or_else(|_| "?".into())
                    );
                }
            }
        }
        Cmd::Ping { ip, timeout_ms, ttl, engine, concurrency } => {
            let ip: std::net::Ipv4Addr = ip.parse()?;
            if engine {
                let targets = vec![engine::Target { ip, ttl }];
                let params = engine::ScanParams {
                    rate_pps: 1000.0,
                    concurrency,
                    timeout_ms,
                    payload_len: 32,
                };
                let t0 = std::time::Instant::now();
                let out = engine::sweep(&targets, &params, None, None)?;
                println!("elapsed {:>7.1}ms | {:?}", t0.elapsed().as_secs_f64() * 1000.0, out[0]);
            } else {
                let mut p = ping::open(timeout_ms, 32)?;
                let t0 = std::time::Instant::now();
                let r = p.ping(ip, ttl);
                println!("elapsed {:>6.1}ms | {:?}", t0.elapsed().as_secs_f64() * 1000.0, r);
            }
        }
    }
    Ok(())
}
