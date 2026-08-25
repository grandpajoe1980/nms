
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use engine::model::{Model, Role, State};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Subcommand)]
enum UserAction {
    Add {
        username: String,
        #[arg(long, default_value = "operator")]
        role: String,
        #[arg(long, help = "password (visible in process list; prefer interactive prompt)")]
        password: Option<String>,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    List {
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    Disable {
        username: String,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    Add {
        name: String,
        #[arg(long, default_value = "automation")]
        role: String,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    List {
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
}

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
        #[arg(long, help = "profile live endpoints: names, open ports, device class")]
        deep: bool,
        #[arg(long, default_value_t = 30, help = "retire inventory devices unseen this many days")]
        retire_days: u64,
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
    #[command(about = "deep inspection pass over live devices: SNMP identity + interfaces + LLDP/CDP neighbors")]
    Inspect {
        #[arg(long, default_value = "public")]
        community: String,
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 161)]
        port: u16,
        #[arg(long, default_value_t = 0, help = "cap devices inspected (0 = all live)")]
        max_devices: usize,
        #[arg(long, help = "opt in to read-only SSH config backup during inspect")]
        config_backup: bool,
        #[arg(long, requires = "config_backup", help = "SSH username (non-secret reference)")]
        ssh_username: Option<String>,
        #[arg(long, requires = "config_backup", help = "opaque vault credential reference")]
        ssh_credential_ref: Option<String>,
        #[arg(long, requires = "config_backup", help = "path to strict SSH known_hosts file")]
        ssh_known_hosts: Option<PathBuf>,
        #[arg(long, default_value_t = 22, requires = "config_backup")]
        ssh_port: u16,
        #[arg(long, default_value_t = 5000, requires = "config_backup")]
        ssh_timeout_ms: u64,
        #[arg(long, default_value = "cisco-ios-xe", requires = "config_backup", help = "config command profile: cisco-ios-xe|aruba-aos-cx")]
        config_profile: String,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },    #[command(about = "regenerate map.html from the stored model")]
    Map {
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "serve the map with clickable Discover/Check/Monitor controls")]
    Serve {
        #[arg(long, default_value_t = 8765)]
        port: u16,
        #[arg(long, default_value = "127.0.0.1", help = "bind address (non-loopback forces hardened auth)")]
        bind: String,
        #[arg(long, help = "do not open the browser automatically")]
        no_open: bool,
        #[arg(long, default_value_t = 60, help = "monitor loop interval when started from the UI")]
        interval_secs: u64,
        #[arg(long, value_delimiter = ',')]
        subnets: Option<Vec<String>>,
        #[arg(long, default_value = "output")]
        out: PathBuf,
    },
    #[command(about = "manage local users for hardened mode")]
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    #[command(about = "manage API bearer tokens for automation")]
    Token {
        #[command(subcommand)]
        action: TokenAction,
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
        Some(parts) => engine::netutil::parse_cidrs(&parts.join(",")),
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
            deep,
            retire_days,
            no_auto,
            out,
        } => {
            if !full && budget_mins >= 60 {
                bail!("--budget-mins must stay under 60 (discovery requirement); use --full to override at your own risk");
            }
            let m = engine::discover::run(engine::discover::Params {
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
                deep,
                retire_days,
            })?;
            let store = engine::db::Db::open(&out.join("ops.db"))?;
            {
                let c = store.lock();
                let prefix: u8 = engine::db::get_setting_or(&c, "site_auto_prefix", "24")
                    .parse()
                    .unwrap_or(24);
                match engine::ops::sync_model(&c, &m, prefix) {
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
            let params = engine::check::Params {
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
            let store = Arc::new(engine::db::Db::open(&out.join("ops.db"))?);
            let (res, stats) = engine::ops::run_cycle(&params, &store)?;
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
            let store = Arc::new(engine::db::Db::open(&out.join("ops.db"))?);
            engine::jobs::start_housekeeping(Arc::clone(&store));
            engine::jobs::start_webhook_sender(Arc::clone(&store));
            engine::jobs::start_report_writer(Arc::clone(&store), out.clone());
            engine::monitor::run(engine::monitor::Params {
                check: engine::check::Params {
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
        Cmd::Inspect {
            community,
            timeout_ms,
            port,
            max_devices,
            config_backup,
            ssh_username,
            ssh_credential_ref,
            ssh_known_hosts,
            ssh_port,
            ssh_timeout_ms,
            config_profile,
            out,
        } => {
            let store = Arc::new(engine::db::Db::open(&out.join("ops.db"))?);
            let config_request = if config_backup {
                let username = ssh_username.ok_or_else(|| anyhow::anyhow!("--ssh-username is required with --config-backup"))?;
                let credential_ref = ssh_credential_ref.ok_or_else(|| anyhow::anyhow!("--ssh-credential-ref is required with --config-backup"))?;
                let known_hosts_path = ssh_known_hosts.ok_or_else(|| anyhow::anyhow!("--ssh-known-hosts is required with --config-backup"))?;
                Some(engine::inspect::ConfigBackupRequest {
                    username,
                    credential_ref,
                    vault_dir: out.clone(),
                    known_hosts_path,
                    port: ssh_port,
                    timeout_ms: ssh_timeout_ms,
                    profile: config_profile.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                })
            } else {
                None
            };
            let stats = engine::inspect::run_with_config(&store, &out, &community, timeout_ms, port, max_devices, config_request)?;
            println!(
                "[+] inspect: {} device(s) | snmp {} | interfaces {} | neighbors {} | configs ok={} changed={} failed={} | {} ms",
                stats.devices, stats.snmp_ok, stats.interfaces, stats.neighbors,
                stats.config_ok, stats.config_changed, stats.config_failed, stats.duration_ms
            );
        }
        Cmd::Map { out } => {
            let path = out.join("model.json");
            let m = Model::load(&path).map_err(|e| anyhow::anyhow!("cannot load {}: {e}", path.display()))?;
            std::fs::create_dir_all(&out)?;
            let html = engine::report::render(&m, 3500)?;
            let dest = out.join("map.html");
            std::fs::write(&dest, html)?;
            println!("[*] wrote {}", dest.display());
        }
        Cmd::Serve { port, bind, no_open, interval_secs, subnets, out } => {
            core_api::server::run(core_api::server::Params {
                port,
                bind,
                no_open,
                interval_secs,
                extra_subnets: parse_subnets(subnets)?,
                out_dir: out,
            })?;
        }
        Cmd::User { action } => match action {
            UserAction::Add { username, role, password, out } => {
                engine::auth::Role::parse(&role)?;
                let pass = match password {
                    Some(p) => p,
                    None => {
                        print!("password for {username}: ");
                        use std::io::Write as _;
                        std::io::stdout().flush()?;
                        let mut line = String::new();
                        std::io::stdin().read_line(&mut line)?;
                        line.trim().to_string()
                    }
                };
                if pass.len() < 8 {
                    bail!("password must be at least 8 characters");
                }
                let store = engine::db::Db::open(&out.join("ops.db"))?;
                let c = store.lock();
                if engine::db::get_user(&c, &username)?.is_some() {
                    bail!("user '{username}' already exists");
                }
                let hash = engine::auth::hash_password(&pass)?;
                let id = engine::db::create_user(&c, &username, &hash, &role)?;
                drop(c);
                println!("[+] created user '{username}' (role={role}, id={id})");
            }
            UserAction::List { out } => {
                let store = engine::db::Db::open(&out.join("ops.db"))?;
                let c = store.lock();
                for (name, role, disabled) in engine::db::list_users(&c)? {
                    println!("{name:<24} {role:<12} {}", if disabled { "disabled" } else { "active" });
                }
            }
            UserAction::Disable { username, out } => {
                let store = engine::db::Db::open(&out.join("ops.db"))?;
                let n = engine::db::set_user_disabled(&store.lock(), &username, true)?;
                if n == 0 {
                    bail!("no such user '{username}'");
                }
                println!("[+] disabled '{username}'");
            }
        },
        Cmd::Token { action } => match action {
            TokenAction::Add { name, role, out } => {
                engine::auth::Role::parse(&role)?;
                let (raw, hashed) = engine::auth::new_token();
                let store = engine::db::Db::open(&out.join("ops.db"))?;
                engine::db::add_api_token(&store.lock(), &hashed, &name, &role)?;
                println!("[+] token '{name}' created (role={role})");
                println!("    raw token (shown once, stored hashed): {raw}");
            }
            TokenAction::List { out } => {
                let store = engine::db::Db::open(&out.join("ops.db"))?;
                let c = store.lock();
                let mut stmt = c.prepare("SELECT name, role, disabled, created_ts FROM api_tokens ORDER BY name")?;
                for row in stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
                })? {
                    let (name, role, disabled, ts) = row?;
                    println!(
                        "{name:<24} {role:<12} {} created {}",
                        if disabled != 0 { "disabled" } else { "active" },
                        chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                            .map(|d| d.format("%Y-%m-%d").to_string())
                            .unwrap_or_default()
                    );
                }
            }
        }
        Cmd::Routes => {
            let rt = engine::routes::read();
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
                    let prefix = engine::netutil::mask_to_prefix(v4.netmask);
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
                let mut p = engine::ping::open(timeout_ms, 32)?;
                let t0 = std::time::Instant::now();
                let r = p.ping(ip, ttl);
                println!("elapsed {:>6.1}ms | {:?}", t0.elapsed().as_secs_f64() * 1000.0, r);
            }
        }
    }
    Ok(())
}
