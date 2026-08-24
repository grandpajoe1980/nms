use crate::ping;
use anyhow::Result;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<String>,
    pub reached: bool,
    pub rtt_ms: Option<f64>,
}

/// ICMP traceroute using per-probe TTLs. Stops when the target answers or
/// after `silent_streak` consecutive silent hops.
pub fn trace_path(
    ip: Ipv4Addr,
    max_hops: u8,
    timeout_ms: u64,
    silent_streak_max: u8,
) -> Result<Vec<Hop>> {
    let mut pinger = ping::open(timeout_ms, 64)?;
    let mut hops: Vec<Hop> = Vec::new();
    let mut silent: u8 = 0;
    for ttl in 1..=max_hops.max(1) {
        let r = pinger.ping(ip, Some(ttl));
        if r.up {
            hops.push(Hop {
                ttl,
                ip: Some(r.responder.map(|i| i.to_string()).unwrap_or_else(|| ip.to_string())),
                reached: true,
                rtt_ms: r.rtt_ms,
            });
            return Ok(hops);
        }
        match r.responder {
            Some(hop_ip) => {
                if hop_ip == ip {
                    hops.push(Hop { ttl, ip: Some(hop_ip.to_string()), reached: true, rtt_ms: r.rtt_ms });
                    return Ok(hops);
                }
                silent = 0;
                hops.push(Hop { ttl, ip: Some(hop_ip.to_string()), reached: false, rtt_ms: r.rtt_ms });
            }
            None => {
                silent += 1;
                hops.push(Hop { ttl, ip: None, reached: false, rtt_ms: None });
                if silent >= silent_streak_max {
                    break;
                }
            }
        }
    }
    Ok(hops)
}
