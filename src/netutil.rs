use anyhow::Result;
use ipnet::Ipv4Net;
use rand::rngs::StdRng;
use rand::seq::index::sample as sample_idx;
use rand::SeedableRng;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub fn parse_cidrs(s: &str) -> Result<Vec<Ipv4Net>> {
    let mut out = Vec::new();
    for part in s.split([',', ' ']).filter(|p| !p.is_empty()) {
        let raw: Ipv4Net = part
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv4 CIDR: '{part}' (example: 10.0.0.0/24)"))?;
        out.push(raw.trunc());
    }
    Ok(out)
}

pub fn bits(n: Ipv4Net) -> u32 {
    u32::from(n.network())
}

pub fn broadcast(n: Ipv4Net) -> u32 {
    bits(n) | (u32::MAX >> n.prefix_len())
}

pub fn host_count(n: Ipv4Net) -> u64 {
    match n.prefix_len() {
        32 => 1,
        31 => 2,
        p => (1u64 << (32 - p as u32)) - 2,
    }
}

pub fn is_scannable(n: Ipv4Net) -> bool {
    let o = n.network().octets();
    if o[0] >= 224 {
        return false;
    }
    if n.network().is_loopback() {
        return false;
    }
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return true;
    }
    n.network().is_private()
}

pub fn gateway_candidates(n: Ipv4Net) -> Vec<Ipv4Addr> {
    let base = bits(n);
    let top = broadcast(n);
    let mut v = vec![Ipv4Addr::from(base + 1)];
    if top > base + 1 {
        v.push(Ipv4Addr::from(top - 1));
    }
    v
}

pub fn host_targets(
    n: Ipv4Net,
    full: bool,
    big_threshold: u64,
    sample_count: u32,
) -> (Vec<Ipv4Addr>, bool) {
    let cnt = host_count(n);
    if full || cnt <= big_threshold {
        return (n.hosts().collect(), false);
    }
    let base = bits(n);
    let top = broadcast(n);
    let first = base + 1;
    let last = top.wrapping_sub(1);
    let mut set: BTreeSet<u32> = BTreeSet::new();
    if n.prefix_len() < 24 {
        for a in first..=(base + 255).min(last) {
            set.insert(a);
        }
        for a in (top.wrapping_sub(255)).max(first)..=last {
            set.insert(a);
        }
    } else {
        set.insert(first);
        set.insert(last);
    }
    let universe = (last - first + 1) as usize;
    let k = (sample_count as usize).min(universe);
    let mut rng = StdRng::from_entropy();
    for idx in sample_idx(&mut rng, universe, k) {
        set.insert(first + idx as u32);
    }
    (set.into_iter().map(Ipv4Addr::from).collect(), true)
}

pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

pub fn shuffle<T>(v: &mut [T]) {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    v.shuffle(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        let n: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert_eq!(host_count(n), 254);
        let (targets, sampled) = host_targets(n, false, 4096, 100);
        assert!(!sampled);
        assert_eq!(targets.len(), 254);
        assert!(targets.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!targets.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!targets.contains(&"192.168.1.255".parse().unwrap()));
    }

    #[test]
    fn sampling_big() {
        let n: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let (targets, sampled) = host_targets(n, false, 4096, 500);
        assert!(sampled);
        assert!(targets.len() >= 500);
        assert!(targets.iter().all(|ip| n.contains(ip)));
    }

    #[test]
    fn scannable() {
        assert!(is_scannable("10.0.0.0/8".parse().unwrap()));
        assert!(is_scannable("172.16.5.0/24".parse().unwrap()));
        assert!(is_scannable("192.168.0.0/16".parse().unwrap()));
        assert!(is_scannable("100.64.0.0/10".parse().unwrap()));
        assert!(!is_scannable("127.0.0.0/8".parse().unwrap()));
        assert!(!is_scannable("224.0.0.0/4".parse().unwrap()));
        assert!(!is_scannable("8.8.8.0/24".parse().unwrap()));
    }

    #[test]
    fn gateways() {
        let n: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        let g = gateway_candidates(n);
        assert!(g.contains(&"192.168.1.1".parse().unwrap()));
        assert!(g.contains(&"192.168.1.254".parse().unwrap()));
    }
}
