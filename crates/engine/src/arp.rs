use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

pub type MacMap = HashMap<Ipv4Addr, [u8; 6]>;

pub fn read() -> MacMap {
    let mut out = MacMap::new();
    let output = if cfg!(windows) {
        Command::new("arp").arg("-a").output()
    } else {
        Command::new("arp").arg("-an").output()
    };
    let text = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return out,
    };
    for line in text.lines() {
        let line = line.trim();
        let (ip_str, tail) = if let Some(open) = line.find('(') {
            let close = match line[open..].find(')') {
                Some(c) => open + c,
                None => continue,
            };
            (&line[open + 1..close], &line[close + 1..])
        } else {
            let mut ws = line.splitn(2, char::is_whitespace);
            let first = match ws.next() {
                Some(f) => f,
                None => continue,
            };
            let rest = match ws.next() {
                Some(r) => r,
                None => continue,
            };
            (first, rest)
        };
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let mac = tail.split_whitespace().find(|t| {
            t.len() == 17 && (t.as_bytes()[2] == b':' || t.as_bytes()[2] == b'-')
        });
        let mac = match mac {
            Some(m) => m,
            None => continue,
        };
        let octets: Vec<u8> =
            mac.split([':', '-']).filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
        if octets.len() == 6 {
            out.insert(ip, [octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]]);
        }
    }
    out
}
