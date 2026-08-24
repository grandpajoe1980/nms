use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// Ports probed during deep discovery / diagnostics.
pub const PROFILE_PORTS: &[u16] = &[
    22,    // ssh
    53,    // dns
    80,    // http
    443,   // https
    445,   // smb
    631,   // ipp
    1433,  // mssql
    3306,  // mysql
    3389,  // rdp
    5000,  // synology/dlna
    5432,  // postgres
    8080,  // http-alt
    8443,  // https-alt
    9100,  // raw printing
];

const TIMEOUT_MS: u64 = 250;

pub fn tcp_open(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    let addr = std::net::SocketAddr::new(IpAddr::V4(ip), port);
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

/// Probe a fixed port list concurrently; returns the open ones in order.
pub fn scan_ports(ip: Ipv4Addr, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    let open: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for &p in ports {
            let open = &open;
            s.spawn(move || {
                if tcp_open(ip, p, timeout_ms) {
                    open.lock().unwrap().push(p);
                }
            });
        }
    });
    let mut v = open.into_inner().unwrap();
    v.sort_unstable();
    v
}

pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    match dns_lookup::lookup_addr(&IpAddr::V4(ip)) {
        Ok(name) if !name.is_empty() && name != ip.to_string() => Some(name),
        _ => None,
    }
}

// ------------------------------------------------------- classification

/// Vendor prefixes useful for endpoint classification (beyond wifi/router).
const CLASSES: &[(&str, &str)] = &[
    // Apple (many prefixes; representative set)
    ("f0:18:98", "apple"),
    ("a4:83:e7", "apple"),
    ("ac:bc:32", "apple"),
    ("d0:03:4b", "apple"),
    ("fc:fb:fb", "apple"),
    ("14:99:e2", "apple"),
    ("8c:85:90", "apple"),
    ("40:b0:fa", "apple"),
    // phones / tablets
    ("48:d7:05", "samsung"),
    ("8c:77:12", "samsung"),
    ("00:16:32", "samsung"),
    ("f8:e9:4e", "htc"),
    ("84:a6:c8", "xiaomi"),
    ("64:09:80", "xiaomi"),
    ("c0:ee:fb", "xiaomi"),
    // IoT / hobbyist
    ("24:0a:c4", "espressif"),
    ("30:ae:a4", "espressif"),
    ("bc:dd:c2", "espressif"),
    ("5c:cf:7f", "espressif"),
    ("68:c6:3a", "tuya"),
    ("d8:f1:5b", "tuya"),
    ("b8:27:eb", "raspberry-pi"),
    ("dc:a6:32", "raspberry-pi"),
    ("e4:5f:01", "raspberry-pi"),
    ("00:e0:4c", "realtek-iot"),
    // printers
    ("00:1e:4f", "printer-hp"),
    ("b0:5a:da", "printer-hp"),
    ("f4:39:09", "printer-hp"),
    ("00:80:77", "printer-brother"),
    ("28:cd:c1", "printer-brother"),
    ("00:00:48", "printer-epson"),
    ("b8:9a:8a", "printer-canon"),
    // NAS
    ("00:11:32", "nas-synology"),
    ("90:09:d0", "nas-synology"),
    ("00:08:9b", "nas-qnap"),
    ("24:5e:be", "nas-qnap"),
    ("00:14:ee", "nas-wd"),
];

fn mac_prefix(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(format!("{}:{}:{}", parts[0], parts[1], parts[2]).to_lowercase())
}

pub fn vendor_hint(mac: Option<&str>) -> Option<&'static str> {
    let prefix = mac_prefix(mac?)?;
    for (p, vendor) in crate::oui::WIFI.iter().chain(crate::oui::ROUTERS).chain(CLASSES) {
        if *p == prefix {
            return Some(vendor);
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub hostname: Option<String>,
    pub device_class: String,
    pub open_ports: Vec<u16>,
}

/// Best-effort endpoint profiling from passive data + light TCP probes.
pub fn profile_endpoint(ip: Ipv4Addr, mac: Option<&str>, role: &str) -> Profile {
    let hostname = reverse_dns(ip);
    let open_ports = scan_ports(ip, PROFILE_PORTS, TIMEOUT_MS);
    let device_class = classify(mac, role, hostname.as_deref(), &open_ports);
    Profile { hostname, device_class, open_ports }
}

fn has(ports: &[u16], p: u16) -> bool {
    ports.contains(&p)
}

pub fn classify(
    mac: Option<&str>,
    role: &str,
    hostname: Option<&str>,
    open_ports: &[u16],
) -> String {
    if role == "router" || role == "wap" {
        return role.to_string();
    }
    let vendor = vendor_hint(mac).unwrap_or("");
    let host = hostname.unwrap_or("").to_lowercase();

    if vendor.starts_with("printer")
        || has(open_ports, 9100)
        || has(open_ports, 631)
        || host.contains("printer")
        || host.contains("hp ")
        || host.contains("epson")
        || host.contains("brother")
        || host.contains("canon")
    {
        return "printer".into();
    }
    if vendor.starts_with("nas") || host.contains("nas") || host.contains("diskstation")
        || host.contains("synology") || host.contains("qnap")
    {
        return "nas".into();
    }
    if has(open_ports, 3389) || has(open_ports, 445) || host.contains("desktop") {
        return "computer".into();
    }
    if has(open_ports, 22) && !has(open_ports, 80) && !has(open_ports, 443) {
        return "server".into();
    }
    if has(open_ports, 80) || has(open_ports, 443) || has(open_ports, 8080) {
        if vendor == "raspberry-pi" || host.contains("pi") || host.contains("server") {
            return "server".into();
        }
        return "appliance".into();
    }
    match vendor {
        "espressif" | "tuya" | "realtek-iot" => return "iot".into(),
        "raspberry-pi" => return "server".into(),
        "apple" | "samsung" | "htc" | "xiaomi" => {
            if host.contains("iphone") || host.contains("ipad") || host.contains("android") {
                return "mobile".into();
            }
            if host.contains("tv") || host.contains("tv-") {
                return "tv".into();
            }
            return "mobile".into();
        }
        _ => {}
    }
    if !host.is_empty() {
        return "computer".into();
    }
    "unknown".into()
}

/// Ports a device class should be serving; deviations surface as
/// "missing services" in diagnostics (functional health beyond reachability).
pub fn expected_services(class: &str) -> &'static [u16] {
    match class {
        "printer" => &[631, 9100],
        "nas" => &[445],
        "server" => &[22],
        "computer" => &[445],
        _ => &[],
    }
}

pub fn missing_expected(class: &str, open: &[u16]) -> Vec<u16> {
    expected_services(class)
        .iter()
        .filter(|p| !open.contains(p))
        .copied()
        .collect()
}

/// Human-readable summary appended to hints.
pub fn summarize(p: &Profile) -> String {
    let mut s = String::new();
    if let Some(h) = &p.hostname {
        s.push_str(h);
    }
    if p.device_class != "unknown" && p.device_class != "computer" {
        if !s.is_empty() {
            s.push_str(" · ");
        }
        s.push_str(&p.device_class);
    }
    if !p.open_ports.is_empty() {
        let ports: Vec<String> = p.open_ports.iter().map(|x| x.to_string()).collect();
        s.push_str(&format!(" · ports {}", ports.join(",")));
    }
    s
}

/// Convenience map used by diagnostics output.
pub fn service_names() -> HashMap<u16, &'static str> {
    HashMap::from([
        (22, "ssh"),
        (53, "dns"),
        (80, "http"),
        (443, "https"),
        (445, "smb"),
        (631, "ipp"),
        (1433, "mssql"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5000, "dlna/nas"),
        (5432, "postgres"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (9100, "raw-print"),
    ])
}
