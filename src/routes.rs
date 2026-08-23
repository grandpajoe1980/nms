use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct RouteRec {
    pub prefix: Ipv4Net,
    pub next_hop: Option<Ipv4Addr>,
    pub metric: u32,
}

pub fn read() -> Vec<RouteRec> {
    read_os()
}

#[cfg(not(windows))]
fn parse_hex_addr(h: &str) -> Option<Ipv4Addr> {
    if h.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
    }
    bytes.reverse();
    Some(Ipv4Addr::from(bytes))
}

#[cfg(windows)]
fn read_os() -> Vec<RouteRec> {
    const AF_INET: u16 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrIn6 {
        family: u16,
        port: u16,
        flow: u32,
        addr: [u8; 16],
        scope: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union SinUn {
        v4: SockaddrIn,
        v6: SockaddrIn6,
        family: u16,
    }

    use SinUn as SockaddrInet;

    impl SockaddrInet {
        fn family_of(&self) -> u16 {
            unsafe { self.family }
        }
    }

    #[repr(C)]
    struct AddrPrefix {
        prefix: SockaddrInet,
        len: u8,
    }

    #[repr(C)]
    struct NetLuid(u64);

    #[repr(C)]
    struct Row {
        luid: NetLuid,
        index: u32,
        dest: AddrPrefix,
        nexthop: SockaddrInet,
        site_len: u8,
        valid: u32,
        pref: u32,
        metric: u32,
        protocol: u32,
        loopback: u8,
        autoconf: u8,
        publish: u8,
        immortal: u8,
        age: u32,
        origin: u32,
    }

    #[repr(C)]
    struct Table {
        num: u32,
        rows: [Row; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIpForwardTable2(family: u16, table: *mut *mut Table) -> u32;
        fn FreeMibTable(p: *mut std::os::raw::c_void);
    }

    unsafe fn v4(sa: &SockaddrInet) -> Option<Ipv4Addr> {
        if sa.family_of() == AF_INET {
            Some(Ipv4Addr::from(unsafe { sa.v4.addr }.to_le_bytes()))
        } else {
            None
        }
    }

    let mut out = Vec::new();
    let mut table: *mut Table = std::ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if rc != 0 || table.is_null() {
        return out;
    }
    unsafe {
        let t = &*table;
        let rows = std::slice::from_raw_parts(t.rows.as_ptr(), t.num as usize);
        for row in rows {
            let dst = match v4(&row.dest.prefix) {
                Some(d) => d,
                None => continue,
            };
            let plen = row.dest.len.min(32);
            let prefix = match Ipv4Net::new(dst, plen) {
                Ok(p) => p.trunc(),
                Err(_) => continue,
            };
            let nh = v4(&row.nexthop).filter(|ip| !ip.is_unspecified());
            out.push(RouteRec { prefix, next_hop: nh, metric: row.metric });
        }
        FreeMibTable(table as *mut std::os::raw::c_void);
    }
    out
}

#[cfg(not(windows))]
fn read_os() -> Vec<RouteRec> {
    let mut out = Vec::new();
    if let Ok(body) = std::fs::read_to_string("/proc/net/route") {
        for line in body.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 {
                continue;
            }
            let dest = match parse_hex_addr(cols[1]) {
                Some(a) => a,
                None => continue,
            };
            let mask = match parse_hex_addr(cols[7]) {
                Some(m) => m,
                None => continue,
            };
            let gw = parse_hex_addr(cols[2]).filter(|ip| !ip.is_unspecified());
            let metric = cols[6].parse().unwrap_or(0);
            if let Ok(prefix) = Ipv4Net::new(dest, crate::netutil::mask_to_prefix(mask)) {
                out.push(RouteRec { prefix: prefix.trunc(), next_hop: gw, metric });
            }
        }
    }
    if out.is_empty() {
        if let Ok(body) = std::process::Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
            let text = String::from_utf8_lossy(&body.stdout);
            for line in text.lines().skip(2) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 2 {
                    continue;
                }
                if cols[0] == "default" {
                    if let Ok(gw) = cols[1].parse::<Ipv4Addr>() {
                        out.push(RouteRec {
                            prefix: "0.0.0.0/0".parse().unwrap(),
                            next_hop: Some(gw),
                            metric: 0,
                        });
                    }
                    continue;
                }
                if let Ok(p) = cols[0].parse::<Ipv4Net>() {
                    let gw = cols.get(1).and_then(|g| g.parse::<Ipv4Addr>().ok());
                    out.push(RouteRec { prefix: p.trunc(), next_hop: gw, metric: 0 });
                }
            }
        }
    }
    out
}
