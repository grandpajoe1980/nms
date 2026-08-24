#[cfg(windows)]
pub mod win;
#[cfg(unix)]
pub mod unix;

#[derive(Clone, Copy, Debug)]
pub struct RawResult {
    pub up: bool,
    pub rtt_ms: Option<f64>,
    pub reply_ttl: Option<u8>,
    pub responder: Option<std::net::Ipv4Addr>,
}

impl RawResult {
    pub fn down() -> Self {
        RawResult { up: false, rtt_ms: None, reply_ttl: None, responder: None }
    }
}

pub trait Pinger: Send {
    fn ping(&mut self, ip: std::net::Ipv4Addr, ttl: Option<u8>) -> RawResult;
}

#[cfg(windows)]
pub fn open(timeout_ms: u64, _payload_len: usize) -> anyhow::Result<Box<dyn Pinger>> {
    Ok(Box::new(win::WinIcmp::new(timeout_ms)?))
}

#[cfg(unix)]
pub fn open(timeout_ms: u64, payload_len: usize) -> anyhow::Result<Box<dyn Pinger>> {
    Ok(Box::new(unix::UnixIcmp::new(timeout_ms, payload_len)?))
}

pub fn backend_name() -> &'static str {
    if cfg!(windows) {
        "windows-icmp (iphlpapi IcmpSendEcho)"
    } else {
        "unix-icmp (datagram/raw socket)"
    }
}
