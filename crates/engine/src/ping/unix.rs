use super::{Pinger, RawResult};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

pub struct UnixIcmp {
    sock: Socket,
    timeout: Duration,
    ident: u16,
    seq: u16,
    payload: Vec<u8>,
}

impl UnixIcmp {
    pub fn new(timeout_ms: u64, payload_len: usize) -> anyhow::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))?;
        sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        sock.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let ident = (std::process::id() as u16) ^ (std::process::id() as u16 >> 8) ^ 0x4E4D;
        let mut payload = vec![0u8; payload_len.max(8)];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        Ok(UnixIcmp { sock, timeout: Duration::from_millis(timeout_ms), ident, seq: 0, payload })
    }

    fn build_packet(&mut self) -> Vec<u8> {
        self.seq = self.seq.wrapping_add(1);
        let mut pkt = Vec::with_capacity(8 + self.payload.len());
        pkt.push(8);
        pkt.push(0);
        pkt.extend_from_slice(&self.ident.to_be_bytes());
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        pkt.extend_from_slice(&self.payload);
        let mut sum = 0u32;
        for chunk in pkt.chunks(2) {
            let w = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                (chunk[0] as u16) << 8
            };
            sum = sum.wrapping_add(w as u32);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
        pkt
    }
}

impl Pinger for UnixIcmp {
    fn ping(&mut self, ip: Ipv4Addr, ttl: Option<u8>) -> RawResult {
        let _ = self.sock.set_ttl(ttl.unwrap_or(128) as u32);
        let pkt = self.build_packet();
        let dst = SocketAddr::V4(SocketAddrV4::new(ip, 0));
        if self.sock.send_to(&pkt, &dst).is_err() {
            return RawResult::down();
        }
        let deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; 1500];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return RawResult::down();
            }
            let _ = self.sock.set_read_timeout(Some(deadline - now));
            match self.sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    if n < 8 {
                        continue;
                    }
                    let responder = match src.as_socket_ipv4() {
                        Some(v4) => *v4.ip(),
                        None => continue,
                    };
                    let mut start = 0usize;
                    if n > 20 && (buf[0] & 0xF0) == 0x40 && buf[9] == 1 {
                        start = ((buf[0] & 0x0F) as usize) * 4;
                        if n < start + 8 {
                            continue;
                        }
                    }
                    let icmp = &buf[start..n];
                    let mtype = icmp[0];
                    if mtype == 0 {
                        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
                        if id != self.ident {
                            continue;
                        }
                        return RawResult {
                            up: true,
                            rtt_ms: Some(self.timeout.as_secs_f64() * 1000.0
                                - (deadline - Instant::now()).as_secs_f64() * 1000.0),
                            reply_ttl: None,
                            responder: Some(responder),
                        };
                    } else if mtype == 11 {
                        return RawResult {
                            up: false,
                            rtt_ms: None,
                            reply_ttl: None,
                            responder: Some(responder),
                        };
                    }
                }
                Err(_) => return RawResult::down(),
            }
        }
    }
}
