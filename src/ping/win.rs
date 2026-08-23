use super::{Pinger, RawResult};
use std::net::Ipv4Addr;
use std::os::raw::c_void;

type Handle = *mut c_void;

#[repr(C)]
struct IcmpOptions {
    ttl: u8,
    tos: u8,
    flags: u8,
    options_size: u8,
    options_data: *mut u8,
}

#[repr(C)]
struct IcmpEchoReply {
    address: u32,
    status: u32,
    rtt_ms: u32,
    data_size: u16,
    reserved: u16,
    data_ptr: *mut u8,
    options: IcmpOptions,
    data: u8,
}

#[repr(align(8))]
struct ReplyBuf([u8; REPLY_SIZE]);

const PAYLOAD: [u8; 32] = *b"abcdefghijklmnopqrstuvwabcdefghi";
const REPLY_SIZE: usize = 48 + PAYLOAD.len() + 64;

const IP_SUCCESS: u32 = 0;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;

#[link(name = "iphlpapi")]
extern "system" {
    fn IcmpCreateFile() -> Handle;
    fn IcmpCloseHandle(handle: Handle) -> i32;
    fn IcmpSendEcho(
        handle: Handle,
        dest: u32,
        data: *const u8,
        size: u16,
        opts: *mut IcmpOptions,
        reply: *mut u8,
        reply_size: u32,
        timeout: u32,
    ) -> u32;
}

pub struct WinIcmp {
    handle: Handle,
    timeout_ms: u64,
    opts: IcmpOptions,
    buf: Box<ReplyBuf>,
}

unsafe impl Send for WinIcmp {}

impl WinIcmp {
    pub fn new(timeout_ms: u64) -> anyhow::Result<Self> {
        let handle = unsafe { IcmpCreateFile() };
        if handle.is_null() {
            anyhow::bail!("IcmpCreateFile failed");
        }
        Ok(WinIcmp {
            handle,
            timeout_ms,
            opts: IcmpOptions {
                ttl: 128,
                tos: 0,
                flags: 0,
                options_size: 0,
                options_data: std::ptr::null_mut(),
            },
            buf: Box::new(ReplyBuf([0u8; REPLY_SIZE])),
        })
    }
}

impl Drop for WinIcmp {
    fn drop(&mut self) {
        unsafe { IcmpCloseHandle(self.handle) };
    }
}

impl Pinger for WinIcmp {
    fn ping(&mut self, ip: Ipv4Addr, ttl: Option<u8>) -> RawResult {
        self.opts.ttl = ttl.unwrap_or(128);
        let dest = u32::from_le_bytes(ip.octets());
        let ret = unsafe {
            IcmpSendEcho(
                self.handle,
                dest,
                PAYLOAD.as_ptr(),
                PAYLOAD.len() as u16,
                &mut self.opts,
                self.buf.0.as_mut_ptr(),
                REPLY_SIZE as u32,
                self.timeout_ms as u32,
            )
        };
        if ret == 0 {
            return RawResult::down();
        }
        let reply = unsafe { &*(self.buf.0.as_ptr() as *const IcmpEchoReply) };
        let status = reply.status;
        let responder = Ipv4Addr::from(reply.address.to_le_bytes());
        if status == IP_SUCCESS {
            RawResult {
                up: true,
                rtt_ms: Some(reply.rtt_ms as f64),
                reply_ttl: Some(reply.options.ttl),
                responder: Some(responder),
            }
        } else if status == IP_TTL_EXPIRED_TRANSIT {
            RawResult { up: false, rtt_ms: None, reply_ttl: None, responder: Some(responder) }
        } else {
            RawResult::down()
        }
    }
}
