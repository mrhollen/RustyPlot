use anyhow::{Context, Result};
use libc::{
    c_void, sockaddr, sockaddr_in, sock_extended_err, socklen_t,
    msghdr, iovec, CMSG_FIRSTHDR, CMSG_DATA, IPPROTO_IP, IP_RECVERR, IP_TTL,
    SOCK_DGRAM, AF_INET, MSG_ERRQUEUE, MSG_DONTWAIT, AF_INET as PF_INET,
    EHOSTUNREACH, ECONNREFUSED,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Maximum number of hops to trace
const MAX_HOPS: u8 = 30;

/// Number of probe attempts per hop
const ATTEMPTS_PER_HOP: u32 = 3;

/// Timeout for each probe attempt
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Base port for UDP traceroute probes (standard: 33434)
const BASE_PORT: u16 = 33434;

/// Size of the UDP probe payload
const PROBE_SIZE: usize = 40;

// ─── Response Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpResponseType {
    /// ICMP Time Exceeded (Type 11) — intermediate router responded
    TimeExceeded,
    /// ICMP Port Unreachable (Type 3, Code 3) — target reached
    PortUnreachable,
}

// ─── Hop Data ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HopData {
    pub hop_number: u8,
    pub ip: IpAddr,
    pub rtts: Vec<f64>,
    pub packets_sent: u32,
    pub packets_received: u32,
}

// ─── Socket Creation ────────────────────────────────────────────────────

/// Create a UDP socket with IP_RECVERR enabled.
/// Returns the raw file descriptor.
fn create_traceroute_socket() -> Result<i32> {
    let fd = unsafe {
        libc::socket(PF_INET, SOCK_DGRAM, 0)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to create UDP socket")?;
    }

    // Enable IP_RECVERR — allows reading ICMP errors from the error queue
    let enable: i32 = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            IP_RECVERR,
            &enable as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::last_os_error())
            .context("Failed to set IP_RECVERR")?;
    }

    Ok(fd)
}

/// Set the TTL on the socket.
fn set_ttl(fd: i32, ttl: i32) -> Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            IP_TTL,
            &ttl as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
            .context(format!("Failed to set TTL to {}", ttl))
    } else {
        Ok(())
    }
}

// ─── Sending Probes ─────────────────────────────────────────────────────

/// Send a UDP probe to the target with the given TTL.
fn send_probe(fd: i32, target: Ipv4Addr, port: u16, payload: &[u8]) -> Result<()> {
    let mut dest = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: port,
        sin_addr: libc::in_addr { s_addr: target.into() },
        sin_zero: [0; 8],
    };
    unsafe { std::ptr::write_bytes(dest.sin_zero.as_mut_ptr(), 0, 8) };

    let ret = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const c_void,
            payload.len(),
            0,
            &dest as *const _ as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
            .context("Failed to send UDP probe")
    } else {
        Ok(())
    }
}

// ─── Reading from Error Queue ───────────────────────────────────────────

/// Read an ICMP error from the socket's error queue using recvmsg.
/// Returns (responder_ip, response_type, rtt_ms) or None if no error available.
fn read_error_queue(fd: i32) -> Result<Option<(IpAddr, IcmpResponseType, f64)>> {
    let mut iov = iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };

    // Control message buffer (needs to be large enough for IP_RECVERR)
    let mut control_buf = [0u8; 256];

    let mut msg = msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control_buf.as_mut_ptr() as *mut c_void,
        msg_controllen: control_buf.len(),
        msg_flags: 0,
    };

    let ret = unsafe {
        libc::recvmsg(fd, &mut msg, MSG_ERRQUEUE | MSG_DONTWAIT)
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => return Ok(None), // EWOULDBLOCK == EAGAIN on Linux
            _ => return Err(err).context("recvmsg failed"),
        }
    }

    // Parse control messages to find IP_RECVERR
    let mut cmsg = unsafe { CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let cmsg_data = unsafe { &*cmsg };

        if cmsg_data.cmsg_level == IPPROTO_IP && cmsg_data.cmsg_type == IP_RECVERR {
            // Parse the sock_extended_err structure
            let serr = unsafe { &*(CMSG_DATA(cmsg) as *const sock_extended_err) };

            // Determine response type:
            // EE_ORIGIN_ICMP — ICMP error (Time Exceeded or Port Unreachable)
            // serr->ee_info contains the original destination address
            // The offending address follows the sock_extended_err struct

            let is_time_exceeded = serr.ee_errno == EHOSTUNREACH as u32; // ICMP Time Exceeded maps to EHOSTUNREACH
            let is_port_unreachable = serr.ee_errno == ECONNREFUSED as u32; // ICMP Port Unreachable maps to ECONNREFUSED on Linux

            let response_type = if is_time_exceeded {
                IcmpResponseType::TimeExceeded
            } else if is_port_unreachable {
                IcmpResponseType::PortUnreachable
            } else {
                // Not a response we care about, continue to next cmsg
                unsafe {
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
                continue;
            };

            // Extract the offending address (the router that sent the ICMP error)
            // It follows the sock_extended_err structure
            let addr_ptr = unsafe {
                ((serr as *const sock_extended_err as *const u8)
                    .add(std::mem::size_of::<sock_extended_err>()))
                    as *const sockaddr_in
            };

            let addr = unsafe { *addr_ptr };
            let responder_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));

            // RTT is calculated by the caller using Instant::elapsed()
            let rtt_ms = 0.0;

            return Ok(Some((responder_ip, response_type, rtt_ms)));
        }

        unsafe {
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok(None)
}

// ─── Main Traceroute Logic ──────────────────────────────────────────────

/// Run a traceroute to the target IP address.
/// Returns `(hops, target_reached)` where `target_reached` indicates if the final destination was contacted.
pub async fn run_traceroute(target: IpAddr) -> Result<(Vec<HopData>, bool)> {
    let target_ip = match target {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(anyhow::anyhow!("IPv6 not yet supported"));
        }
    };

    let mut hops: Vec<HopData> = Vec::new();
    let mut target_reached = false;

    println!("🔍 Starting traceroute to {}...", target);

    let fd = create_traceroute_socket()?;

    for ttl in 1..=MAX_HOPS {
        let mut hop_rtts: Vec<f64> = Vec::new();
        let mut responder_ip: Option<IpAddr> = None;

        // Set TTL for this hop
        set_ttl(fd, ttl as i32)?;

        // Calculate the destination port (standard traceroute uses BASE_PORT + TTL)
        let port = BASE_PORT + ttl as u16;

        // Create a simple payload
        let payload = [ttl; PROBE_SIZE];

        // Send probes and read responses
        for attempt in 1..=ATTEMPTS_PER_HOP {
            let start = std::time::Instant::now();

            // Send the probe
            if let Err(e) = send_probe(fd, target_ip, port, &payload) {
                eprintln!("Send error at hop {}, attempt {}: {}", ttl, attempt, e);
                continue;
            }

            // Wait for response with timeout
            let timeout = PROBE_TIMEOUT;
            let _deadline = start + timeout;

            loop {
                if start.elapsed() >= timeout {
                    break; // Timeout
                }

                match read_error_queue(fd)? {
                    Some((ip, response_type, _rtt)) => {
                        let rtt = start.elapsed().as_secs_f64() * 1000.0;
                        hop_rtts.push(rtt);
                        responder_ip = Some(ip);

                        if response_type == IcmpResponseType::PortUnreachable {
                            target_reached = true;
                        }
                        break;
                    }
                    None => {
                        // No error yet, wait a bit
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }

            if target_reached {
                break;
            }

            // Small delay between attempts
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Build the hop data
        let hop = if let Some(ip) = responder_ip {
            HopData {
                hop_number: ttl,
                ip,
                rtts: hop_rtts.clone(),
                packets_sent: ATTEMPTS_PER_HOP,
                packets_received: hop_rtts.len() as u32,
            }
        } else {
            HopData {
                hop_number: ttl,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                rtts: Vec::new(),
                packets_sent: ATTEMPTS_PER_HOP,
                packets_received: 0,
            }
        };

        // Print hop info
        if hop.rtts.is_empty() {
            println!("Hop {}: * (timeout)", ttl);
        } else {
            let avg_rtt: f64 = hop.rtts.iter().sum::<f64>() / hop.rtts.len() as f64;
            println!(
                "Hop {}: {} — {:.1}ms avg",
                ttl,
                hop.ip,
                avg_rtt
            );
        }

        hops.push(hop);

        // Early termination: if last 3 hops all timed out, stop
        if hops.len() >= 3 {
            let last_3: Vec<&HopData> = hops.iter().rev().take(3).collect();
            if last_3.iter().all(|h| h.rtts.is_empty()) {
                println!("⚠️  3 consecutive timeouts — stopping early");
                break;
            }
        }

        if target_reached {
            break;
        }
    }

    // Close the socket
    unsafe { libc::close(fd) };

    if target_reached {
        println!("✅ Target reached at hop {}", hops.last().unwrap().hop_number);
    }
    println!("Total hops discovered: {}", hops.len());
    Ok((hops, target_reached))
}
