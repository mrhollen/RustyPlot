use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use rand::Rng;

/// Maximum number of hops to trace
const MAX_HOPS: u8 = 30;

/// Number of probe attempts per hop
const ATTEMPTS_PER_HOP: u32 = 3;

/// Timeout for each probe attempt
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Size of the ICMP payload (data after ICMP header)
const ICMP_PAYLOAD_SIZE: usize = 32;

/// Total size of our ICMP Echo Request packet
const ICMP_PACKET_SIZE: usize = 8 + ICMP_PAYLOAD_SIZE; // 8-byte header + payload

/// Types of ICMP responses we care about in traceroute
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpResponseType {
    /// ICMP Time Exceeded (Type 11) — intermediate router responded
    TimeExceeded,
    /// ICMP Echo Reply (Type 0) — target reached
    EchoReply,
}

// ─── ICMP Packet Building ───────────────────────────────────────────────

/// Build an ICMP Echo Request packet.
/// 
/// Format (IPv4):
/// [Type:1][Code:1][Checksum:2][Id:2][Seq:2][Data:32]
/// Total: 40 bytes
pub fn build_icmp_echo_request(ident: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![0u8; ICMP_PACKET_SIZE];
    
    // Type = 8 (Echo Request)
    packet[0] = 8;
    // Code = 0
    packet[1] = 0;
    // Checksum = 0 (filled in later)
    // bytes 2-3: checksum (will be calculated)
    // Identifier
    packet[4] = ((ident >> 8) & 0xFF) as u8;
    packet[5] = (ident & 0xFF) as u8;
    // Sequence number
    packet[6] = ((seq >> 8) & 0xFF) as u8;
    packet[7] = (seq & 0xFF) as u8;
    
    // Fill payload with predictable data (timestamp + pattern)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ts = timestamp.as_nanos() as u64;
    for i in 0..ICMP_PAYLOAD_SIZE {
        packet[8 + i] = ((ts >> (i * 8)) & 0xFF) as u8;
    }
    
    // Calculate and set checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = ((checksum >> 8) & 0xFF) as u8;
    packet[3] = (checksum & 0xFF) as u8;
    
    packet
}

/// Calculate ICMP checksum (one's complement of one's complement sum)
fn calculate_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    
    // Sum all 16-bit words
    while i + 1 < packet.len() {
        let word = (packet[i] as u32) << 8 | (packet[i + 1] as u32);
        sum += word;
        i += 2;
    }
    
    // Handle odd-length packet (shouldn't happen for us, but be safe)
    if i < packet.len() {
        sum += (packet[i] as u32) << 8;
    }
    
    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !sum as u16 & 0xFFFF
}

// ─── ICMP Response Parsing ──────────────────────────────────────────────

/// Parse an ICMP response packet and determine its type.
///
/// For traceroute, we care about two types:
/// - **ICMP Time Exceeded (Type 11)**: An intermediate router dropped our packet
/// - **ICMP Echo Reply (Type 0)**: The target responded directly
///
/// The response packet contains the original Echo Request embedded inside it,
/// which we can use to verify it matches our probe (by checking ident + seq).
fn parse_icmp_response(buffer: &[u8]) -> Option<(IcmpResponseType, u16, u16)> {
    if buffer.len() < 8 {
        return None;
    }

    let icmp_type = buffer[0];
    let _icmp_code = buffer[1];

    // Determine response type
    let response_type = match (icmp_type, _icmp_code) {
        (11, 0) => IcmpResponseType::TimeExceeded, // Time Exceeded, TTL=0
        (0, 0)  => IcmpResponseType::EchoReply,    // Echo Reply
        _ => return None, // Ignore other ICMP types
    };

    // Extract the embedded original packet to verify it matches our probe
    // For Time Exceeded: original IP header starts at offset 8 (after ICMP error header)
    // The ICMP error message contains:
    //   [8 bytes ICMP error header][original IP header + original packet data]
    // The original IPv4 header is typically 20 bytes (IHL=5), so original ICMP starts at offset 28
    // But we need to read the IHL from the original IP header at offset 8

    let original_ip_offset = 8; // Start of embedded original IP header
    if buffer.len() < original_ip_offset + 20 {
        return None;
    }

    // Get original IP header length
    let ihl = (buffer[original_ip_offset] & 0x0F) as usize * 4;
    let original_icmp_offset = original_ip_offset + ihl;

    if buffer.len() < original_icmp_offset + 4 {
        return None;
    }

    // Extract ident and seq from the original ICMP Echo Request
    let ident = (buffer[original_icmp_offset + 4] as u16) << 8 | (buffer[original_icmp_offset + 5] as u16);
    let seq = (buffer[original_icmp_offset + 6] as u16) << 8 | (buffer[original_icmp_offset + 7] as u16);

    Some((response_type, ident, seq))
}

// ─── Raw Socket Creation ────────────────────────────────────────────────

/// Create a raw ICMP socket and set the TTL.
/// 
/// Returns a tokio UdpSocket that can be used for async send/recv.
async fn create_icmp_socket(ttl: u32) -> Result<UdpSocket> {
    // Create a raw ICMP socket
    let sock = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::ICMPV4),
    )
    .context("Failed to create raw ICMP socket. Try running with sudo or check CAP_NET_RAW?")?;

    // Bind to any local address (required for recv_from on raw sockets)
    let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    sock.bind(&local_addr.into())
        .context("Failed to bind socket")?;

    // Set TTL (Time To Live) - this controls how many hops the packet can traverse
    sock.set_ttl(ttl)
        .context("Failed to set socket TTL")?;

    // Set receive timeout so we don't block forever
    sock.set_read_timeout(Some(PROBE_TIMEOUT))
        .context("Failed to set socket read timeout")?;
    
    // Convert to tokio UdpSocket for async operations
    // This works because raw ICMP sockets behave like UDP sockets at the OS level
    let std_socket: std::net::UdpSocket = sock.into();
    let tokio_socket = UdpSocket::from_std(std_socket)?;
    
    Ok(tokio_socket)
}

// ─── Probe Sending ──────────────────────────────────────────────────────

/// Send an ICMP Echo Request to the target and wait for a response.
///
/// Returns the responder IP address, response type, and RTT in milliseconds,
/// or None on timeout.
async fn send_probe(socket: &UdpSocket, target: IpAddr, ident: u16, seq: u16) -> Result<Option<(IpAddr, IcmpResponseType, f64)>> {
    let packet = build_icmp_echo_request(ident, seq);
    let start = std::time::Instant::now();

    // Build target address for send_to
    let target_addr = match target {
        IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
        IpAddr::V6(_) => {
            return Err(anyhow::anyhow!("IPv6 not yet supported"));
        }
    };

    // Send the probe to the target
    socket.send_to(&packet, target_addr).await
        .context("Failed to send ICMP probe")?;

    // Wait for response using recv_from to get the responder's IP
    let mut buffer = vec![0u8; 1500];

    match tokio::time::timeout(PROBE_TIMEOUT, socket.recv_from(&mut buffer)).await {
        Ok(Ok((received_len, from_addr))) => {
            let rtt = start.elapsed().as_secs_f64() * 1000.0; // Convert to milliseconds

            // Parse the ICMP response
            let response = parse_icmp_response(&buffer[..received_len]);

            match response {
                Some((response_type, resp_ident, resp_seq)) => {
                    // Verify this response matches our probe
                    if resp_ident == ident && resp_seq == seq {
                        let responder_ip = from_addr.ip();
                        Ok(Some((responder_ip, response_type, rtt)))
                    } else {
                        // Response doesn't match our probe, ignore it
                        Ok(None)
                    }
                }
                None => {
                    // Unrecognized ICMP type, ignore
                    Ok(None)
                }
            }
        }
        Ok(Err(e)) => {
            // Log the error but don't fail the probe
            eprintln!("Recv error: {}", e);
            Ok(None)
        }
        Err(_timeout) => {
            // Timed out - no response from this hop
            Ok(None)
        }
    }
}

// ─── Public API ─────────────────────────────────────────────────────────

/// Run a traceroute to the target IP address.
///
/// Returns a vector of hops, where each hop contains the responding IP,
/// RTT measurements, and packet loss statistics.
pub async fn run_traceroute(target: IpAddr) -> Result<Vec<HopData>> {
    let ident: u16 = rand::thread_rng().gen();

    // Create socket (binds internally via socket2)
    let socket = create_icmp_socket(1).await?;

    // Quick test: send one probe
    let result = send_probe(&socket, target, ident, 0).await?;
    if let Some((responder_ip, response_type, rtt)) = result {
        println!("Test probe responded: {} (type: {:?}, RTT: {:.1}ms)", responder_ip, response_type, rtt);
    } else {
        println!("Test probe timed out");
    }

    Ok(Vec::new())
}

/// Data collected for a single hop in the traceroute path.
#[derive(Debug, Clone)]
pub struct HopData {
    pub hop_number: u8,
    pub ip: IpAddr,
    pub rtts: Vec<f64>,       // RTT measurements in milliseconds
    pub packets_sent: u32,
    pub packets_received: u32,
}
