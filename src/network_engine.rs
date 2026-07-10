//! TCP-based traceroute and continuous ping engine using surge-ping crate.
//! No sudo required - uses ICMP packets with configurable TTL for traceroute.
//!
//! Note: On Linux, ICMP sockets work without sudo due to kernel capabilities.
//! For true TCP-based traceroute, you would need raw socket capabilities.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use log::{debug, info, warn};
use rand::random;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::app_state::AppState;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};

/// Represents a single hop in the traceroute
#[derive(Debug, Clone)]
pub struct Hop {
    pub hop_number: u8,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    /// Rolling buffer of last 100 RTT measurements (in milliseconds)
    pub rtts: Vec<f64>,
    /// Total packets sent to this hop
    pub packets_sent: u32,
    /// Total packets received (successful responses)
    pub packets_received: u32,
}

impl Hop {
    /// Create a new hop entry with the given hop number and IP address
    pub fn new(hop_number: u8, ip: IpAddr) -> Self {
        Self {
            hop_number,
            ip,
            hostname: None, // Reverse DNS lookup requires additional dependencies
            rtts: Vec::with_capacity(100),
            packets_sent: 0,
            packets_received: 0,
        }
    }

    /// Create a new hop with an optional hostname
    #[allow(dead_code)]
    pub fn with_hostname(hop_number: u8, ip: IpAddr, hostname: Option<String>) -> Self {
        Self {
            hop_number,
            ip,
            hostname,
            rtts: Vec::with_capacity(100),
            packets_sent: 0,
            packets_received: 0,
        }
    }

    /// Calculate packet loss percentage
    pub fn loss_percentage(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        ((self.packets_sent - self.packets_received) as f64 / self.packets_sent as f64) * 100.0
    }

    /// Calculate average jitter (mean absolute difference between consecutive RTTs)
    #[allow(dead_code)]
    pub fn jitter(&self) -> f64 {
        if self.rtts.len() < 2 {
            return 0.0;
        }
        let mut total_diff = 0.0;
        for i in 1..self.rtts.len() {
            total_diff += (self.rtts[i] - self.rtts[i - 1]).abs();
        }
        total_diff / (self.rtts.len() - 1) as f64
    }

    /// Get min/avg/max RTT statistics
    pub fn rtt_stats(&self) -> (Option<f64>, Option<f64>, Option<f64>) {
        if self.rtts.is_empty() {
            return (None, None, None);
        }
        let min = self.rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = self.rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = self.rtts.iter().sum::<f64>() / self.rtts.len() as f64;
        (Some(min), Some(avg), Some(max))
    }

    /// Add a new RTT measurement, maintaining rolling buffer of 100
    pub fn add_rtt(&mut self, rtt_ms: f64) {
        if self.rtts.len() >= 100 {
            self.rtts.remove(0);
        }
        self.rtts.push(rtt_ms);
    }

    /// Check if this hop is considered "alive" (has received at least one response)
    #[allow(dead_code)]
    pub fn is_alive(&self) -> bool {
        self.packets_received > 0
    }
}

/// Main network engine that manages traceroute and continuous pinging
pub struct NetworkEngine {
    target: String,
    hops: Vec<Hop>,
    is_running: bool,
    /// Handle to the tokio task doing continuous pinging
    ping_handle: Option<JoinHandle<()>>,
}

impl NetworkEngine {
    /// Initialize a new NetworkEngine with the target hostname or IP address
    pub fn new(target: String) -> Self {
        debug!("Creating NetworkEngine for target: {}", target);
        Self {
            target,
            hops: Vec::new(),
            is_running: false,
            ping_handle: None,
        }
    }

    /// Perform traceroute to discover hops to the target
    ///
    /// Uses ICMP packets with increasing TTL values.
    /// Maximum 30 hops, 2 attempts per hop, 500ms timeout per attempt.
    /// Optimized for responsiveness: early exit after first failed attempt.
    pub async fn traceroute(&mut self) -> Result<()> {
        info!("Starting traceroute to {}", self.target);

        // Clear previous hops
        self.hops.clear();

        // Resolve target to IP address first
        let target_ip = self.resolve_target(&self.target).await?;
        info!("Resolved target to: {}", target_ip);

        // Perform traceroute with increasing TTL
        self.traceroute_icmp(target_ip).await?;

        // If we discovered hops, add the final target as the last hop if not already present
        if !self.hops.is_empty() {
            let last_hop_ip = self.hops.last().unwrap().ip;
            if last_hop_ip != target_ip {
                // Target was reached, add it as final hop
                let hop_number = (self.hops.len() + 1) as u8;
                self.hops.push(Hop::new(hop_number, target_ip));
            }
        }

        info!("Traceroute complete. Discovered {} hops", self.hops.len());
        Ok(())
    }

    /// Resolve a hostname to an IP address
    async fn resolve_target(&self, target: &str) -> Result<IpAddr> {
        // Check if target is already an IP address
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Try to resolve as hostname
        match tokio::net::lookup_host(format!("{}:80", target)).await {
            addrs => {
                let mut addrs = addrs?;
                if let Some(addr) = addrs.next() {
                    Ok(addr.ip())
                } else {
                    Err(anyhow!("No IP address found for target: {}", target))
                }
            }
        }
    }

    /// Perform ICMP-based traceroute using increasing TTL
    ///
    /// Optimized for responsiveness:
    /// - 500ms timeout per attempt (instead of 2s)
    /// - 2 attempts per hop (instead of 3)
    /// - Early exit: if first attempt fails, immediately try next hop
    /// - Only do second attempt if first succeeds but we haven't reached target
    async fn traceroute_icmp(&mut self, target: IpAddr) -> Result<()> {
        const MAX_HOPS: u8 = 30;
        const ATTEMPTS_PER_HOP: u32 = 3;
        const TIMEOUT: Duration = Duration::from_secs(2);
        const PAYLOAD: &[u8] = b"traceroute";

        // Determine ICMP type based on target address
        let icmp_type = if target.is_ipv4() { ICMP::V4 } else { ICMP::V6 };

        // Progress indicator
        println!("\n🔍 Starting traceroute to {}...", self.target);
        println!("Press Ctrl+C to stop\n");

        for hop_num in 1..=MAX_HOPS {
            // Progress indicator every 5 hops
            if hop_num == 1 || hop_num % 5 == 0 {
                println!("📍 Probing hop {}...", hop_num);
            }

            debug!("Probing hop {}", hop_num);

            let mut hop_resolved = false;
            let mut first_attempt_failed = false;

            for attempt in 1..=ATTEMPTS_PER_HOP {
                debug!("  Attempt {}/{} for hop {}", attempt, ATTEMPTS_PER_HOP, hop_num);

                match self.probe_hop_with_ttl(hop_num, target, icmp_type, TIMEOUT, PAYLOAD).await {
                    Ok((ip, rtt_ms)) => {
                        // We got a response
                        if !hop_resolved {
                            // First time seeing this hop, create entry
                            let mut hop = Hop::new(hop_num, ip);
                            hop.add_rtt(rtt_ms);
                            hop.packets_sent = 1;
                            hop.packets_received = 1;
                            self.hops.push(hop);
                            hop_resolved = true;
                            // Print immediately for responsiveness
                            println!("Hop {}: {} ({}ms)", hop_num, ip, rtt_ms.round() as u64);
                        } else {
                            // Update existing hop
                            if let Some(hop) = self.hops.last_mut() {
                                hop.add_rtt(rtt_ms);
                                hop.packets_sent += 1;
                                hop.packets_received += 1;
                            }
                        }

                        // If we reached the target, we're done
                        if ip == target {
                            println!("✅ Target reached at hop {}", hop_num);
                            info!("Target reached at hop {}", hop_num);
                            return Ok(());
                        }

                        // Collect all RTT measurements across all attempts
                    }
                    Err(e) => {
                        debug!("  Attempt {} failed: {}", attempt, e);
                        if attempt == 1 {
                            first_attempt_failed = true;
                            // Continue to second attempt only
                        }
                    }
                }
            }

            // If we didn't get any response after all attempts
            if !hop_resolved {
                // Print unresponsive hop for visibility
                if first_attempt_failed {
                    println!("Hop {}: * (timeout)", hop_num);
                }
                warn!("Hop {} did not respond after {} attempts", hop_num, ATTEMPTS_PER_HOP);

                // Continue to next hop - some routers don't respond (blackhole)
                // but the target might still be reachable
                continue;
            }
        }

        println!("\n⚠️  Reached maximum hop count ({}). Target may be unreachable.", MAX_HOPS);
        warn!("Reached maximum hop count ({}). Target may be unreachable.", MAX_HOPS);
        Ok(())
    }

    /// Probe a single hop using ICMP with specified TTL
    ///
    /// Returns the responding IP and RTT in milliseconds
    async fn probe_hop_with_ttl(
        &self,
        hop_num: u8,
        target: IpAddr,
        icmp_type: ICMP,
        timeout: Duration,
        payload: &[u8],
    ) -> Result<(IpAddr, f64)> {
        // Create config with the TTL for this hop
        let config = Config::builder()
            .kind(icmp_type)
            .ttl(hop_num as u32)
            .build();

        // Create client and pinger
        let client = Client::new(&config).map_err(|e| anyhow!("Failed to create client: {}", e))?;
        let mut pinger = client.pinger(target, PingIdentifier(random())).await;
        pinger.timeout(timeout);

        // Send ping
        let seq = PingSequence(0);
        match pinger.ping(seq, payload).await {
            Ok((response_packet, rtt)) => {
                let responder_ip = match response_packet {
                    surge_ping::IcmpPacket::V4(pkt) => IpAddr::V4(pkt.get_source()),
                    surge_ping::IcmpPacket::V6(pkt) => IpAddr::V6(pkt.get_source()),
                };
                let rtt_ms = rtt.as_secs_f64() * 1000.0;
                Ok((responder_ip, rtt_ms))
            }
            Err(e) => Err(anyhow!("Ping failed: {}", e)),
        }
    }

    /// Start continuous pinging of all discovered hops
    ///
    /// Spawns a tokio task that pings all hops every second and updates
    /// the shared AppState for UI updates.
    #[allow(dead_code)]
    pub fn start_continuous_ping(&mut self, state: Arc<Mutex<AppState>>) -> Result<()> {
        if self.is_running {
            warn!("Continuous ping is already running");
            return Ok(());
        }

        if self.hops.is_empty() {
            return Err(anyhow!("No hops to ping. Run traceroute first."));
        }

        info!("Starting continuous ping for {} hops", self.hops.len());
        self.is_running = true;

        // Clone hops for the task
        let hops = self.hops.clone();
        let target = self.target.clone();

        // Spawn the ping task
        let handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            let mut iteration = 0;

            info!("Continuous ping started for target: {}", target);

            // Determine ICMP type based on first hop
            let icmp_type = if !hops.is_empty() && hops[0].ip.is_ipv6() {
                ICMP::V6
            } else {
                ICMP::V4
            };

            loop {
                interval.tick().await;
                iteration += 1;

                // Ping each hop concurrently
                for hop in &hops {
                    let config = Config::builder().kind(icmp_type).build();

                    match Client::new(&config) {
                        Ok(client) => {
                            let mut pinger = client
                                .pinger(hop.ip, PingIdentifier(random()))
                                .await;
                            pinger.timeout(Duration::from_secs(1));

                            match pinger.ping(PingSequence(0), b"ping").await {
                                Ok((_packet, rtt)) => {
                                    let rtt_ms = rtt.as_secs_f64() * 1000.0;

                                    // Update the shared state
                                    let mut state_guard = state.lock().unwrap();
                                    state_guard.add_ping_result(hop.hop_number, rtt_ms, true);
                                    drop(state_guard);

                                    debug!("Hop {}: RTT = {}ms", hop.hop_number, rtt_ms);
                                }
                                Err(e) => {
                                    warn!("Ping to hop {} failed: {}", hop.hop_number, e);

                                    // Update the shared state with failure
                                    let mut state_guard = state.lock().unwrap();
                                    state_guard.add_ping_result(hop.hop_number, 0.0, false);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create client for hop {}: {}", hop.hop_number, e);
                            let mut state_guard = state.lock().unwrap();
                            state_guard.add_ping_result(hop.hop_number, 0.0, false);
                        }
                    }
                }

                // Log progress every 60 seconds
                if iteration % 60 == 0 {
                    info!("Continuous ping running for {} seconds", iteration);
                }
            }
        });

        self.ping_handle = Some(handle);
        Ok(())
    }

    /// Stop the continuous ping task
    pub fn stop(&mut self) {
        if let Some(handle) = self.ping_handle.take() {
            info!("Stopping continuous ping...");
            handle.abort();
            self.is_running = false;
        } else {
            debug!("Continuous ping was not running");
        }
    }

    /// Get a reference to the discovered hops
    pub fn hops(&self) -> &Vec<Hop> {
        &self.hops
    }

    /// Check if the continuous ping is currently running
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// Get the target hostname/IP
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Get the number of discovered hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

impl Drop for NetworkEngine {
    fn drop(&mut self) {
        if self.is_running {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_new() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let hop = Hop::new(1, ip);

        assert_eq!(hop.hop_number, 1);
        assert_eq!(hop.ip, ip);
        assert_eq!(hop.rtts.capacity(), 100);
        assert_eq!(hop.packets_sent, 0);
        assert_eq!(hop.packets_received, 0);
    }

    #[test]
    fn test_hop_with_hostname() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let hop = Hop::with_hostname(1, ip, Some("router.example.com".to_string()));

        assert_eq!(hop.hostname, Some("router.example.com".to_string()));
    }

    #[test]
    fn test_loss_percentage() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut hop = Hop::new(1, ip);

        // No packets sent
        assert_eq!(hop.loss_percentage(), 0.0);

        // All packets received
        hop.packets_sent = 100;
        hop.packets_received = 100;
        assert_eq!(hop.loss_percentage(), 0.0);

        // 50% loss
        hop.packets_sent = 100;
        hop.packets_received = 50;
        assert_eq!(hop.loss_percentage(), 50.0);

        // 100% loss
        hop.packets_received = 0;
        assert_eq!(hop.loss_percentage(), 100.0);
    }

    #[test]
    fn test_jitter() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut hop = Hop::new(1, ip);

        // No RTTs
        assert_eq!(hop.jitter(), 0.0);

        // Single RTT
        hop.add_rtt(10.0);
        assert_eq!(hop.jitter(), 0.0);

        // Two RTTs with same value
        hop.add_rtt(10.0);
        assert_eq!(hop.jitter(), 0.0);

        // Two RTTs with different values
        hop.add_rtt(20.0);
        assert!((hop.jitter() - 5.0).abs() < 0.001); // (0 + 10) / 2 = 5
    }

    #[test]
    fn test_rtt_stats() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut hop = Hop::new(1, ip);

        // No RTTs
        let (min, avg, max) = hop.rtt_stats();
        assert!(min.is_none());
        assert!(avg.is_none());
        assert!(max.is_none());

        // Add some RTTs
        hop.add_rtt(10.0);
        hop.add_rtt(20.0);
        hop.add_rtt(30.0);

        let (min, avg, max) = hop.rtt_stats();
        assert!(min.is_some() && (min.unwrap() - 10.0).abs() < 0.001);
        assert!(avg.is_some() && (avg.unwrap() - 20.0).abs() < 0.001);
        assert!(max.is_some() && (max.unwrap() - 30.0).abs() < 0.001);
    }

    #[test]
    fn test_rolling_buffer() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut hop = Hop::new(1, ip);

        // Add 101 RTTs
        for i in 0..101 {
            hop.add_rtt(i as f64);
        }

        // Should only have 100 RTTs (oldest removed)
        assert_eq!(hop.rtts.len(), 100);
        assert_eq!(hop.rtts[0], 1.0); // First value after removal
        assert_eq!(hop.rtts[99], 100.0); // Last value
    }

    #[test]
    fn test_network_engine_new() {
        let engine = NetworkEngine::new("example.com".to_string());

        assert_eq!(engine.target(), "example.com");
        assert_eq!(engine.hop_count(), 0);
        assert!(!engine.is_running());
    }

    #[test]
    fn test_hop_is_alive() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut hop = Hop::new(1, ip);

        assert!(!hop.is_alive());

        hop.packets_received = 1;
        assert!(hop.is_alive());
    }
}
