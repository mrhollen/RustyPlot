//! Application state management for shared data between UI and network engine.

use std::collections::HashMap;
use std::net::IpAddr;

use std::time::{Duration, Instant};

/// Maximum number of ping results to keep in history
const MAX_HISTORY_SIZE: usize = 1000;

/// Ping result for a specific hop at a specific time
#[derive(Debug, Clone)]
pub struct PingResult {
    pub timestamp: Instant,
    pub rtt_ms: f64,
    pub success: bool,
}

/// State for a single hop's ping history
#[derive(Debug, Clone)]
pub struct HopState {
    pub results: Vec<PingResult>,
    /// Most recent RTT value (for quick UI access)
    pub latest_rtt: Option<f64>,
    /// Whether the hop is currently responding
    pub is_alive: bool,
}

impl HopState {
    pub fn new() -> Self {
        Self {
            results: Vec::with_capacity(MAX_HISTORY_SIZE),
            latest_rtt: None,
            is_alive: false,
        }
    }

    pub fn add_result(&mut self, rtt_ms: f64, success: bool) {
        // Trim history if needed
        if self.results.len() >= MAX_HISTORY_SIZE {
            self.results.remove(0);
        }

        let result = PingResult {
            timestamp: Instant::now(),
            rtt_ms,
            success,
        };

        self.results.push(result.clone());

        if success {
            self.latest_rtt = Some(rtt_ms);
            self.is_alive = true;
        } else {
            // Only mark as dead if this was a recent failure
            // and we had been alive before
            if self.latest_rtt.is_some() {
                self.is_alive = false;
            }
        }
    }

    /// Get the last N results for plotting
    pub fn get_recent_results(&self, count: usize) -> Vec<&PingResult> {
        let start = if self.results.len() > count {
            self.results.len() - count
        } else {
            0
        };
        self.results[start..].iter().collect()
    }

    /// Calculate average RTT from recent results
    pub fn average_rtt(&self) -> Option<f64> {
        let recent = self.get_recent_results(100);
        let successful: Vec<_> = recent.iter().filter(|r| r.success).collect();
        if successful.is_empty() {
            return None;
        }
        let sum: f64 = successful.iter().map(|r| r.rtt_ms).sum();
        Some(sum / successful.len() as f64)
    }

    /// Calculate packet loss percentage from recent results
    pub fn loss_percentage(&self) -> f64 {
        let recent = self.get_recent_results(100);
        if recent.is_empty() {
            return 0.0;
        }
        let failed = recent.iter().filter(|r| !r.success).count();
        (failed as f64 / recent.len() as f64) * 100.0
    }

    /// Get minimum RTT from recent results
    pub fn min_rtt(&self) -> Option<f64> {
        let recent = self.get_recent_results(100);
        let successful: Vec<_> = recent.iter().filter(|r| r.success).collect();
        if successful.is_empty() {
            return None;
        }
        successful
            .iter()
            .map(|r| r.rtt_ms)
            .min_by(|a, b| a.partial_cmp(b).unwrap())
    }

    /// Get maximum RTT from recent results
    pub fn max_rtt(&self) -> Option<f64> {
        let recent = self.get_recent_results(100);
        let successful: Vec<_> = recent.iter().filter(|r| r.success).collect();
        if successful.is_empty() {
            return None;
        }
        successful
            .iter()
            .map(|r| r.rtt_ms)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
    }
}

/// Main application state shared between UI and network engine
#[derive(Debug)]
pub struct AppState {
    /// Target being traced
    pub target: String,
    /// State for each hop
    pub hops: HashMap<u8, HopState>,
    /// IP addresses for each hop (populated from NetworkEngine)
    pub hop_ips: HashMap<u8, IpAddr>,
    /// Whether traceroute has been completed
    pub traceroute_complete: bool,
    /// Whether continuous ping is running
    pub ping_running: bool,
    /// Start time of the session
    pub session_start: Instant,
}

impl AppState {
    pub fn new(target: String) -> Self {
        Self {
            target,
            hops: HashMap::new(),
            hop_ips: HashMap::new(),
            traceroute_complete: false,
            ping_running: false,
            session_start: Instant::now(),
        }
    }

    /// Initialize hop states from a list of hop numbers
    pub fn initialize_hops(&mut self, hop_numbers: Vec<u8>) {
        for hop_num in hop_numbers {
            self.hops.insert(hop_num, HopState::new());
        }
    }

    /// Add a ping result for a specific hop
    pub fn add_ping_result(&mut self, hop_number: u8, rtt_ms: f64, success: bool) {
        self.hops
            .entry(hop_number)
            .or_insert_with(HopState::new)
            .add_result(rtt_ms, success);
    }

    /// Get or create a hop state
    pub fn get_hop_state(&self, hop_number: u8) -> Option<&HopState> {
        self.hops.get(&hop_number)
    }

    /// Set traceroute complete flag
    pub fn set_traceroute_complete(&mut self, complete: bool) {
        self.traceroute_complete = complete;
    }

    /// Set ping running flag
    pub fn set_ping_running(&mut self, running: bool) {
        self.ping_running = running;
    }

    /// Get session duration
    pub fn session_duration(&self) -> Duration {
        self.session_start.elapsed()
    }

    /// Get all hop numbers in order
    pub fn hop_numbers(&self) -> Vec<u8> {
        let mut nums: Vec<u8> = self.hops.keys().cloned().collect();
        nums.sort();
        nums
    }

    /// Set hop IP addresses from NetworkEngine hops
    pub fn set_hop_ips(&mut self, hops: &Vec<crate::network_engine::Hop>) {
        self.hop_ips.clear();
        for hop in hops {
            self.hop_ips.insert(hop.hop_number, hop.ip);
        }
    }

    /// Get IP address for a specific hop number
    pub fn get_hop_ip(&self, hop_number: u8) -> Option<IpAddr> {
        self.hop_ips.get(&hop_number).copied()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_new() {
        let state = AppState::new("example.com".to_string());
        assert_eq!(state.target, "example.com");
        assert!(!state.traceroute_complete);
        assert!(!state.ping_running);
        assert!(state.hops.is_empty());
    }

    #[test]
    fn test_hop_state_add_result() {
        let mut hop = HopState::new();

        hop.add_result(10.0, true);
        assert_eq!(hop.latest_rtt, Some(10.0));
        assert!(hop.is_alive);

        hop.add_result(0.0, false);
        assert!(!hop.is_alive);

        hop.add_result(15.0, true);
        assert_eq!(hop.latest_rtt, Some(15.0));
        assert!(hop.is_alive);
    }

    #[test]
    fn test_hop_state_average_rtt() {
        let mut hop = HopState::new();

        assert!(hop.average_rtt().is_none());

        hop.add_result(10.0, true);
        hop.add_result(20.0, true);
        hop.add_result(30.0, true);

        assert!(hop.average_rtt().is_some());
        let avg = hop.average_rtt().unwrap();
        assert!((avg - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_hop_state_loss_percentage() {
        let mut hop = HopState::new();

        assert_eq!(hop.loss_percentage(), 0.0);

        hop.add_result(10.0, true);
        hop.add_result(0.0, false);
        hop.add_result(15.0, true);
        hop.add_result(0.0, false);

        assert!((hop.loss_percentage() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_hop_state_rolling_buffer() {
        let mut hop = HopState::new();

        // Add more than MAX_HISTORY_SIZE results
        for i in 0..MAX_HISTORY_SIZE + 50 {
            hop.add_result(i as f64, true);
        }

        assert_eq!(hop.results.len(), MAX_HISTORY_SIZE);
    }

    #[test]
    fn test_app_state_initialize_hops() {
        let mut state = AppState::new("example.com".to_string());

        state.initialize_hops(vec![1, 2, 3]);

        assert_eq!(state.hops.len(), 3);
        assert!(state.get_hop_state(1).is_some());
        assert!(state.get_hop_state(2).is_some());
        assert!(state.get_hop_state(3).is_some());
        assert!(state.get_hop_state(4).is_none());
    }

    #[test]
    fn test_app_state_add_ping_result() {
        let mut state = AppState::new("example.com".to_string());

        state.add_ping_result(1, 10.0, true);

        let hop = state.get_hop_state(1).unwrap();
        assert_eq!(hop.latest_rtt, Some(10.0));
    }

    #[test]
    fn test_app_state_hop_numbers() {
        let mut state = AppState::new("example.com".to_string());

        state.initialize_hops(vec![3, 1, 2]);

        let nums = state.hop_numbers();
        assert_eq!(nums, vec![1, 2, 3]);
    }

    #[test]
    fn test_hop_ip_storage() {
        use crate::network_engine::Hop;

        let mut state = AppState::new("example.com".to_string());

        // Initially no hop IPs
        assert!(state.get_hop_ip(1).is_none());
        assert!(state.hop_ips.is_empty());

        // Create mock hops
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        let hops = vec![Hop::new(1, ip1), Hop::new(2, ip2), Hop::new(3, ip3)];

        // Set hop IPs
        state.set_hop_ips(&hops);

        // Verify IPs are stored
        assert_eq!(state.get_hop_ip(1), Some(ip1));
        assert_eq!(state.get_hop_ip(2), Some(ip2));
        assert_eq!(state.get_hop_ip(3), Some(ip3));
        assert_eq!(state.get_hop_ip(4), None); // Non-existent hop
    }
}
