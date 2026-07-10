//! RustyPlot CLI - A standalone terminal traceroute tool
//!
//! This binary provides network diagnostics without any GUI dependencies.
//! Uses the same NetworkEngine as the main application but outputs to terminal.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use rustyplot::NetworkEngine;
use tokio::time::interval;

/// RustyPlot CLI - A terminal-based network traceroute tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target hostname or IP address to trace
    #[arg(required = true)]
    target: String,

    /// Run in continuous ping mode (ping all hops every second until Ctrl+C)
    #[arg(short, long, default_value_t = false)]
    continuous: bool,
}

/// Formatted output for displaying hop information
struct HopDisplay {
    hop_number: u8,
    ip_str: String,
    rtt_ms: Option<f64>,
    is_target: bool,
}

impl HopDisplay {
    fn new(hop_number: u8, ip_str: String, rtt_ms: Option<f64>, is_target: bool) -> Self {
        Self {
            hop_number,
            ip_str,
            rtt_ms,
            is_target,
        }
    }
}

impl std::fmt::Display for HopDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rtt_str = match self.rtt_ms {
            Some(rtt) if rtt > 0.0 => format!("{:.1}ms", rtt),
            Some(_) | None => "timeout".to_string(),
        };

        let status = if self.rtt_ms.is_some() && self.rtt_ms.unwrap() > 0.0 {
            "✓"
        } else {
            "✗"
        };

        let target_marker = if self.is_target { " (target)" } else { "" };

        write!(
            f,
            "{:>3}  {:<20}  {:<10}  {}{}",
            self.hop_number, self.ip_str, rtt_str, status, target_marker
        )
    }
}

/// Print a formatted table header for hop results
fn print_table_header() {
    println!("\n{:<5} {:<22} {:<12} {:<10}", "Hop", "IP Address", "RTT", "Status");
    println!("{:-<5} {:-<22} {:-<12} {:-<10}", "", "", "", "");
}

/// Print the target information line
fn print_target_info(target: &str, target_ip: &str) {
    println!("Traceroute to {} ({})", target, target_ip);
}

/// Run a single traceroute and display results
async fn run_traceroute(engine: &mut NetworkEngine) -> Result<()> {
    // Clone target string before mutable borrow
    let target_ip = engine.target().to_string();

    // Run traceroute
    engine.traceroute().await?;

    // Get target IP for display
    let target_ip_str = if let Ok(ip) = target_ip.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        // If not an IP, try to resolve it
        match tokio::net::lookup_host(format!("{}:80", target_ip)).await {
            Ok(addrs) => {
                if let Some(addr) = addrs.into_iter().next() {
                    addr.ip().to_string()
                } else {
                    target_ip.to_string()
                }
            }
            Err(_) => target_ip.to_string(),
        }
    };

    print_target_info(&target_ip, &target_ip_str);
    print_table_header();

    let hops = engine.hops();
    let target_ip_addr: Option<std::net::IpAddr> = target_ip.parse().ok();

    for hop in hops {
        let is_target = if let Some(target_ip) = target_ip_addr {
            hop.ip == target_ip
        } else {
            hop.hop_number == hops.len() as u8
        };

        let rtt_ms = hop.rtts.last().copied();
        let display = HopDisplay::new(
            hop.hop_number,
            hop.ip.to_string(),
            rtt_ms,
            is_target,
        );

        println!("{}", display);
    }

    // Print summary
    println!();
    println!("Total hops: {}", hops.len());

    if let Some(last_hop) = hops.last() {
        if let Some(target_ip) = target_ip_addr {
            if last_hop.ip == target_ip {
                println!("Target reached at hop {}", last_hop.hop_number);
            }
        }
    }

    Ok(())
}

/// Run continuous ping mode
async fn run_continuous_ping(engine: &mut NetworkEngine, stop_flag: Arc<AtomicBool>) -> Result<()> {
    if engine.hops().is_empty() {
        anyhow::bail!("No hops discovered. Run traceroute first (omit --continuous flag).");
    }

    let target_ip = engine.target();
    let target_ip_str = if let Ok(ip) = target_ip.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        target_ip.to_string()
    };

    println!("Continuous ping mode for: {} ({})", target_ip, target_ip_str);
    println!("Press Ctrl+C to stop\n");
    print_table_header();

    let mut interval = interval(Duration::from_secs(1));
    let mut iteration: u64 = 0;

    // Store previous RTTs for comparison
    let mut prev_rtts: Vec<Option<f64>> = vec![None; engine.hops().len()];

    while !stop_flag.load(Ordering::SeqCst) {
        interval.tick().await;
        iteration += 1;

        // Clear previous line output (move cursor up)
        for _ in 0..engine.hops().len() + 2 {
            print!("\x1B[A\x1B[2K");
        }

        // Re-print header
   print_target_info(&target_ip, &target_ip_str);
        print_table_header();

        // Ping each hop
        for hop in engine.hops() {
            let is_target = hop.hop_number == engine.hops().len() as u8;

            // We need to ping the hop - but the NetworkEngine doesn't expose a direct ping method
            // We'll use the surge-ping client directly here
            let rtt_ms = ping_hop(hop.ip).await;

            let display = HopDisplay::new(
                 hop.hop_number,
                 hop.ip.to_string(),
                 rtt_ms,
                 is_target,
             );

            println!("{}", display);
            prev_rtts[hop.hop_number as usize - 1] = rtt_ms;
        }

        println!("\nIteration: {}  (Ctrl+C to stop)", iteration);
        io::stdout().flush().unwrap();
    }

    println!("\n\nContinuous ping stopped after {} iterations", iteration);
    Ok(())
}

/// Ping a single hop and return RTT in milliseconds
async fn ping_hop(ip: std::net::IpAddr) -> Option<f64> {
    use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};

    let icmp_type = if ip.is_ipv4() { ICMP::V4 } else { ICMP::V6 };

    match Client::new(&Config::builder().kind(icmp_type).build()) {
        Ok(client) => {
            let mut pinger = client.pinger(ip, PingIdentifier(rand::random())).await;
            pinger.timeout(Duration::from_millis(500));

            match pinger.ping(PingSequence(0), b"ping").await {
                Ok((_packet, rtt)) => Some(rtt.as_secs_f64() * 1000.0),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging - use "error" to suppress traceroute warnings
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error"))
        .format_timestamp(None)
        .format(|buf, record| {
            writeln!(buf, "[{}] {}", record.level(), record.args())
        })
        .init();

    let args = Args::parse();

    println!("RustyPlot CLI - Network Traceroute Tool");
    println!("========================================\n");

    // Create engine with target
    let mut engine = NetworkEngine::new(args.target.clone());

    // Set up Ctrl+C handler for continuous mode
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        stop_flag_clone.store(true, Ordering::SeqCst);
    });

    if args.continuous {
        // Run traceroute first to discover hops
        println!("Discovering network path...");
        engine.traceroute().await?;
        println!("\n");

        // Then start continuous ping
        run_continuous_ping(&mut engine, stop_flag).await?;
    } else {
        // Single traceroute run
        run_traceroute(&mut engine).await?;
    }

    Ok(())
}
