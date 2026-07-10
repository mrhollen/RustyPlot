//! RustyPlot - A TCP-based graphical traceroute tool
//!
//! Main entry point that:
//! 1. Sets up eframe window with dark theme
//! 2. Initializes NetworkEngine and AppState
//! 3. Bridges tokio runtime (network) with eframe render loop (UI)
//! 4. Provides console mode for testing network engine without GUI

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use eframe::egui;
use log::{debug, info, error, warn};

mod app_state;
mod network_engine;
mod traceroute;
mod ui_renderer;

use app_state::AppState;
use network_engine::NetworkEngine;
use ui_renderer::{SortColumn, SortDirection};

/// Application state for the GUI
struct RustyPlotApp {
    target: String,
    state: Arc<tokio::sync::Mutex<AppState>>,
    stop_signal: Arc<AtomicBool>,
    selected_hop: Option<usize>,
    /// Sorting state for the hop table
    sort_column: SortColumn,
    sort_direction: SortDirection,
    /// Whether the engine task has been spawned
    engine_initialized: bool,
}

impl RustyPlotApp {
    /// Create a new RustyPlotApp instance
    fn new(cc: &eframe::CreationContext<'_>, target: String) -> Self {
        // Set up dark theme
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let state = Arc::new(tokio::sync::Mutex::new(AppState::new(target.clone())));

        Self {
            target,
            state,
            stop_signal: Arc::new(AtomicBool::new(false)),
            selected_hop: None,
            sort_column: SortColumn::default(),
            sort_direction: SortDirection::default(),
            engine_initialized: false,
        }
    }

    /// Spawn the network engine task
    fn spawn_engine_task(&mut self) {
        if self.engine_initialized {
            return;
        }

        let state_clone = Arc::clone(&self.state);
        let stop_clone = Arc::clone(&self.stop_signal);
        let target = self.target.clone();

        // Spawn in a separate thread with its own tokio runtime
        // eframe doesn't provide a tokio runtime by default
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime");
            rt.block_on(async move {
                debug!("Spawning network engine task for target: {}", target);

                let mut engine = NetworkEngine::new(target.clone());

            // Perform traceroute
            match engine.traceroute().await {
                Ok(()) => {
                    info!("Traceroute completed, discovered {} hops", engine.hop_count());

                    // Initialize app state with discovered hops
                    let hop_numbers: Vec<u8> = engine.hops().iter().map(|h| h.hop_number).collect();
                    {
                        let mut state = state_clone.lock().await;
                        state.initialize_hops(hop_numbers);
                        state.set_hop_ips(engine.hops());
                        state.set_traceroute_complete(true);
                    }

                    // Start continuous ping if not stopped
                    if !stop_clone.load(Ordering::SeqCst) {
                        let state_for_ping = Arc::clone(&state_clone);
                        // Convert tokio::sync::Mutex to std::sync::Mutex for the engine
                        // We'll use a different approach - directly update state in the ping task
                        if let Err(e) = start_ping_task(engine, state_for_ping, stop_clone, target) {
                            error!("Failed to start ping task: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Traceroute failed: {}", e);
                    let mut state = state_clone.lock().await;
                    state.set_traceroute_complete(false);
                }
            }
        });
        });

        self.engine_initialized = true;
    }
}

/// Start the continuous ping task
fn start_ping_task(
    engine: NetworkEngine,
    state: Arc<tokio::sync::Mutex<AppState>>,
    _stop_signal: Arc<AtomicBool>,
    _target: String,
) -> Result<()> {
    use std::sync::Mutex as StdMutex;

    // Create a std::sync::Mutex wrapper for the ping task
    // The network_engine expects std::sync::Mutex, so we wrap our tokio::sync::Mutex
    let _std_state: Arc<StdMutex<AppState>> = Arc::new(StdMutex::new({
        // Create a fresh AppState that will be updated by the ping task
        // and then synced back to the tokio mutex
        AppState::new(String::new())
    }));

    // Actually, let's use a different approach: clone the tokio state and convert
    // We'll create a hybrid approach where we use the tokio mutex directly
    // by implementing our own ping loop that doesn't rely on network_engine's start_continuous_ping

    // For now, let's just spawn the ping task directly without using network_engine's method
    let state_clone = Arc::clone(&state);
    let hops = engine.hops().clone();
    let target_name = engine.target().to_string();

    info!("Starting continuous ping for {} hops to {}", hops.len(), target_name);

    // Determine ICMP type based on first hop
    let icmp_type = if !hops.is_empty() && hops[0].ip.is_ipv6() {
        surge_ping::ICMP::V6
    } else {
        surge_ping::ICMP::V4
    };

    // Set ping running flag
    let state_clone2 = Arc::clone(&state_clone);
    tokio::spawn(async move {
        let mut state = state_clone2.lock().await;
        state.set_ping_running(true);
    });

    // Spawn the actual ping task
    tokio::spawn(async move {
        use std::time::Duration;
        use rand::random;
        use surge_ping::{Client, Config, PingIdentifier, PingSequence};
        use tokio::time::interval;

        let mut interval_timer = interval(Duration::from_secs(1));
        let mut iteration = 0;

        info!("Continuous ping started for target: {}", target_name);

        loop {
            interval_timer.tick().await;
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
                                let mut state_guard = state_clone.lock().await;
                                state_guard.add_ping_result(hop.hop_number, rtt_ms, true);
                                drop(state_guard);

                                debug!("Hop {}: RTT = {}ms", hop.hop_number, rtt_ms);
                            }
                            Err(e) => {
                                warn!("Ping to hop {} failed: {}", hop.hop_number, e);

                                // Update the shared state with failure
                                let mut state_guard = state_clone.lock().await;
                                state_guard.add_ping_result(hop.hop_number, 0.0, false);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create client for hop {}: {}", hop.hop_number, e);
                        let mut state_guard = state_clone.lock().await;
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

    Ok(())
}

impl eframe::App for RustyPlotApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Spawn engine task on first frame if not yet initialized
        if !self.engine_initialized {
            self.spawn_engine_task();
        }

        // Check stop signal
        if self.stop_signal.load(Ordering::SeqCst) {
            // Set ping running to false - must use separate thread with tokio runtime
            // because eframe doesn't provide a tokio runtime by default
            let state_clone = Arc::clone(&self.state);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .expect("Failed to create tokio runtime");
                rt.block_on(async move {
                    let mut state = state_clone.lock().await;
                    state.set_ping_running(false);
                });
            });
        }

        // Render the main UI
        ui_renderer::render(
            ctx,
            &self.state,
            &mut self.selected_hop,
            &self.stop_signal,
            &mut self.sort_column,
            &mut self.sort_direction,
        );
    }
}

/// Run the GUI mode
pub fn run_gui(target: String) -> eframe::Result<()> {
    // Initialize logging with filter to suppress verbose zbus (D-Bus) logs
    // Keep application logs at INFO, suppress zbus and other noisy crates
    env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("info,zbus=off,tracing=off,eframe=warn")
    )
    .init();

    info!("Starting RustyPlot GUI for target: {}", target);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title(format!("RustyPlot - {}", target)),
        ..Default::default()
    };

    eframe::run_native(
        "RustyPlot - Network Traceroute",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(RustyPlotApp::new(cc, target.clone())))
        }),
    )
}

/// Run in console mode for testing the network engine without GUI
pub fn run_console(target: String) -> Result<()> {
    // Initialize logging with filter to suppress verbose zbus (D-Bus) logs
    // Keep application logs at INFO, suppress zbus and other noisy crates
    env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("info,zbus=off,tracing=off,eframe=warn")
    )
    .init();

    info!("Starting RustyPlot console mode for target: {}", target);

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let mut engine = NetworkEngine::new(target.clone());

        println!("Performing TCP traceroute to {}...", target);
        println!();

        match engine.traceroute().await {
            Ok(()) => {
                println!("Traceroute complete. Hops discovered:\n");

                for hop in engine.hops() {
                    println!(
                        "Hop {}: {} ({})",
                        hop.hop_number,
                        hop.hostname.as_deref().unwrap_or("unknown"),
                        hop.ip
                    );

                    // Print statistics for each hop
                    let (min, avg, max) = hop.rtt_stats();
                    println!(
                        "    RTT: min={:?}ms, avg={:?}ms, max={:?}ms, loss={:.1}%",
                        min,
                        avg,
                        max,
                        hop.loss_percentage()
                    );
                }

                println!("\nTotal hops discovered: {}", engine.hop_count());
            }
            Err(e) => {
                eprintln!("Traceroute failed: {}", e);
                return Err(e);
            }
        }

        Ok::<_, anyhow::Error>(())
    })
}

/// Print usage information
fn print_usage() {
    eprintln!("Usage: rustyplot [OPTIONS] <target>");
    eprintln!();
    eprintln!("A TCP-based graphical traceroute tool for diagnosing network connections.");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --console    Run in console mode (no GUI, for testing)");
    eprintln!();
    eprintln!("ARGUMENTS:");
    eprintln!("  target       Hostname or IP address to trace (e.g., google.com, 8.8.8.8)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  rustyplot google.com              # Run in GUI mode");
    eprintln!("  rustyplot --console google.com    # Run in console mode");
    eprintln!("  rustyplot 8.8.8.8                 # Trace by IP address");
}

/// Main entry point
fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let (mode, target) = if args[1] == "--console" {
        if args.len() < 3 {
            eprintln!("Error: --console mode requires a target");
            print_usage();
            std::process::exit(1);
        }
        ("console", args[2].clone())
    } else if args[1] == "--help" || args[1] == "-h" {
        print_usage();
        std::process::exit(0);
    } else {
        ("gui", args[1].clone())
    };

    // Validate target is not empty
    if target.is_empty() {
        eprintln!("Error: target cannot be empty");
        print_usage();
        std::process::exit(1);
    }

    match mode {
        "console" => {
            if let Err(e) = run_console(target) {
                eprintln!("Console mode error: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            if let Err(e) = run_gui(target) {
                eprintln!("GUI mode error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rusty_plot_app_new() {
        // We can't easily test the eframe integration, but we can verify
        // that the structure compiles correctly
        let app = RustyPlotApp {
            target: "test.com".to_string(),
            state: Arc::new(tokio::sync::Mutex::new(AppState::new("test.com".to_string()))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            selected_hop: None,
            sort_column: SortColumn::default(),
            sort_direction: SortDirection::default(),
            engine_initialized: false,
        };

        assert_eq!(app.target, "test.com");
        assert!(!app.stop_signal.load(Ordering::SeqCst));
        assert!(!app.engine_initialized);
    }
}
