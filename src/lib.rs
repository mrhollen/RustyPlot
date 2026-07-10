//! RustyPlot - A TCP-based graphical traceroute tool
//!
//! This crate provides a network diagnostic tool that uses TCP-based
//! traceroute and continuous ping to monitor network path quality.

pub mod app_state;
pub mod network_engine;
pub mod traceroute;
pub mod ui_renderer;

pub use app_state::AppState;
pub use network_engine::NetworkEngine;
