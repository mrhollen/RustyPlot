//! UI rendering module for RustyPlot.
//! Handles all egui rendering for the main window, hop visualization, and controls.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};

use crate::app_state::AppState;

/// Sorting column and direction for the hop table
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SortColumn {
    HopNumber,
    #[default]
    AvgRtt,
    MinRtt,
    MaxRtt,
    Loss,
    PingCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

/// Generate a distinct color for each hop number
fn hop_color(hop_num: u8) -> egui::Color32 {
    // Use a deterministic color based on hop number
    let hue = (hop_num as f32 * 137.508) % 360.0; // Golden angle for good distribution
    let r = ((hue + 0.0).cos() * 0.5 + 0.5) * 255.0;
    let g = ((hue + 120.0).cos() * 0.5 + 0.5) * 255.0;
    let b = ((hue + 240.0).cos() * 0.5 + 0.5) * 255.0;
    egui::Color32::from_rgb(r as u8, g as u8, b as u8)
}

/// Render the main UI for RustyPlot
pub fn render(
    ctx: &egui::Context,
    state: &Arc<std::sync::Mutex<AppState>>,
    selected_hop: &mut Option<usize>,
    stop_signal: &Arc<AtomicBool>,
    sort_column: &mut SortColumn,
    sort_direction: &mut SortDirection,
) {
    // Apply dark theme with high contrast
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(egui::Color32::from_rgb(200, 200, 200));
    visuals.window_fill = egui::Color32::from_rgb(30, 30, 30);
    visuals.panel_fill = egui::Color32::from_rgb(40, 40, 40);
    ctx.set_visuals(visuals);

    // Need to acquire the state lock for rendering
    let state_guard = match state.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            // If we can't get the lock, show a loading indicator
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Loading...");
            });
            return;
        }
    };

    let app_state = &*state_guard;

    egui::CentralPanel::default().show(ctx, |ui| {
        // Header with title and controls
        render_header(ui, app_state, stop_signal);

        ui.separator();

        // Split view: 60% left (table), 40% right (timeline)
        ui.horizontal(|ui| {
            // Calculate available width for sizing
            let available_width = ui.available_width();

            // Left pane: Hop table (60%)
            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                ui.set_min_width(available_width * 0.6);
                render_hop_table(ui, app_state, selected_hop, sort_column, sort_direction);
            });

            ui.add_space(10.0);

            // Right pane: Timeline graphs (40%)
            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                ui.set_min_width(available_width * 0.4);
                render_timeline_graphs(ui, app_state, selected_hop);
            });
        });
    });
}

/// Render header with title, status, and controls
fn render_header(ui: &mut egui::Ui, app_state: &AppState, stop_signal: &Arc<AtomicBool>) {
    ui.heading(format!("RustyPlot - {}", app_state.target));

    // Session info and status
    ui.horizontal(|ui| {
        ui.label("Session duration:");
        let duration = app_state.session_duration();
        let duration_str = format!(
            "{}m {:02}s",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        );
        ui.label(&duration_str);

        ui.add_space(20.0);

        ui.label("Status:");
        if app_state.ping_running {
            let status_color = egui::Color32::from_rgb(0, 200, 100);
            ui.label(egui::RichText::new("Running").color(status_color));
        } else if app_state.traceroute_complete {
            let status_color = egui::Color32::from_rgb(200, 200, 0);
            ui.label(egui::RichText::new("Traceroute complete").color(status_color));
        } else {
            let status_color = egui::Color32::from_rgb(200, 100, 0);
            ui.label(egui::RichText::new("Initializing...").color(status_color));
        }

        if ui.button("Stop Ping").clicked() {
            stop_signal.store(true, Ordering::SeqCst);
        }
    });
}

/// Render the sortable hop table
fn render_hop_table(
    ui: &mut egui::Ui,
    app_state: &AppState,
    selected_hop: &mut Option<usize>,
    sort_column: &mut SortColumn,
    sort_direction: &mut SortDirection,
) {
    egui::ScrollArea::vertical()
        .max_height(500.0)
        .show(ui, |ui| {
            ui.heading("Network Hops");

            let hop_numbers = app_state.hop_numbers();

            if hop_numbers.is_empty() {
                ui.label("No hops discovered yet...");
                return;
            }

            // Build sortable data
            let mut hop_data: Vec<(u8, usize)> = hop_numbers
                .iter()
                .enumerate()
                .map(|(idx, &hop_num)| (hop_num, idx))
                .collect();

            // Sort based on current sort column and direction
            hop_data.sort_by(|a, b| {
                let a_state = app_state.get_hop_state(a.0).unwrap();
                let b_state = app_state.get_hop_state(b.0).unwrap();

                let cmp = match *sort_column {
                    SortColumn::HopNumber => a.0.cmp(&b.0),
                    SortColumn::AvgRtt => {
                        let a_avg = a_state.average_rtt().unwrap_or(0.0);
                        let b_avg = b_state.average_rtt().unwrap_or(0.0);
                        a_avg
                            .partial_cmp(&b_avg)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    }
                    SortColumn::MinRtt => {
                        let a_min = a_state.min_rtt().unwrap_or(f64::INFINITY);
                        let b_min = b_state.min_rtt().unwrap_or(f64::INFINITY);
                        a_min
                            .partial_cmp(&b_min)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    }
                    SortColumn::MaxRtt => {
                        let a_max = a_state.max_rtt().unwrap_or(0.0);
                        let b_max = b_state.max_rtt().unwrap_or(0.0);
                        a_max
                            .partial_cmp(&b_max)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    }
                    SortColumn::Loss => {
                        let a_loss = a_state.loss_percentage();
                        let b_loss = b_state.loss_percentage();
                        a_loss
                            .partial_cmp(&b_loss)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    }
                    SortColumn::PingCount => a_state.results.len().cmp(&b_state.results.len()),
                };

                match *sort_direction {
                    SortDirection::Asc => cmp,
                    SortDirection::Desc => cmp.reverse(),
                }
            });

            // Header row with sort indicators
            ui.horizontal(|ui| {
                render_sort_header(
                    ui,
                    sort_column,
                    sort_direction,
                    SortColumn::HopNumber,
                    "Hop",
                );
                render_sort_header(
                    ui,
                    sort_column,
                    sort_direction,
                    SortColumn::MinRtt,
                    "Min RTT",
                );
                render_sort_header(
                    ui,
                    sort_column,
                    sort_direction,
                    SortColumn::MaxRtt,
                    "Max RTT",
                );
                render_sort_header(
                    ui,
                    sort_column,
                    sort_direction,
                    SortColumn::AvgRtt,
                    "Avg RTT",
                );
                render_sort_header(ui, sort_column, sort_direction, SortColumn::Loss, "Loss %");
                render_sort_header(
                    ui,
                    sort_column,
                    sort_direction,
                    SortColumn::PingCount,
                    "Pings",
                );
            });
            ui.separator();

            // Data rows
            for (hop_num, hop_idx) in &hop_data {
                if let Some(hop_state) = app_state.get_hop_state(*hop_num) {
                    let is_selected = Some(*hop_idx) == *selected_hop;

                    ui.horizontal(|ui| {
                        // Hop number (clickable for isolate view)
                        let response = ui.selectable_label(is_selected, format!("Hop {}", hop_num));
                        if response.clicked() {
                            *selected_hop = Some(*hop_idx);
                        }

                        // Min RTT
                        if let Some(min) = hop_state.min_rtt() {
                            ui.label(format!("{:.1}", min));
                        } else {
                            ui.label("-");
                        }

                        // Max RTT
                        if let Some(max) = hop_state.max_rtt() {
                            ui.label(format!("{:.1}", max));
                        } else {
                            ui.label("-");
                        }

                        // Average RTT
                        if let Some(avg) = hop_state.average_rtt() {
                            ui.label(format!("{:.1}", avg));
                        } else {
                            ui.label("-");
                        }

                        // Loss percentage
                        let loss = hop_state.loss_percentage();
                        let loss_color = if loss > 50.0 {
                            egui::Color32::from_rgb(200, 0, 0)
                        } else if loss > 10.0 {
                            egui::Color32::from_rgb(200, 200, 0)
                        } else {
                            egui::Color32::from_rgb(0, 200, 100)
                        };
                        ui.label(egui::RichText::new(format!("{:.1}%", loss)).color(loss_color));

                        // Ping count
                        ui.label(format!("{}", hop_state.results.len()));
                    });

                    ui.separator();
                }
            }

            // Isolate view for selected hop
            if let Some(selected_idx) = *selected_hop {
                if let Some(selected_hop_num) = hop_numbers.get(selected_idx) {
                    if let Some(selected_hop_state) = app_state.get_hop_state(*selected_hop_num) {
                        ui.separator();
                        ui.heading(format!(
                            "Isolate View: Hop {} (IP: {})",
                            selected_hop_num,
                            get_hop_ip(app_state, *selected_hop_num)
                        ));

                        // Detailed statistics
                        ui.horizontal(|ui| {
                            ui.label("Average RTT:");
                            if let Some(avg) = selected_hop_state.average_rtt() {
                                ui.label(format!("{:.1} ms", avg));
                            } else {
                                ui.label("N/A");
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Min RTT:");
                            if let Some(min) = selected_hop_state.min_rtt() {
                                ui.label(format!("{:.1} ms", min));
                            } else {
                                ui.label("N/A");
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Max RTT:");
                            if let Some(max) = selected_hop_state.max_rtt() {
                                ui.label(format!("{:.1} ms", max));
                            } else {
                                ui.label("N/A");
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Packet Loss:");
                            ui.label(format!("{:.1}%", selected_hop_state.loss_percentage()));
                        });

                        ui.horizontal(|ui| {
                            ui.label("Total Pings:");
                            ui.label(format!("{}", selected_hop_state.results.len()));
                        });

                        ui.horizontal(|ui| {
                            ui.label("Latest RTT:");
                            if let Some(rtt) = selected_hop_state.latest_rtt {
                                ui.label(format!("{:.1} ms", rtt));
                            } else {
                                ui.label("N/A");
                            }
                        });

                        ui.separator();
                        ui.label("Recent RTT History (last 20 pings):");

                        // Display recent RTT values as a simple list
                        let recent = selected_hop_state.get_recent_results(20);
                        egui::ScrollArea::horizontal().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                for (i, r) in recent.iter().enumerate() {
                                    let text = if r.success {
                                        format!("{:.0}", r.rtt_ms)
                                    } else {
                                        "X".to_string()
                                    };
                                    let color = if r.success {
                                        egui::Color32::from_rgb(0, 200, 100)
                                    } else {
                                        egui::Color32::from_rgb(200, 50, 50)
                                    };
                                    ui.label(egui::RichText::new(text).color(color));
                                    if i < recent.len() - 1 {
                                        ui.label("→");
                                    }
                                }
                            });
                        });

                        if ui.button("Close Isolate View").clicked() {
                            *selected_hop = None;
                        }
                    }
                }
            }
        });
}

/// Render a sortable column header
fn render_sort_header(
    ui: &mut egui::Ui,
    current_column: &mut SortColumn,
    current_direction: &mut SortDirection,
    column: SortColumn,
    label: &str,
) {
    let response = ui.button(label);
    if response.clicked() {
        if *current_column == column {
            *current_direction = match *current_direction {
                SortDirection::Asc => SortDirection::Desc,
                SortDirection::Desc => SortDirection::Asc,
            };
        } else {
            *current_column = column;
            *current_direction = SortDirection::Asc;
        }
    }

    // Show sort indicator
    if *current_column == column {
        let indicator = match *current_direction {
            SortDirection::Asc => " ▲",
            SortDirection::Desc => " ▼",
        };
        ui.label(egui::RichText::new(indicator).small());
    }
}

/// Render timeline graphs using egui_plot
fn render_timeline_graphs(ui: &mut egui::Ui, app_state: &AppState, selected_hop: &Option<usize>) {
    ui.heading("RTT Timeline");

    let hop_numbers = app_state.hop_numbers();
    if hop_numbers.is_empty() {
        ui.label("No data available for plotting yet...");
        return;
    }

    // Determine which hops to show
    let hops_to_show = match selected_hop {
        Some(idx) => {
            if let Some(&hop_num) = hop_numbers.get(*idx) {
                vec![hop_num]
            } else {
                hop_numbers.clone()
            }
        }
        None => hop_numbers.clone(),
    };

    // Build plot data for each hop
    let mut lines = Vec::new();
    let mut legend_labels = Vec::new();
    let mut all_points: Vec<(f64, f64)> = Vec::new();

    for &hop_num in &hops_to_show {
        if let Some(hop_state) = app_state.get_hop_state(hop_num) {
            // Get last 60 seconds of data (or all data if less)
            let now = std::time::Instant::now();
            let recent_results: Vec<_> = hop_state
                .results
                .iter()
                .rev()
                .take_while(|r| now.duration_since(r.timestamp).as_secs_f64() <= 60.0)
                .collect();

            // Reverse back to chronological order
            let recent_results: Vec<_> = recent_results.into_iter().rev().collect();

            if !recent_results.is_empty() {
                // Convert to PlotPoints with time offset from first point
                let first_time = recent_results[0].timestamp;
                let points: PlotPoints = recent_results
                    .iter()
                    .map(|r| {
                        let time_offset = r.timestamp.duration_since(first_time).as_secs_f64();
                        let pt = [time_offset, r.rtt_ms];
                        all_points.push((time_offset, r.rtt_ms));
                        pt
                    })
                    .collect();

                let color = hop_color(hop_num);
                lines.push(Line::new(points).width(1.5).color(color));
                legend_labels.push(format!("Hop {}", hop_num));
            }
        }
    }

    if lines.is_empty() {
        ui.label("No RTT data available for plotting yet...");
        return;
    }

    // Calculate plot bounds from all points
    let _max_time = all_points
        .iter()
        .map(|(t, _)| t)
        .fold(0.0, |max, t| t.max(max));
    let _max_rtt = all_points
        .iter()
        .map(|(_, r)| r)
        .fold(0.0, |max, r| r.max(max));

    // Set up the plot with proper ranges
    let plot = Plot::new("rtt_timeline")
        .width(400.0)
        .height(300.0)
        .x_axis_label("Time (seconds)")
        .y_axis_label("RTT (ms)");

    plot.show(ui, |plot_ui: &mut egui_plot::PlotUi| {
        for line in lines {
            plot_ui.line(line);
        }
    });

    // Show legend below the plot
    ui.separator();
    ui.horizontal(|ui| {
        for (i, label) in legend_labels.iter().enumerate() {
            let color = hop_color(hops_to_show[i]);
            // Create a colored square for the legend
            let rect = ui.available_rect_before_wrap();
            let square_size = egui::vec2(16.0, 16.0);
            let square_rect = egui::Rect::from_min_size(rect.min, square_size);
            ui.painter().rect_filled(square_rect, 0.0, color);
            ui.label(label);
            ui.add_space(15.0);
        }
    });
}

/// Get IP address for a hop from AppState
fn get_hop_ip(app_state: &AppState, hop_num: u8) -> String {
    app_state
        .get_hop_ip(hop_num)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Render a simple loading screen while the engine initializes
#[allow(dead_code)]
pub fn render_loading(ctx: &egui::Context) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.heading("RustyPlot");
        ui.label("Initializing network engine...");
        ui.add(egui::Spinner::default());
    });
}
