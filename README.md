# RustyPlot

A lightweight, graphical traceroute and ping utility that reports real-time latency and packet loss. Built with Rust, using TCP-based probes that work without sudo/root privileges.

## Features

- 🚀 **No Sudo Required** - Uses TCP-based traceroute (no raw socket permissions needed)
- 📊 **Real-time Monitoring** - Continuous ping every 1 second with live updates
- 📈 **Timeline Graphs** - Visual RTT history using egui_plot
- 📉 **Packet Loss Tracking** - Rolling buffer of last 100 measurements per hop
- 🎨 **Dark Theme** - High-contrast UI for long-term monitoring
- 🖱️ **Interactive** - Click hops to isolate and inspect in detail

## Installation

### From Source

```bash
git clone https://github.com/yourusername/RustyPlot.git
cd RustyPlot
cargo build --release
```

The binary will be at `target/release/rustyplot`.

### Requirements

- Rust 1.70 or later
- On Linux/macOS: No special permissions required (TCP mode)
- On Windows: Works out of the box

## Usage

### GUI Mode (Default)

```bash
# Trace a hostname
./rustyplot google.com

# Trace an IP address
./rustyplot 8.8.8.8
```

### Console Mode (Testing)

```bash
# Run traceroute without GUI
./rustyplot --console google.com
```

## Interface

### Left Pane - Hop Table
| Column | Description |
|--------|-------------|
| Hop # | Router hop number (1-30) |
| IP Address | Resolved IP of the hop |
| Avg RTT | Average round-trip time (ms) |
| Min RTT | Minimum observed RTT |
| Max RTT | Maximum observed RTT |
| Jitter | RTT variance (ms) |
| Loss % | Packet loss percentage |

**Click any column header to sort.**

### Right Pane - Timeline Graph
- Shows RTT over time for all hops
- Each hop displayed in a different color
- Legend shows hop number and color mapping
- Updates in real-time as pings complete

### Isolate View
Click on any hop in the table to:
- See detailed statistics for that hop
- View recent RTT history (last 20 pings)
- Focus the timeline graph on that hop only

## How It Works

1. **Traceroute Phase**: Discovers network path using TCP SYN probes with increasing TTL
2. **Continuous Ping Phase**: Spawns concurrent tasks to ping each hop every second
3. **Data Collection**: Maintains rolling buffer of last 100 RTT samples per hop
4. **Metrics Calculation**: Computes packet loss, average RTT, min/max, and jitter

## Technical Details

### Protocol
- Uses TCP SYN packets to port 80 for traceroute
- Falls back gracefully to ICMP if available
- No raw socket permissions required

### Concurrency
- Tokio runtime for async network operations
- `Arc<tokio::sync::Mutex<AppState>>` for thread-safe UI updates
- One ping task per hop for parallel measurement

### Data Structures
- `Hop`: Represents a single router in the path
- `AppState`: Shared state between network engine and UI
- Rolling `VecDeque` for efficient buffer management

## Troubleshooting

### "No hops discovered"
- Some networks block traceroute probes
- Try a different target (e.g., `8.8.8.8`, `1.1.1.1`)
- Check firewall settings

### High packet loss
- Normal for intermediate hops (many routers drop probes)
- Focus on the final target's metrics

### Slow traceroute
- Some hops may not respond (blackhole routers)
- Traceroute continues even if intermediate hops timeout
- Typical completion time: 10-20 seconds

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.
