# NetGuard 🛡️

**Real-time network traffic analyzer & intrusion detection system with CLI and Web GUI.**

NetGuard captures live network traffic using tshark, detects threats with Suricata IDS rules, performs behavioral analysis (beaconing, data exfiltration, anomaly detection), and provides both a hacker-style CLI shell and a modern dark-mode web dashboard.

---

## Features

### Capture & Analysis
- **Zero-drop packet capture** using dumpcap + tshark reprocessing
- **30+ protocol detection** — QUIC, TLS 1.2/1.3, DNS, HTTP, SSH, WebSocket, ARP, ICMPv6, and more
- **Connection tracking** with flow aggregation (src/dst IP, ports, packets, bytes, duration)
- **Directional traffic analysis** — incoming vs outgoing classification
- **IPv6 support** with intelligent display truncation

### Threat Detection
- **Suricata IDS integration** — real-time alert generation from 40,000+ community rules
- **Behavioral tagging** — detects beaconing, data exfiltration, new destinations, anomalous traffic
- **Configurable tuning** — severity remapping, IP allowlists, suppression rules, thresholds

### CLI Shell
- Interactive command-line interface with Rich terminal UI
- Commands: `capture start/stop`, `show stats`, `show alerts`, `show connections`, `session list/load`, `search ip/protocol`, and more
- Live packet feed during capture
- CSV export of captured data

### Web Dashboard (GUI)
- **Dashboard** — live stats, protocol distribution charts, traffic overview
- **Capture** — start/stop captures, live packet feed with auto-scroll
- **Alerts** — severity-filtered alert list, AI-powered alert analysis (Groq), AbuseIPDB IP reputation checks
- **Connections** — paginated connection table with search, protocol/port/tag filters
- **Settings** — system info, session management (load/unload/delete), per-session CSV export

### AI Integration
- **Alert analysis** — AI explains what each alert means, risk level, and recommended actions
- **Connection analysis** — AI analyzes connection patterns and identifies suspicious behavior
- **IP reputation** — AbuseIPDB integration with abuse score, ISP, country, domain, Tor detection
- Powered by Groq API (free tier available)

---

## Prerequisites

Before installing NetGuard, make sure you have these system packages:

### System Dependencies

| Package | Purpose | Install (Debian/Ubuntu) |
|---|---|---|
| **Python 3.10+** | Runtime | `sudo apt install python3 python3-pip python3-venv` |
| **tshark** | Packet dissection | `sudo apt install tshark` |
| **Suricata** | IDS engine | `sudo apt install suricata` |
| **Node.js 18+** | Frontend build (dev only) | `sudo apt install nodejs npm` |

```bash
# Install all system dependencies at once (Debian/Ubuntu/Mint)
sudo apt update
sudo apt install python3 python3-pip python3-venv tshark suricata nodejs npm
```

> **Note:** During tshark installation, select **"Yes"** when asked to allow non-superusers to capture packets, or run NetGuard with `sudo`.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/DamodarPatil/NetGuard.git
cd NetGuard
```

### 2. Set Up Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Build the Web Dashboard

```bash
cd web
npm install
npx vite build
cd ..
```

### 4. Configure (Optional)

Create a config file for AI features and AbuseIPDB:

```bash
mkdir -p ~/.netguard
cat > ~/.netguard/config.json << 'EOF'
{
    "groq_api_key": "your-groq-api-key-here",
    "abuseipdb_api_key": "your-abuseipdb-api-key-here"
}
EOF
```

- **Groq API key** (free): Get from [console.groq.com](https://console.groq.com)
- **AbuseIPDB API key** (free): Get from [abuseipdb.com](https://www.abuseipdb.com)

> Both are optional — NetGuard works fully without them, you just won't have AI analysis and IP reputation features.

---

## Usage

### CLI Mode

```bash
sudo venv/bin/python3 netguard.py
```

> **Important:** Use `sudo venv/bin/python3` (not just `sudo python3`) so that venv packages are available.

**Common CLI commands:**

```
# Capture
set interface wlo1          # Set network interface
capture start               # Start live capture
capture stop                # Stop capture

# View data
show stats                  # Protocol stats for current session
show stats all              # Cumulative stats across all sessions
show alerts                 # View Suricata & behavioral alerts
show connections            # View tracked connections

# Search
search ip 192.168.1.100     # Search by IP address
search protocol QUIC        # Search by protocol
search threat <ip>          # AbuseIPDB reputation check

# Sessions
session list                # List all capture sessions
session load 42             # Load a specific session
session unload              # Return to latest data

# Export
export csv output.csv       # Export current session to CSV
```

### Web Dashboard (GUI)

Start the API server, then open the dashboard:

```bash
# Terminal 1 — Start the backend API
sudo venv/bin/python3 web/api.py

# The dashboard is available at:
# http://localhost:8000
```

The web GUI serves the pre-built frontend from `web/dist/`. No separate frontend server needed.

**For frontend development** (hot reload):

```bash
# Terminal 1 — API server
sudo venv/bin/python3 web/api.py

# Terminal 2 — Vite dev server
cd web && npm run dev
# Dashboard at http://localhost:5173
```

---

## Project Structure

```
NetGuard/
├── netguard.py              # CLI entry point
├── requirements.txt         # Python dependencies
├── cli/                     # CLI shell & display
│   ├── shell.py             # Interactive command handler
│   ├── display.py           # Rich terminal formatting
│   └── banner.py            # ASCII art banner
├── core/                    # Capture & analysis engine
│   ├── tshark_capture.py    # tshark/dumpcap capture pipeline
│   ├── database.py          # SQLite database layer
│   ├── connection_tracker.py # Flow aggregation
│   ├── behavior_engine.py   # Behavioral detection (beaconing, exfil, etc.)
│   └── sniffer.py           # Legacy scapy capture (fallback)
├── config/                  # Detection tuning
│   ├── threshold.config     # Suricata threshold overrides
│   ├── severity_remap.yaml  # Alert severity customization
│   ├── ip_allowlist.txt     # Trusted IPs (suppress alerts)
│   └── tuning.yaml          # Behavioral engine thresholds
├── intelligence/            # Threat detection
│   ├── suricata.py          # Suricata IDS management
│   └── threat_intel.py      # AbuseIPDB integration
├── web/                     # Web dashboard
│   ├── api.py               # FastAPI backend (serves GUI + REST API)
│   ├── src/                 # React frontend source
│   └── dist/                # Built frontend (auto-served by API)
├── data/                    # Runtime data (gitignored)
│   ├── netguard.db          # SQLite database
│   └── *.pcapng             # Capture files
└── logs/                    # Log files (gitignored)
```

---

## Configuration

### Suricata IDS Tuning

NetGuard includes pre-configured Suricata tuning files in `config/`:

- **`threshold.config`** — Suppress noisy rules, rate-limit frequent alerts
- **`severity_remap.yaml`** — Override default severity levels
- **`ip_allowlist.txt`** — Trusted IPs to exclude from alerting
- **`do_not_suppress.yaml`** — Critical rules that should never be suppressed

### Behavioral Engine Tuning

Edit `config/tuning.yaml` to adjust detection thresholds for:

- **Beaconing detection** — interval regularity, minimum connections
- **Data exfiltration** — byte thresholds, upload/download ratios
- **New destination alerts** — minimum history before flagging
- **Anomaly detection** — deviation thresholds from baseline

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Capture** | dumpcap (zero-drop) + tshark (dissection) |
| **IDS** | Suricata with ET Open rules |
| **Database** | SQLite with WAL mode |
| **CLI** | Python + Rich |
| **API** | FastAPI + Uvicorn |
| **Frontend** | React + Vite + Lucide Icons |
| **AI** | Groq API (Llama 3) |
| **Threat Intel** | AbuseIPDB API |

---

## Troubleshooting

### "Permission denied" during capture
```bash
# Always run with sudo for packet capture:
sudo venv/bin/python3 netguard.py
```

### "tshark not found"
```bash
sudo apt install tshark
```

### "Suricata rules not loaded"
```bash
sudo suricata-update    # Download/update community rules
```

### Database locked errors
NetGuard uses SQLite WAL mode to handle concurrent access. If you see lock errors, ensure only one capture is running at a time.

### Web dashboard shows blank page
```bash
# Rebuild the frontend
cd web && npx vite build
```

---

## License

College Project — NetGuard Team
