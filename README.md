# FlowSentrix 🛡️

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/DamodarPatil/FlowSentrix?style=for-the-badge&logo=github)](https://github.com/DamodarPatil/FlowSentrix)
[![GitHub License](https://img.shields.io/github/license/DamodarPatil/FlowSentrix?style=for-the-badge)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)

</div>

**Real-time network traffic analyzer & intrusion detection system with CLI and Web GUI.**

FlowSentrix captures live network traffic using tshark, detects threats with Suricata IDS rules, performs behavioral analysis (beaconing, data exfiltration, anomaly detection), and provides both a hacker-style CLI shell and a modern dark-mode web dashboard.

> **Perfect for:** Security analysts, network administrators, SOC teams, incident responders, and cybersecurity researchers.

---

## 📑 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Roadmap](#roadmap)

---

## ⚡ Quick Start

**30-second setup (Linux/Ubuntu):**

```bash
# Install dependencies
sudo apt update && sudo apt install python3 python3-pip python3-venv tshark suricata nodejs npm

# Clone & setup
git clone https://github.com/DamodarPatil/FlowSentrix.git
cd FlowSentrix
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd web && npm install && npx vite build && cd ..

# Run CLI (hacker mode)
sudo venv/bin/python3 flowsentrix.py

# Or run Web Dashboard (two terminals)
# Terminal 1:
sudo venv/bin/python3 web/api.py
# Terminal 2:
cd web && npm run dev  # Open http://localhost:5173
```

---

## 🎯 Key Use Cases

| Use Case | Why FlowSentrix |
|----------|---|
| 🏢 **Network Monitoring** | Real-time visibility into all network traffic with protocol detection |
| 🔍 **Threat Hunting** | Detect beaconing, C2 communication, data exfiltration, anomalies |
| 🚨 **Incident Response** | Quickly investigate network incidents with connection tracking & behavioral analysis |
| 📊 **SOC Operations** | Alert correlation, AI-powered severity assessment, IP reputation checks |
| 👤 **Security Research** | Analyze traffic patterns, test IDS detection, study network behavior |
| 🎓 **Cybersecurity Training** | Learn network protocols, intrusion detection, incident response |

---

## 📊 Features

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

Before installing FlowSentrix, make sure you have these system packages:

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

> **Note:** During tshark installation, select **"Yes"** when asked to allow non-superusers to capture packets, or run FlowSentrix with `sudo`.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/DamodarPatil/FlowSentrix.git
cd FlowSentrix
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

Create a config file for AI features and AbuseIPDB in your **home directory** (not the project folder):

```bash
mkdir -p ~/.flowsentrix
cat > ~/.flowsentrix/config.json << 'EOF'
{
    "groq_api_key": "your-groq-api-key-here",
    "abuseipdb_api_key": "your-abuseipdb-api-key-here"
}
EOF
```

> **Location:** The `~/.flowsentrix` folder is created in your **home directory** (e.g., `/home/username/.flowsentrix`). The `~` symbol is shell shorthand for your home folder. When running with `sudo`, FlowSentrix automatically looks in the original user's home directory.

- **Groq API key** (free): Get from [console.groq.com](https://console.groq.com)
- **AbuseIPDB API key** (free): Get from [abuseipdb.com](https://www.abuseipdb.com)

> Both are optional — FlowSentrix works fully without them, you just won't have AI analysis and IP reputation features.

---

## Usage

### CLI Mode

```bash
sudo venv/bin/python3 flowsentrix.py
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

You need two terminals — one for the backend API and one for the frontend:

```bash
# Terminal 1 — Start the backend API
sudo venv/bin/python3 web/api.py

# Terminal 2 — Start the frontend dev server
cd web && npm run dev
```

The dashboard will be available at **http://localhost:5173**

---

## Project Structure

```
FlowSentrix/
├── flowsentrix.py           # CLI entry point
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
│   ├── flowsentrix.db       # SQLite database
│   └── *.pcapng             # Capture files
└── logs/                    # Log files (gitignored)
```

---

## Configuration

### Suricata IDS Tuning

FlowSentrix includes pre-configured Suricata tuning files in `config/`:

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
sudo venv/bin/python3 flowsentrix.py
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
FlowSentrix uses SQLite WAL mode to handle concurrent access. If you see lock errors, ensure only one capture is running at a time.

### Web dashboard shows blank page
```bash
# Rebuild the frontend
cd web && npx vite build
```

---

## 🚀 Roadmap

**Planned features for upcoming releases:**

- [ ] Machine learning-based anomaly detection
- [ ] Kubernetes network policy recommendations
- [ ] YARA rule integration for malware detection
- [ ] Slack/Teams integration for alerts
- [ ] Time-travel analysis (historical traffic replay)
- [ ] GeoIP mapping for traffic visualization
- [ ] Automated incident enrichment
- [ ] Multi-node aggregation & correlation

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to:
- Report bugs
- Request features
- Submit pull requests
- Set up the development environment

---

## 📞 Support & Community

- 💬 **Discussions:** [GitHub Discussions](https://github.com/DamodarPatil/FlowSentrix/discussions)
- 🐛 **Issues:** [GitHub Issues](https://github.com/DamodarPatil/FlowSentrix/issues)
- 📖 **Documentation:** [GitHub Wiki](https://github.com/DamodarPatil/FlowSentrix/wiki)
- 🔐 **Security:** See [SECURITY.md](SECURITY.md) for vulnerability reporting

---

## License

MIT License — Copyright (c) 2026 Damodar Patil

See [LICENSE](LICENSE) for details.
