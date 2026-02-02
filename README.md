# NetGuard 🛡️

**Network monitoring reimagined: Automated decisions, not raw data.**

## Philosophy

- **Wireshark** = Microscope (manual deep-dive analysis)
- **NetGuard** = Security Camera (automated monitoring)

We show **decisions and status**, not packet dumps.

## Features (Planned)

- ✅ Real-time packet capture
- 🔄 Behavioral tagging (e.g., "Scanner", "Downloader")
- 🔄 Anomaly detection
- 🔄 Human-readable alerts
- 🔄 One-click PDF reporting
- 🔄 Modern dark-mode GUI
- 🔄 Hacker-style CLI

## Tech Stack

- **Backend**: Python 3.10+, Scapy, SQLite
- **GUI**: CustomTkinter
- **CLI**: Rich
- **Platform**: Linux Mint

## Quick Start

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Activate the environment
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Test Packet Capture

```bash
sudo venv/bin/python3 test_sniffer.py
```

> **Note**: Use `sudo venv/bin/python3` (not just `sudo python3`) to ensure scapy is available.

## Project Structure

```
NetGuard/
├── core/              # Packet capture & database
├── intelligence/      # 🧠 Behavioral tagging & anomaly detection
├── gui/               # CustomTkinter interface
├── cli/               # Rich terminal UI
├── utils/             # Helpers & parsers
└── reports/           # PDF generation
```

## Development Roadmap

**Phase 1** (Current): Basic packet capture ✅  
**Phase 2**: SQLite database integration  
**Phase 3**: Behavioral tagging engine  
**Phase 4**: CLI interface with Rich  
**Phase 5**: GUI with CustomTkinter  
**Phase 6**: PDF reporting  

## License

College Project - NetGuard Team
