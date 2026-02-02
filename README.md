# NetGuard 🛡️

**Network monitoring reimagined: Automated decisions, not raw data.**

## Philosophy

- **Wireshark** = Microscope (manual deep-dive analysis)
- **NetGuard** = Security Camera (automated monitoring)

We show **decisions and status**, not packet dumps.

## Features (Planned)

- ✅ Real-time packet capture  
- ✅ Smart protocol detection (TCP, UDP, DNS, QUIC, ICMP, ARP)
- ✅ Traffic statistics & session summaries
- ✅ **SQLite database storage** (efficient, queryable)
- ✅ Database query tools (search by IP, protocol, top talkers)
- ✅ Optional CSV export
- ✅ IPv6 support with intelligent display truncation
- ✅ Keyboard interrupt handling (Ctrl+C)
- ✅ Interface validation
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

### 4. Query Captured Data

```bash
# Show statistics and recent packets
python3 query_db.py

# Show last 100 packets
python3 query_db.py --recent 100

# Search by IP
python3 query_db.py --ip 192.168.1.100

# Search by protocol
python3 query_db.py --protocol TCP

# Show top 20 most active IPs
python3 query_db.py --top-talkers 20

# Export to CSV
python3 query_db.py --export output.csv
```

**📚 Documentation:**
- [USAGE.md](USAGE.md) - Detailed usage guide
- [DATABASE_GUIDE.md](DATABASE_GUIDE.md) - SQLite database & queries
- [PROTOCOL_DETECTION.md](PROTOCOL_DETECTION.md) - 40+ protocols detected

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

**Phase 1**: ✅ Production-ready packet capture with logging  
**Phase 2** (Current): ✅ SQLite database integration  
**Phase 3**: Behavioral tagging engine  
**Phase 4**: CLI interface with Rich  
**Phase 5**: GUI with CustomTkinter  
**Phase 6**: PDF reporting

## Current Features

### ✅ Packet Capture Engine
- Captures TCP, UDP, DNS, QUIC (HTTP/3), ICMP, ARP, IPv6
- **Smart protocol detection** (40+ services):
  - **Web**: HTTP, HTTPS, QUIC/HTTP3
  - **Email**: SMTP, POP3, IMAP, IMAPS
  - **Databases**: MySQL, PostgreSQL, MongoDB, Redis
  - **Remote Access**: SSH, RDP, Telnet, FTP
  - **Network Services**: DNS, DHCP, NTP, SNMP, mDNS, NetBIOS
  - **VPN**: OpenVPN, IPSec/IKE
  - **Discovery**: SSDP/UPnP
- **TCP flag analysis** (SYN, SYN-ACK, FIN, RST for connection tracking)
- **ICMP type detection** (Echo Request/Reply, Destination Unreachable, TTL Exceeded)
- **DHCP distinction** (Client vs Server traffic)
- IPv6 support with intelligent display truncation
- Separate data storage vs display logic (GUI-ready architecture)

### ✅ Traffic Statistics
- Real-time protocol counting
- **Total data transferred** (bytes/KB/MB/GB)
- **Average packet size** calculation
- Session summary with percentage breakdown
- **Visual progress bars** for protocol distribution
- Automatic statistics on Ctrl+C

### ✅ Database Storage
- **SQLite database** (`data/netguard.db`) - Primary storage
- Indexed for fast queries (timestamp, protocol, IPs)
- Session tracking with start/end times
- Protocol statistics table for quick analysis
- **Query tools included**:
  - Search by IP address
  - Search by protocol
  - Show top talkers (most active IPs)
  - Export to CSV
  - View recent packets
- Full IPv6 addresses preserved
- Optional CSV export for compatibility

### ✅ Robustness
- Interface validation (checks if interface exists)
- Graceful keyboard interrupt handling
- Comprehensive error messages  

## License

College Project - NetGuard Team
