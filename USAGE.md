# NetGuard Usage Guide

## Running the Sniffer

### Basic Usage
```bash
sudo venv/bin/python3 test_sniffer.py
```

### Understanding the Output

#### Real-time Capture Display
```
🛡️  NetGuard Monitoring Started
Interface: All
Log File: network_log.csv
Packets to Capture: 50
----------------------------------------------------------------------

[2026-02-02 17:30:45] DNS    | 10.71.160.96       → 1.1.1.1            | Size: 74    | Domain Name Resolution
[2026-02-02 17:30:45] TCP    | 10.71.160.96       → 142.250.80.46      | Size: 60    | HTTPS Secure Web (443)
[2026-02-02 17:30:45] QUIC   | 10.71.160.96       → 142.250.80.46      | Size: 1200  | QUIC (HTTP/3) Traffic
[2026-02-02 17:30:46] ICMP   | 10.71.160.96       → 8.8.8.8            | Size: 64    | Ping Request/Reply
[2026-02-02 17:30:46] TCP    | 192.168.1.100      → 52.168.117.170     | Size: 52    | TCP Connection :8080
[2026-02-02 17:30:47] IPv6   | 2409:40c4:2b:a...  → 2001:4860:4860...  | Size: 120   | Raw IPv6
[2026-02-02 17:30:47] ARP    | 192.168.1.1        → 192.168.1.100      | Size: 42    | Who has 192.168.1.100?
```

#### Session Summary (on Ctrl+C or completion)
```
======================================================================
🛡️  NetGuard Session Summary
======================================================================
Total Packets Captured: 237
Log File: network_log.csv

Protocol Breakdown:
----------------------------------------
  TCP        :    142 packets ( 59.9%)
  DNS        :     38 packets ( 16.0%)
  QUIC       :     28 packets ( 11.8%)
  ICMP       :     15 packets (  6.3%)
  UDP        :     10 packets (  4.2%)
  ARP        :      4 packets (  1.7%)
======================================================================
```

## Features Explained

### 1. Smart Protocol Detection
- **QUIC Detection**: Automatically identifies UDP port 443 as QUIC (HTTP/3)
- **Common Services**: Auto-tags HTTP (80), HTTPS (443), SSH (22), FTP (21), RDP (3389)
- **DNS Identification**: Recognizes port 53 traffic as DNS queries

### 2. IPv6 Handling
**Display** (console output):
```
IPv6   | 2409:40c4:2b:a...  → 2001:4860:4860...
```
Truncated to 15 chars + "..." for alignment

**Storage** (CSV file):
```
2409:40c4:2b:a712:fe34:92db:1a23:db05
```
Full address preserved in network_log.csv

### 3. CSV Log File
Location: `network_log.csv` (root of project)

Format:
```csv
Timestamp,Source,Destination,Protocol,Size,Info
2026-02-02 17:30:45,10.71.160.96,1.1.1.1,DNS,74,Domain Name Resolution
2026-02-02 17:30:45,10.71.160.96,142.250.80.46,TCP,60,HTTPS Secure Web (443)
2026-02-02 17:30:47,2409:40c4:2b:a712:fe34:92db:1a23:db05,2001:4860:4860::8888,IPv6,120,Raw IPv6
```

### 4. Traffic Statistics
Automatically tracked:
- Total packet count
- Per-protocol breakdown
- Percentage distribution
- Displayed on exit (Ctrl+C or completion)

## Advanced Usage

### Capture Specific Interface
```python
from core.sniffer import PacketSniffer

sniffer = PacketSniffer(interface="eth0")
sniffer.start(count=100)
```

### Custom Log File
```python
sniffer = PacketSniffer(interface=None, log_file="logs/capture_2026_02_02.csv")
sniffer.start(count=0)  # 0 = infinite capture
```

### Infinite Capture (until Ctrl+C)
```python
sniffer = PacketSniffer()
sniffer.start(count=0)
```

## Troubleshooting

### "Interface not found" Error
Run this to see available interfaces:
```python
from scapy.all import get_if_list
print(get_if_list())
```

### "Permission denied" Error
You must run with sudo:
```bash
sudo venv/bin/python3 test_sniffer.py
```

### No Packets Captured
1. Check if you're generating network traffic (ping, curl, browse)
2. Verify interface is active: `ip link show`
3. Some interfaces require promiscuous mode

## Architecture Notes

### Design Philosophy
The sniffer follows a **clean separation of concerns**:

1. **Data Extraction** (`analyze_packet`)
   - Returns structured dictionary
   - Full data for storage
   - Independent of display logic

2. **Display Logic** (`packet_callback`)
   - Uses `display_src`/`display_dst` for console
   - Truncates IPv6 for alignment

3. **Storage Logic** (`_log_to_csv`)
   - Uses `src`/`dst` (full addresses)
   - Permanent record

This makes it easy to:
- Add a GUI later (just consume the `packet_data` dict)
- Change display format without touching core logic
- Add database storage alongside CSV

## Example: Generating Test Traffic

Terminal 1 (Sniffer):
```bash
sudo venv/bin/python3 test_sniffer.py
```

Terminal 2 (Generate traffic):
```bash
# DNS queries
ping -c 5 google.com

# HTTP/HTTPS
curl http://example.com
curl https://google.com

# QUIC (HTTP/3) - browsers use this
# Just browse with Chrome/Firefox

# ICMP
ping -c 10 8.8.8.8
```

## What's Next?

Phase 2 will add:
- SQLite database storage
- Behavioral IP tagging
- Anomaly detection rules

Stay tuned!
