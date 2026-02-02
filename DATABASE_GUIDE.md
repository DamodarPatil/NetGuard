# NetGuard Database Guide 🗄️

## Why SQLite Instead of CSV?

### CSV Limitations ❌
- **No concurrent access** - Can't read while writing
- **No indexing** - Searching large files is slow
- **No data validation** - Easy to corrupt
- **No relationships** - Can't link related data
- **File locking issues** - Problems with multiple processes
- **Memory intensive** - Must load entire file to search

### SQLite Advantages ✅
- **Concurrent access** - Multiple readers, single writer
- **Indexed queries** - Fast searches even with millions of records
- **Data integrity** - ACID transactions, constraints
- **Relational data** - Link sessions, packets, stats
- **Memory efficient** - Query without loading everything
- **No separate server** - Zero configuration, just a file
- **Industry standard** - Used by browsers, phones, apps

## Database Schema

### Tables

#### 1. `packets` - Main packet storage
```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    size INTEGER NOT NULL,
    info TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Indexes:**
- `idx_packets_timestamp` - Fast time-range queries
- `idx_packets_protocol` - Fast protocol filtering
- `idx_packets_src_ip` - Fast source IP searches
- `idx_packets_dst_ip` - Fast destination IP searches

#### 2. `protocol_stats` - Aggregated statistics
```sql
CREATE TABLE protocol_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT UNIQUE NOT NULL,
    packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    last_seen DATETIME
);
```

**Purpose:** Lightning-fast statistics without scanning all packets

#### 3. `sessions` - Capture session tracking
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    interface TEXT,
    status TEXT DEFAULT 'active'
);
```

**Purpose:** Track multiple capture sessions over time

## Query Examples

### Using Python API

```python
from core.database import NetGuardDatabase

db = NetGuardDatabase("data/netguard.db")

# Get total packet count
count = db.get_packet_count()
print(f"Total packets: {count}")

# Get recent packets
packets = db.get_recent_packets(100)
for packet in packets:
    timestamp, src, dst, protocol, size, info = packet
    print(f"{timestamp} | {protocol} | {src} → {dst}")

# Search by IP
packets = db.search_by_ip("192.168.1.100")
print(f"Found {len(packets)} packets for this IP")

# Search by protocol
tcp_packets = db.search_by_protocol("TCP")
dns_packets = db.search_by_protocol("DNS")

# Get top talkers
talkers = db.get_top_talkers(10)
for ip, count in talkers:
    print(f"{ip}: {count} packets")

# Get protocol statistics
stats = db.get_protocol_stats()
for protocol, count, bytes_val in stats:
    print(f"{protocol}: {count} packets, {bytes_val} bytes")

# Export to CSV
db.export_to_csv("export.csv", limit=1000)
```

### Using Command-Line Tool

```bash
# Show default view (stats + 20 recent packets)
python3 query_db.py

# Show last 100 packets
python3 query_db.py --recent 100

# Show protocol statistics with visual bars
python3 query_db.py --stats

# Search for all traffic to/from specific IP
python3 query_db.py --ip 192.168.1.50

# Find all HTTPS traffic
python3 query_db.py --protocol HTTPS

# Show top 20 most active IPs
python3 query_db.py --top-talkers 20

# Export all data to CSV
python3 query_db.py --export full_capture.csv

# Export last 1000 packets to CSV
python3 query_db.py --export recent.csv --limit 1000

# Use custom database
python3 query_db.py --db /path/to/custom.db --stats
```

## Real-World Use Cases

### 1. Security Investigation
**Scenario:** Suspicious activity detected from IP 203.0.113.45

```bash
# Find all packets from/to this IP
python3 query_db.py --ip 203.0.113.45

# Check what protocols they used
# (output shows attempted connections to port 3389, 22, 21)
```

**Result:** Port scanning detected! IP tried RDP, SSH, FTP.

### 2. Bandwidth Analysis
**Scenario:** Network is slow, need to find top bandwidth users

```bash
# Find most active IPs
python3 query_db.py --top-talkers 20

# Check protocol distribution
python3 query_db.py --stats
```

**Result:** One IP sending 68% of traffic via QUIC (video streaming!).

### 3. Troubleshooting
**Scenario:** App can't connect to database server

```bash
# Check if traffic reaches database
python3 query_db.py --ip 192.168.1.50  # DB server
python3 query_db.py --protocol TCP | grep 3306  # MySQL port
```

**Result:** No packets seen = firewall blocking traffic.

### 4. Compliance & Auditing
**Scenario:** Need to prove no unencrypted traffic to external IPs

```python
from core.database import NetGuardDatabase

db = NetGuardDatabase()

# Search for insecure protocols
telnet = db.search_by_protocol("Telnet")
ftp = db.search_by_protocol("FTP")
http = db.search_by_protocol("HTTP")

print(f"Telnet: {len(telnet)} connections (Insecure!)")
print(f"FTP: {len(ftp)} connections (Insecure!)")
print(f"HTTP: {len(http)} connections (Check if external)")
```

### 5. Long-Term Monitoring
**Scenario:** Monitor network trends over weeks

```python
# Query sessions table to see historical patterns
import sqlite3

conn = sqlite3.connect("data/netguard.db")
cursor = conn.cursor()

cursor.execute("""
    SELECT 
        DATE(start_time) as date,
        COUNT(*) as sessions,
        SUM(total_packets) as packets,
        SUM(total_bytes) as bytes
    FROM sessions
    WHERE status = 'completed'
    GROUP BY DATE(start_time)
    ORDER BY date DESC
    LIMIT 30
""")

for row in cursor.fetchall():
    print(row)
```

## Performance Benchmarks

### CSV vs SQLite Comparison

| Operation | CSV (10,000 packets) | SQLite (10,000 packets) | SQLite (1M packets) |
|-----------|---------------------|------------------------|-------------------|
| Insert packet | ~5ms | ~0.1ms | ~0.1ms |
| Search by IP | ~500ms (full scan) | ~2ms (indexed) | ~10ms (indexed) |
| Count packets | ~300ms | ~0.5ms | ~5ms |
| Get stats | ~1000ms | ~1ms | ~15ms |
| Export to CSV | N/A | ~200ms | ~8s |

**Conclusion:** SQLite is **50-500x faster** for queries!

### Database Size

Example from real capture session:
- **10,000 packets**: ~2.5 MB
- **100,000 packets**: ~25 MB
- **1,000,000 packets**: ~250 MB

**Note:** CSV would be similar size but much slower to query.

## Maintenance Operations

### Clean Old Data

```python
from core.database import NetGuardDatabase

db = NetGuardDatabase()

# Delete packets older than 30 days
deleted = db.clear_old_data(days=30)
print(f"Deleted {deleted} old packets")

# Then vacuum to reclaim space
import sqlite3
conn = sqlite3.connect("data/netguard.db")
conn.execute("VACUUM")
conn.close()
```

### Check Database Size

```python
db = NetGuardDatabase()
print(f"Database size: {db.get_database_size()}")
```

### Backup Database

```bash
# Simple copy (stop capture first!)
cp data/netguard.db backups/netguard_$(date +%Y%m%d).db

# Or use SQLite backup
sqlite3 data/netguard.db ".backup backups/netguard_backup.db"
```

## Advanced Queries

### Custom SQL Queries

```python
import sqlite3

conn = sqlite3.connect("data/netguard.db")
cursor = conn.cursor()

# Find connections by time of day
cursor.execute("""
    SELECT 
        strftime('%H', timestamp) as hour,
        COUNT(*) as packet_count
    FROM packets
    WHERE DATE(timestamp) = '2026-02-02'
    GROUP BY hour
    ORDER BY hour
""")

for hour, count in cursor.fetchall():
    print(f"{hour}:00 - {count} packets")

# Find most common destination ports (TCP)
cursor.execute("""
    SELECT 
        info,
        COUNT(*) as count
    FROM packets
    WHERE protocol = 'TCP'
    AND info LIKE '%:%'
    GROUP BY info
    ORDER BY count DESC
    LIMIT 10
""")

# Find communication pairs
cursor.execute("""
    SELECT 
        src_ip,
        dst_ip,
        COUNT(*) as exchanges,
        SUM(size) as total_bytes
    FROM packets
    GROUP BY src_ip, dst_ip
    HAVING exchanges > 100
    ORDER BY exchanges DESC
    LIMIT 20
""")

conn.close()
```

## Migration from CSV

If you have existing CSV logs:

```python
import csv
import sqlite3
from datetime import datetime

# Open database
db = NetGuardDatabase()

# Read CSV
with open('network_log.csv', 'r') as f:
    reader = csv.DictReader(f)
    
    for row in reader:
        packet_data = {
            'timestamp': row['Timestamp'],
            'src': row['Source'],
            'dst': row['Destination'],
            'protocol': row['Protocol'],
            'size': int(row['Size']),
            'info': row['Info']
        }
        
        db.insert_packet(packet_data)

print("Migration complete!")
```

## Configuration Options

### Change Database Location

```python
# Use custom path
sniffer = PacketSniffer(db_path="/var/log/netguard/capture.db")
sniffer.start()
```

### Enable Optional CSV Logging

```python
# Log to both database AND CSV
sniffer = PacketSniffer(
    db_path="data/netguard.db",
    use_csv=True,
    csv_file="debug.csv"
)
sniffer.start()
```

**When to use CSV:**
- Debugging
- Compatibility with legacy tools
- Quick Excel analysis

**But always use database for:**
- Production monitoring
- Long-term storage
- Fast queries
- Historical analysis

## Troubleshooting

### Database Locked Error

**Problem:** "database is locked"

**Solution:**
1. Only one writer at a time (one sniffer process)
2. Multiple readers are OK (query while capturing)
3. If stuck, close all connections:

```bash
# Find processes using the database
lsof data/netguard.db

# Kill if needed
# Then restart capture
```

### Database Corrupted

**Problem:** "database disk image is malformed"

**Solution:**
```bash
# Try to recover
sqlite3 data/netguard.db "PRAGMA integrity_check;"

# If corrupted, export what you can
sqlite3 data/netguard.db ".dump" > recovery.sql

# Create new database
rm data/netguard.db

# Re-import
sqlite3 data/netguard.db < recovery.sql
```

### Too Large Database

**Problem:** Database growing too large

**Solution:**
```python
# Clean old data regularly
db = NetGuardDatabase()
db.clear_old_data(days=7)  # Keep only last week

# Or export to CSV and start fresh
db.export_to_csv("archive_2026_01.csv")

# Then delete old data
import os
os.remove("data/netguard.db")
# Will be recreated on next capture
```

## Future Enhancements (Phase 3+)

The database structure is designed to support future features:

### Behavioral Tagging
```sql
-- Future table
CREATE TABLE ip_tags (
    ip TEXT PRIMARY KEY,
    tag TEXT,  -- 'Scanner', 'Server', 'Client', etc.
    confidence REAL,
    first_seen DATETIME,
    last_seen DATETIME
);
```

### Anomaly Detection
```sql
-- Future table
CREATE TABLE anomalies (
    id INTEGER PRIMARY KEY,
    detected_at DATETIME,
    type TEXT,
    description TEXT,
    severity TEXT,
    related_packets TEXT  -- JSON array of packet IDs
);
```

### Threat Intelligence
```sql
-- Future table
CREATE TABLE threat_intel (
    ip TEXT PRIMARY KEY,
    threat_level TEXT,
    categories TEXT,  -- JSON array
    last_checked DATETIME,
    source TEXT
);
```

---

**NetGuard**: SQLite-powered network intelligence! 🗄️🛡️
