"""
NetGuard Database Module
SQLite-based storage for connection/flow-level network analysis.

Architecture:
  - connections table: One row per flow (5-tuple), not per packet
  - protocol_stats table: Aggregate protocol counters
  - sessions table: Capture session metadata
  - alerts table: Suricata IDS alerts
  - ip_reputation table: AbuseIPDB cache

The raw pcapng file is the ground truth for individual packets.
This DB stores aggregated summaries for fast querying.
"""
import sqlite3
import os
import threading
from datetime import datetime
from typing import Dict, Optional, List


class NetGuardDatabase:
    """
    Manages SQLite database for connection-level network analysis.
    Stores flow summaries instead of individual packets.
    """
    
    def __init__(self, db_path="data/netguard.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
        # Thread safety lock for database operations
        self._lock = threading.Lock()
        
        # Ensure data directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        
        # Create persistent connection
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Initialize database schema
        self._init_database()
    
    def _init_database(self):
        """Create tables and indexes if they don't exist."""
        # Connection/flow table — one row per 5-tuple flow
        # This is how real enterprise monitors (Zeek, ntopng) store data
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                transport TEXT NOT NULL,
                direction TEXT,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                duration REAL DEFAULT 0,
                total_packets INTEGER DEFAULT 1,
                total_bytes INTEGER DEFAULT 0,
                state TEXT DEFAULT 'ACTIVE',
                tags TEXT DEFAULT '',
                severity TEXT DEFAULT '',
                session_id INTEGER,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        # Protocol statistics table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS protocol_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT UNIQUE NOT NULL,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                last_seen DATETIME
            )
        """)
        
        # Session information table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                interface TEXT,
                pcap_file TEXT,
                status TEXT DEFAULT 'active'
            )
        """)
        
        # Suricata IDS alerts table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                severity TEXT NOT NULL,
                severity_num INTEGER NOT NULL,
                signature TEXT NOT NULL,
                signature_id INTEGER,
                category TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                action TEXT DEFAULT 'allowed',
                session_id INTEGER
            )
        """)

        # IP reputation cache (AbuseIPDB)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                abuse_score INTEGER DEFAULT 0,
                country TEXT,
                isp TEXT,
                is_malicious BOOLEAN DEFAULT 0,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Known destinations table (for new_dest / traffic_anomaly detection)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS known_destinations (
                ip TEXT PRIMARY KEY,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_count INTEGER DEFAULT 1,
                total_bytes_avg REAL DEFAULT 0
            )
        """)

        # Create indexes for connections table
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_src_ip 
            ON connections(src_ip)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_dst_ip 
            ON connections(dst_ip)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_protocol 
            ON connections(protocol)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_start_time 
            ON connections(start_time)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_bytes 
            ON connections(total_bytes)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_direction 
            ON connections(direction)
        """)

        # Auto-migrate: add tags/severity columns if missing (existing DBs)
        try:
            self.cursor.execute("SELECT tags FROM connections LIMIT 1")
        except sqlite3.OperationalError:
            self.cursor.execute("ALTER TABLE connections ADD COLUMN tags TEXT DEFAULT ''")
            self.cursor.execute("ALTER TABLE connections ADD COLUMN severity TEXT DEFAULT ''")

        # Auto-migrate: add pcap_file column to sessions if missing
        try:
            self.cursor.execute("SELECT pcap_file FROM sessions LIMIT 1")
        except sqlite3.OperationalError:
            try:
                self.cursor.execute("ALTER TABLE sessions ADD COLUMN pcap_file TEXT")
            except sqlite3.OperationalError:
                pass  # Read-only DB — skip migration

        # Tags index (must come AFTER migration adds the column)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_tags 
            ON connections(tags)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
            ON alerts(timestamp)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity 
            ON alerts(severity_num)
        """)
        
        # Drop legacy packets table if it exists (data lives in pcapng now)
        self.cursor.execute("DROP TABLE IF EXISTS packets")

        # Drop legacy packet indexes
        for idx in ['idx_packets_timestamp', 'idx_packets_transport_protocol',
                     'idx_packets_application_protocol', 'idx_packets_src_ip',
                     'idx_packets_dst_ip', 'idx_packets_direction']:
            self.cursor.execute(f"DROP INDEX IF EXISTS {idx}")
        
        self.conn.commit()

    # ── Session management ──────────────────────────────────────

    def start_session(self, interface: Optional[str] = None, pcap_file: Optional[str] = None) -> int:
        """
        Start a new capture session.
        
        Args:
            interface: Network interface name
            pcap_file: Path to the pcap capture file
            
        Returns:
            Session ID
        """
        with self._lock:
            self.cursor.execute("""
                INSERT INTO sessions (start_time, interface, pcap_file)
                VALUES (?, ?, ?)
            """, (datetime.now(), interface, pcap_file))
            
            session_id = self.cursor.lastrowid
            self.conn.commit()
            
            return session_id
    
    def end_session(self, session_id: int, total_packets: int, total_bytes: int):
        """
        Mark a session as completed.
        
        Args:
            session_id: ID of the session to end
            total_packets: Total packets captured
            total_bytes: Total bytes transferred
        """
        with self._lock:
            self.cursor.execute("""
                UPDATE sessions 
                SET end_time = ?, 
                    total_packets = ?, 
                    total_bytes = ?,
                    status = 'completed'
                WHERE id = ?
            """, (datetime.now(), total_packets, total_bytes, session_id))
            
            self.conn.commit()

    def get_all_sessions(self) -> List[tuple]:
        """List all capture sessions with aggregated stats.
        
        Returns:
            List of tuples: (id, start_time, end_time, total_packets,
                             total_bytes, interface, pcap_file, alert_count)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT s.id, s.start_time, s.end_time, s.total_packets,
                       s.total_bytes, s.interface, s.pcap_file,
                       COALESCE(a.alert_count, 0) as alert_count
                FROM sessions s
                LEFT JOIN (
                    SELECT session_id, COUNT(*) as alert_count
                    FROM alerts
                    GROUP BY session_id
                ) a ON s.id = a.session_id
                ORDER BY s.id DESC
            """)
        except sqlite3.OperationalError:
            # Fallback: pcap_file column may not exist in older DBs
            cursor.execute("""
                SELECT s.id, s.start_time, s.end_time, s.total_packets,
                       s.total_bytes, s.interface, NULL as pcap_file,
                       COALESCE(a.alert_count, 0) as alert_count
                FROM sessions s
                LEFT JOIN (
                    SELECT session_id, COUNT(*) as alert_count
                    FROM alerts
                    GROUP BY session_id
                ) a ON s.id = a.session_id
                ORDER BY s.id DESC
            """)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_session_stats(self, session_id: int) -> Dict:
        """Get stats for a specific session (same shape as get_cumulative_stats).
        
        Args:
            session_id: ID of the session
        Returns:
            Dict with protocol_stats, direction_counts, totals, etc.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check session exists
        cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
        if not cursor.fetchone():
            conn.close()
            return None

        # Protocol breakdown
        cursor.execute("""
            SELECT protocol, SUM(total_packets) as cnt, SUM(total_bytes) as bytes
            FROM connections WHERE session_id = ?
            GROUP BY protocol ORDER BY cnt DESC
        """, (session_id,))
        protocol_stats = cursor.fetchall()

        # Direction counts
        cursor.execute("""
            SELECT direction, SUM(total_packets) FROM connections
            WHERE session_id = ? AND direction IS NOT NULL AND direction != ''
            GROUP BY direction
        """, (session_id,))
        direction_counts = dict(cursor.fetchall())

        # Totals
        cursor.execute("""
            SELECT COALESCE(SUM(total_packets), 0), COALESCE(SUM(total_bytes), 0)
            FROM connections WHERE session_id = ?
        """, (session_id,))
        total_pkts, total_bytes = cursor.fetchone()

        # Connection count
        cursor.execute("SELECT COUNT(*) FROM connections WHERE session_id = ?", (session_id,))
        connection_count = cursor.fetchone()[0]

        conn.close()
        return {
            'protocol_stats': protocol_stats,
            'direction_counts': direction_counts,
            'total_packets': total_pkts,
            'total_bytes': total_bytes,
            'session_count': 1,
            'connection_count': connection_count,
        }

    def get_recent_session_id(self) -> Optional[int]:
        """Get the ID of the most recent session."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def delete_session(self, session_id: int) -> bool:
        """Cascade-delete a session and all its connections + alerts.
        
        Args:
            session_id: ID of the session to delete
        Returns:
            True if session existed and was deleted, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check existence
        cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
        if not cursor.fetchone():
            conn.close()
            return False

        cursor.execute("DELETE FROM connections WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM alerts WHERE session_id = ?", (session_id,))
        cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        conn.close()
        return True

    def clear_all_sessions(self) -> int:
        """Wipe all session history (sessions, connections, alerts, protocol_stats).
        
        Returns:
            Number of sessions deleted, or -1 on error
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM sessions")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM connections")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM protocol_stats")
            cursor.execute("DELETE FROM sessions")
            conn.commit()
        except sqlite3.OperationalError:
            conn.close()
            return -1
        conn.close()
        return count

    # ── Connection/flow storage ─────────────────────────────────

    def flush_connections(self, flows: list, session_id: int = None):
        """Bulk insert connection/flow summaries from the tracker.
        
        Args:
            flows: List of flow dicts from ConnectionTracker.get_flows()
            session_id: Current capture session ID
        """
        with self._lock:
            try:
                for flow in flows:
                    self.cursor.execute("""
                        INSERT INTO connections (
                            src_ip, dst_ip, src_port, dst_port,
                            protocol, transport, direction,
                            start_time, end_time, duration,
                            total_packets, total_bytes, state,
                            tags, severity, session_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        flow['src_ip'], flow['dst_ip'],
                        flow.get('src_port'), flow.get('dst_port'),
                        flow['protocol'], flow['transport'],
                        flow.get('direction', ''),
                        flow['start_time'], flow['end_time'],
                        flow.get('duration', 0),
                        flow['total_packets'], flow['total_bytes'],
                        flow.get('state', 'ACTIVE'),
                        flow.get('tags', ''),
                        flow.get('severity', ''),
                        session_id,
                    ))
                self.conn.commit()
            except Exception:
                pass  # Don't crash capture on DB errors

    def clear_session_connections(self, session_id: int):
        """Clear connections for a specific session (called before reprocessing)."""
        with self._lock:
            self.cursor.execute("DELETE FROM connections WHERE session_id = ?", (session_id,))
            self.cursor.execute("DELETE FROM protocol_stats")
            self.conn.commit()

    # ── Query methods ───────────────────────────────────────────

    def close(self):
        """Close the database connection."""
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None

    def get_packet_count(self) -> int:
        """Get total packet count (sum across all connections)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COALESCE(SUM(total_packets), 0) FROM connections")
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    
    def get_connection_count(self) -> int:
        """Get total number of connections/flows."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM connections")
        count = cursor.fetchone()[0]
        
        conn.close()
        return count

    def get_protocol_stats(self) -> List[tuple]:
        """
        Get protocol statistics.
        
        Returns:
            List of tuples: (protocol, packet_count, total_bytes)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT protocol, packet_count, total_bytes 
            FROM protocol_stats
            ORDER BY packet_count DESC
        """)
        
        stats = cursor.fetchall()
        conn.close()
        
        return stats

    def get_cumulative_stats(self) -> Dict:
        """Get cumulative stats from all sessions."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Protocol breakdown from connections
        cursor.execute("""
            SELECT protocol, SUM(total_packets) as cnt, SUM(total_bytes) as bytes
            FROM connections
            GROUP BY protocol ORDER BY cnt DESC
        """)
        protocol_stats = cursor.fetchall()

        # Direction counts
        cursor.execute("""
            SELECT direction, SUM(total_packets) FROM connections
            WHERE direction IS NOT NULL AND direction != ''
            GROUP BY direction
        """)
        direction_counts = dict(cursor.fetchall())

        # Totals from connections table (consistent with protocol/direction data)
        cursor.execute("""
            SELECT COALESCE(SUM(total_packets), 0), COALESCE(SUM(total_bytes), 0)
            FROM connections
        """)
        total_pkts, total_bytes = cursor.fetchone()

        # Session count
        cursor.execute("SELECT COUNT(*) FROM sessions")
        session_count = cursor.fetchone()[0]

        # Connection count
        cursor.execute("SELECT COUNT(*) FROM connections")
        connection_count = cursor.fetchone()[0]

        conn.close()
        return {
            'protocol_stats': protocol_stats,  # [(proto, count, bytes), ...]
            'direction_counts': direction_counts,
            'total_packets': total_pkts,
            'total_bytes': total_bytes,
            'session_count': session_count,
            'connection_count': connection_count,
        }

    def get_connections(self, limit: int = 50, order_by: str = 'total_bytes', session_id: int = None) -> List[tuple]:
        """
        Get connections ordered by the specified column.
        
        Args:
            limit: Maximum number of connections to return
            order_by: Column to sort by (total_bytes, total_packets, duration, start_time)
            session_id: If set, filter to this session only
            
        Returns:
            List of tuples with connection data
        """
        # Whitelist allowed order columns
        allowed = {'total_bytes', 'total_packets', 'duration', 'start_time'}
        if order_by not in allowed:
            order_by = 'total_bytes'
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            cursor.execute(f"""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE session_id = ?
                ORDER BY {order_by} DESC
                LIMIT ?
            """, (session_id, limit))
        else:
            cursor.execute(f"""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                ORDER BY {order_by} DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows

    def search_by_ip(self, ip_address: str, session_id: int = None) -> List[tuple]:
        """
        Search connections involving an IP address.
        
        Args:
            ip_address: IP address to search for
            session_id: If set, filter to this session only
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE (src_ip = ? OR dst_ip = ?) AND session_id = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (ip_address, ip_address, session_id))
        else:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (ip_address, ip_address))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows
    
    def search_by_protocol(self, protocol: str, session_id: int = None) -> List[tuple]:
        """
        Search connections by protocol.
        
        Args:
            protocol: Protocol name (TCP, QUIC, DNS, TLSv1.3, etc.)
            session_id: If set, filter to this session only
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE (UPPER(protocol) = UPPER(?) OR UPPER(transport) = UPPER(?)) AND session_id = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (protocol, protocol, session_id))
        else:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE UPPER(protocol) = UPPER(?) OR UPPER(transport) = UPPER(?)
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (protocol, protocol))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows

    def search_by_port(self, port: int, session_id: int = None) -> List[tuple]:
        """
        Search connections by port number.
        
        Args:
            port: Port number to search for
            session_id: If set, filter to this session only
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE (src_port = ? OR dst_port = ?) AND session_id = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (port, port, session_id))
        else:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE src_port = ? OR dst_port = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (port, port))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows
    
    def get_top_talkers(self, limit: int = 10, session_id: int = None) -> List[tuple]:
        """
        Get most active IP addresses by total bytes transferred.
        
        Args:
            limit: Number of top IPs to return
            session_id: If set, filter to this session only
            
        Returns:
            List of tuples: (ip, total_connections, total_packets, total_bytes)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            cursor.execute("""
                SELECT ip, COUNT(*) as connections, 
                       SUM(packets) as total_packets,
                       SUM(bytes) as total_bytes
                FROM (
                    SELECT src_ip as ip, total_packets as packets, total_bytes as bytes FROM connections WHERE session_id = ?
                    UNION ALL
                    SELECT dst_ip as ip, total_packets as packets, total_bytes as bytes FROM connections WHERE session_id = ?
                )
                GROUP BY ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (session_id, session_id, limit))
        else:
            cursor.execute("""
                SELECT ip, COUNT(*) as connections, 
                       SUM(packets) as total_packets,
                       SUM(bytes) as total_bytes
                FROM (
                    SELECT src_ip as ip, total_packets as packets, total_bytes as bytes FROM connections
                    UNION ALL
                    SELECT dst_ip as ip, total_packets as packets, total_bytes as bytes FROM connections
                )
                GROUP BY ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
        
        talkers = cursor.fetchall()
        conn.close()
        
        return talkers
    
    def get_database_size(self) -> str:
        """Get human-readable database size."""
        if not os.path.exists(self.db_path):
            return "0 B"
        
        size_bytes = os.path.getsize(self.db_path)
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        
        return f"{size_bytes:.2f} TB"
    
    def clear_old_data(self, days: int = 30):
        """
        Delete connections older than specified days.
        
        Args:
            days: Delete connections older than this many days
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM connections
            WHERE start_time < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def delete_connections_by_date(self, date_str: str) -> int:
        """
        Delete connections for a specific date.

        Args:
            date_str: Date string in YYYY-MM-DD format
            
        Returns:
            Number of deleted connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM connections
            WHERE date(start_time) = ?
        """, (date_str,))
        
        deleted = cursor.rowcount
        
        # Recalculate protocol_stats from remaining connections
        if deleted > 0:
            cursor.execute("DELETE FROM protocol_stats")
            cursor.execute("""
                INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                SELECT 
                    protocol,
                    SUM(total_packets) as packet_count,
                    SUM(total_bytes) as total_bytes,
                    MAX(end_time) as last_seen
                FROM connections
                GROUP BY protocol
            """)
        
        conn.commit()
        conn.close()
        
        return deleted

    def export_to_csv(self, output_file: str, limit: Optional[int] = None, session_id: int = None):
        """
        Export connections to CSV file.
        
        Args:
            output_file: Path to output CSV file
            limit: Maximum number of records to export (None = all)
            session_id: If set, filter to this session only
        """
        import csv
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if session_id is not None:
            query = """
                SELECT id, src_ip, dst_ip, src_port, dst_port,
                       protocol, transport, direction,
                       start_time, end_time, duration,
                       total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE session_id = ?
                ORDER BY total_bytes DESC
            """
            if limit:
                query += f" LIMIT {limit}"
            cursor.execute(query, (session_id,))
        else:
            query = """
                SELECT id, src_ip, dst_ip, src_port, dst_port,
                       protocol, transport, direction,
                       start_time, end_time, duration,
                       total_packets, total_bytes, state,
                       tags, severity
                FROM connections 
                ORDER BY total_bytes DESC
            """
            if limit:
                query += f" LIMIT {limit}"
            cursor.execute(query)
        rows = cursor.fetchall()
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Connection_ID', 'Source_IP', 'Destination_IP',
                'Source_Port', 'Destination_Port',
                'Protocol', 'Transport', 'Direction',
                'Start_Time', 'End_Time', 'Duration_Seconds',
                'Total_Packets', 'Total_Bytes', 'State',
                'Tags', 'Severity'
            ])
            writer.writerows(rows)
        
        conn.close()
        
        return len(rows)

    # ── Alert methods (Suricata IDS) ──────────────────────────

    def insert_alert(self, alert: Dict, session_id: int = None):
        """Insert a Suricata alert into the database."""
        with self._lock:
            try:
                self.cursor.execute("""
                    INSERT INTO alerts (timestamp, severity, severity_num, signature,
                        signature_id, category, src_ip, dst_ip, src_port, dst_port,
                        proto, action, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get('timestamp', ''),
                    alert.get('severity', 'LOW'),
                    alert.get('severity_num', 3),
                    alert.get('signature', ''),
                    alert.get('signature_id', 0),
                    alert.get('category', ''),
                    alert.get('src_ip', ''),
                    alert.get('dst_ip', ''),
                    alert.get('src_port'),
                    alert.get('dst_port'),
                    alert.get('proto', ''),
                    alert.get('action', 'allowed'),
                    session_id,
                ))
                self.conn.commit()
            except Exception:
                pass

    def get_alerts(self, limit: int = 100, session_id: int = None) -> List[tuple]:
        """Get recent alerts ordered by timestamp descending."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if session_id is not None:
            cursor.execute("""
                SELECT timestamp, severity, signature, category,
                       src_ip, dst_ip, dst_port, proto
                FROM alerts
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
            """, (session_id, limit))
        else:
            cursor.execute("""
                SELECT timestamp, severity, signature, category,
                       src_ip, dst_ip, dst_port, proto
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_threat_summary(self, session_id: int = None) -> Dict:
        """Get a summary of threats: severity counts, top attackers, top signatures."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        where = "WHERE session_id = ?" if session_id is not None else ""
        params = (session_id,) if session_id is not None else ()

        # Severity counts
        cursor.execute(f"SELECT severity, COUNT(*) FROM alerts {where} GROUP BY severity", params)
        severity_counts = dict(cursor.fetchall())

        # Top source IPs (attackers)
        cursor.execute(f"""
            SELECT src_ip, COUNT(*) as cnt FROM alerts {where}
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """, params)
        top_attackers = cursor.fetchall()

        # Top signatures
        cursor.execute(f"""
            SELECT signature, COUNT(*) as cnt FROM alerts {where}
            GROUP BY signature ORDER BY cnt DESC LIMIT 10
        """, params)
        top_signatures = cursor.fetchall()

        # Total
        cursor.execute(f"SELECT COUNT(*) FROM alerts {where}", params)
        total = cursor.fetchone()[0]

        conn.close()
        return {
            'total': total,
            'severity_counts': severity_counts,
            'top_attackers': top_attackers,
            'top_signatures': top_signatures,
        }

    def get_alert_count(self) -> int:
        """Get total alert count."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def cache_ip_reputation(self, ip: str, abuse_score: int, country: str = '',
                            isp: str = ''):
        """Cache an IP reputation result from AbuseIPDB."""
        with self._lock:
            try:
                self.cursor.execute("""
                    INSERT OR REPLACE INTO ip_reputation
                        (ip, abuse_score, country, isp, is_malicious, last_checked)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (ip, abuse_score, country, isp, abuse_score > 50))
                self.conn.commit()
            except Exception:
                pass

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Get cached IP reputation, or None if not cached."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT abuse_score, country, isp, is_malicious, last_checked
            FROM ip_reputation WHERE ip = ?
        """, (ip,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'abuse_score': row[0], 'country': row[1], 'isp': row[2],
                'is_malicious': bool(row[3]), 'last_checked': row[4],
            }
        return None

    # ── Behavioral tagging methods ────────────────────────────

    def get_known_destinations(self, ips: set) -> set:
        """Check which IPs are already known destinations.
        
        Args:
            ips: Set of IP addresses to check
        Returns:
            Set of IPs that are already in known_destinations table
        """
        if not ips:
            return set()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(ips))
        cursor.execute(f"""
            SELECT ip FROM known_destinations WHERE ip IN ({placeholders})
        """, list(ips))
        known = {row[0] for row in cursor.fetchall()}
        conn.close()
        return known

    def update_known_destinations(self, flows: list):
        """Update known_destinations with IPs from current flows.
        
        For new IPs: insert with current bytes as initial average.
        For existing IPs: update rolling average and session count.
        """
        # Aggregate bytes per destination
        dst_bytes: Dict[str, int] = {}
        for flow in flows:
            dst = flow.get('dst_ip', '')
            if dst:
                dst_bytes[dst] = dst_bytes.get(dst, 0) + flow.get('total_bytes', 0)
        
        if not dst_bytes:
            return

        with self._lock:
            try:
                for ip, total_bytes in dst_bytes.items():
                    # Try insert, on conflict update rolling average
                    self.cursor.execute("""
                        INSERT INTO known_destinations (ip, first_seen, session_count, total_bytes_avg)
                        VALUES (?, CURRENT_TIMESTAMP, 1, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            session_count = session_count + 1,
                            total_bytes_avg = (
                                total_bytes_avg * (session_count - 1) + ?
                            ) / session_count
                    """, (ip, total_bytes, total_bytes))
                self.conn.commit()
            except Exception:
                pass

    def get_destination_averages(self, ips: set) -> Dict[str, float]:
        """Get rolling byte averages for destination IPs.
        
        Returns:
            Dict mapping IP → average_bytes
        """
        if not ips:
            return {}
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(ips))
        cursor.execute(f"""
            SELECT ip, total_bytes_avg FROM known_destinations
            WHERE ip IN ({placeholders}) AND session_count >= 2
        """, list(ips))
        avgs = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return avgs

    def search_by_tag(self, tag: str, session_id: int = None) -> List[tuple]:
        """Search connections by behavioral tag.
        
        Args:
            tag: Tag name to search for (e.g., 'beaconing', 'data_exfil')
            session_id: If set, filter to this session only
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if session_id is not None:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE tags LIKE ? AND session_id = ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (f'%{tag}%', session_id))
        else:
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port,
                       protocol, direction, start_time, end_time,
                       duration, total_packets, total_bytes, state,
                       tags, severity
                FROM connections
                WHERE tags LIKE ?
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (f'%{tag}%',))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_tag_summary(self) -> Dict:
        """Get summary of behavioral tags: counts by tag and severity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get all tagged connections
        cursor.execute("""
            SELECT tags, severity, COUNT(*) as cnt
            FROM connections
            WHERE tags != '' AND tags IS NOT NULL
            GROUP BY tags, severity
            ORDER BY cnt DESC
        """)
        rows = cursor.fetchall()

        # Parse into structured summary
        tag_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        total = 0
        for tags_str, severity, cnt in rows:
            total += cnt
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + cnt
            for tag in tags_str.split(','):
                tag = tag.strip()
                if tag:
                    tag_counts[tag] = tag_counts.get(tag, 0) + cnt

        conn.close()
        return {
            'total_tagged': total,
            'tag_counts': tag_counts,
            'severity_counts': severity_counts,
        }
