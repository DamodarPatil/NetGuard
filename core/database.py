"""
NetGuard Database Module
SQLite-based storage for efficient packet capture analysis.
"""
import sqlite3
import os
import threading
from datetime import datetime
from typing import Dict, Optional, List


class NetGuardDatabase:
    """
    Manages SQLite database for packet storage and querying.
    Much better than CSV for production use!
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
        # Main packets table - Enhanced with Wireshark-inspired fields
        # Using AUTOINCREMENT to avoid ID conflicts across sessions
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                absolute_timestamp DATETIME NOT NULL,
                relative_time REAL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                transport_protocol TEXT NOT NULL,
                application_protocol TEXT,
                tcp_flags TEXT,
                direction TEXT,
                packet_length INTEGER NOT NULL,
                info TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
                status TEXT DEFAULT 'active'
            )
        """)
        
        # Create indexes for faster queries
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_timestamp 
            ON packets(absolute_timestamp)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_transport_protocol 
            ON packets(transport_protocol)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_application_protocol 
            ON packets(application_protocol)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_src_ip 
            ON packets(src_ip)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_dst_ip 
            ON packets(dst_ip)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_direction 
            ON packets(direction)
        """)
        
        self.conn.commit()
    
    def start_session(self, interface: Optional[str] = None) -> int:
        """
        Start a new capture session.
        
        Args:
            interface: Network interface name
            
        Returns:
            Session ID
        """
        with self._lock:
            self.cursor.execute("""
                INSERT INTO sessions (start_time, interface)
                VALUES (?, ?)
            """, (datetime.now(), interface))
            
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
    
    def insert_packet(self, packet_data: Dict):
        """
        Insert a packet into the database with enhanced fields.
        
        Args:
            packet_data: Dictionary containing packet information
        """
        with self._lock:
            # Let SQLite auto-generate packet_id via AUTOINCREMENT
            self.cursor.execute("""
                INSERT INTO packets (
                    absolute_timestamp, relative_time,
                    src_ip, dst_ip, src_port, dst_port,
                    transport_protocol, application_protocol, tcp_flags,
                    direction, packet_length, info
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet_data['absolute_timestamp'],
                packet_data['relative_time'],
                packet_data['src'],  # Full IP address
                packet_data['dst'],  # Full IP address
                packet_data.get('src_port'),
                packet_data.get('dst_port'),
                packet_data['transport_protocol'],
                packet_data['application_protocol'],
                packet_data.get('tcp_flags'),
                packet_data['direction'],
                packet_data['packet_length'],
                packet_data['info']
            ))
            
            # Update protocol statistics (use application protocol if available, else transport)
            protocol_for_stats = packet_data['application_protocol'] or packet_data['transport_protocol']
            self.cursor.execute("""
                INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(protocol) DO UPDATE SET
                    packet_count = packet_count + 1,
                    total_bytes = total_bytes + ?,
                    last_seen = ?
            """, (
                protocol_for_stats,
                packet_data['packet_length'],
                packet_data['absolute_timestamp'],
                packet_data['packet_length'],
                packet_data['absolute_timestamp']
            ))
            
            self.conn.commit()
    
    def close(self):
        """Close the database connection."""
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None
    
    def get_packet_count(self) -> int:
        """Get total number of packets in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM packets")
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
    
    def get_recent_packets(self, limit: int = 100) -> List[tuple]:
        """
        Get most recent packets.
        
        Args:
            limit: Maximum number of packets to return
            
        Returns:
            List of tuples containing packet data
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT absolute_timestamp, src_ip, dst_ip, 
                   application_protocol, packet_length, info
            FROM packets
            ORDER BY packet_id DESC
            LIMIT ?
        """, (limit,))
        
        packets = cursor.fetchall()
        conn.close()
        
        return packets
    
    def search_by_ip(self, ip_address: str) -> List[tuple]:
        """
        Search packets by IP address (source or destination).
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            List of matching packets
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT absolute_timestamp, src_ip, dst_ip, 
                   application_protocol, packet_length, info
            FROM packets
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY absolute_timestamp DESC
            LIMIT 1000
        """, (ip_address, ip_address))
        
        packets = cursor.fetchall()
        conn.close()
        
        return packets
    
    def search_by_protocol(self, protocol: str) -> List[tuple]:
        """
        Search packets by protocol (searches both transport and application).
        
        Args:
            protocol: Protocol name (TCP, UDP, DNS, HTTPS, etc.)
            
        Returns:
            List of matching packets
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT absolute_timestamp, src_ip, dst_ip, 
                   application_protocol, packet_length, info
            FROM packets
            WHERE UPPER(transport_protocol) = UPPER(?) OR UPPER(application_protocol) = UPPER(?)
            ORDER BY absolute_timestamp DESC
            LIMIT 1000
        """, (protocol, protocol))
        
        packets = cursor.fetchall()
        conn.close()
        
        return packets
    
    def get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """
        Get most active IP addresses.
        
        Args:
            limit: Number of top IPs to return
            
        Returns:
            List of tuples: (ip, packet_count)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT src_ip as ip, COUNT(*) as count
            FROM packets
            GROUP BY src_ip
            ORDER BY count DESC
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
        Delete packets older than specified days.
        
        Args:
            days: Delete packets older than this many days
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM packets
            WHERE absolute_timestamp < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def delete_packets_by_date(self, date_str: str) -> int:
        """
        Delete packets for a specific date.

        Args:
            date_str: Date string in YYYY-MM-DD format
            
        Returns:
            Number of deleted packets
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # SQLite's date() function extracts the date part from the timestamp
        cursor.execute("""
            DELETE FROM packets
            WHERE date(absolute_timestamp) = ?
        """, (date_str,))
        
        deleted = cursor.rowcount
        
        # Recalculate protocol_stats from remaining packets
        if deleted > 0:
            cursor.execute("DELETE FROM protocol_stats")
            cursor.execute("""
                INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                SELECT 
                    COALESCE(application_protocol, transport_protocol) as protocol,
                    COUNT(*) as packet_count,
                    SUM(packet_length) as total_bytes,
                    MAX(absolute_timestamp) as last_seen
                FROM packets
                GROUP BY COALESCE(application_protocol, transport_protocol)
            """)
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def export_to_csv(self, output_file: str, limit: Optional[int] = None):
        """
        Export database to CSV file with all enhanced fields.
        
        Args:
            output_file: Path to output CSV file
            limit: Maximum number of records to export (None = all)
        """
        import csv
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = """
            SELECT packet_id, absolute_timestamp, relative_time,
                   src_ip, dst_ip, src_port, dst_port,
                   transport_protocol, application_protocol, tcp_flags,
                   direction, packet_length, info
            FROM packets 
            ORDER BY packet_id ASC
        """
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Packet_ID', 'Absolute_Timestamp', 'Relative_Time',
                'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port',
                'Transport_Protocol', 'Application_Protocol', 'TCP_Flags',
                'Direction', 'Packet_Length', 'Info'
            ])
            writer.writerows(rows)
        
        conn.close()
        
        return len(rows)

