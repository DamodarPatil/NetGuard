"""
NetGuard Database Module
SQLite-based storage for efficient packet capture analysis.
"""
import sqlite3
import os
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
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Create tables and indexes if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                size INTEGER NOT NULL,
                info TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Protocol statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protocol_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT UNIQUE NOT NULL,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                last_seen DATETIME
            )
        """)
        
        # Session information table
        cursor.execute("""
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
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_timestamp 
            ON packets(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_protocol 
            ON packets(protocol)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_src_ip 
            ON packets(src_ip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_dst_ip 
            ON packets(dst_ip)
        """)
        
        conn.commit()
        conn.close()
    
    def start_session(self, interface: Optional[str] = None) -> int:
        """
        Start a new capture session.
        
        Args:
            interface: Network interface name
            
        Returns:
            Session ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO sessions (start_time, interface)
            VALUES (?, ?)
        """, (datetime.now(), interface))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return session_id
    
    def end_session(self, session_id: int, total_packets: int, total_bytes: int):
        """
        Mark a session as completed.
        
        Args:
            session_id: ID of the session to end
            total_packets: Total packets captured
            total_bytes: Total bytes transferred
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE sessions 
            SET end_time = ?, 
                total_packets = ?, 
                total_bytes = ?,
                status = 'completed'
            WHERE id = ?
        """, (datetime.now(), total_packets, total_bytes, session_id))
        
        conn.commit()
        conn.close()
    
    def insert_packet(self, packet_data: Dict):
        """
        Insert a packet into the database.
        
        Args:
            packet_data: Dictionary containing packet information
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, size, info)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            packet_data['timestamp'],
            packet_data['src'],  # Full IP address
            packet_data['dst'],  # Full IP address
            packet_data['protocol'],
            packet_data['size'],
            packet_data['info']
        ))
        
        # Update protocol statistics
        cursor.execute("""
            INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(protocol) DO UPDATE SET
                packet_count = packet_count + 1,
                total_bytes = total_bytes + ?,
                last_seen = ?
        """, (
            packet_data['protocol'],
            packet_data['size'],
            packet_data['timestamp'],
            packet_data['size'],
            packet_data['timestamp']
        ))
        
        conn.commit()
        conn.close()
    
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
            SELECT timestamp, src_ip, dst_ip, protocol, size, info
            FROM packets
            ORDER BY id DESC
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
            SELECT timestamp, src_ip, dst_ip, protocol, size, info
            FROM packets
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY timestamp DESC
            LIMIT 1000
        """, (ip_address, ip_address))
        
        packets = cursor.fetchall()
        conn.close()
        
        return packets
    
    def search_by_protocol(self, protocol: str) -> List[tuple]:
        """
        Search packets by protocol.
        
        Args:
            protocol: Protocol name (TCP, UDP, DNS, etc.)
            
        Returns:
            List of matching packets
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, src_ip, dst_ip, protocol, size, info
            FROM packets
            WHERE protocol = ?
            ORDER BY timestamp DESC
            LIMIT 1000
        """, (protocol,))
        
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
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def export_to_csv(self, output_file: str, limit: Optional[int] = None):
        """
        Export database to CSV file.
        
        Args:
            output_file: Path to output CSV file
            limit: Maximum number of records to export (None = all)
        """
        import csv
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT timestamp, src_ip, dst_ip, protocol, size, info FROM packets ORDER BY id DESC"
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source', 'Destination', 'Protocol', 'Size', 'Info'])
            writer.writerows(cursor.fetchall())
        
        conn.close()
        
        return cursor.rowcount
