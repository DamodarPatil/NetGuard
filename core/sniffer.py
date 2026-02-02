"""
NetGuard Packet Sniffer Module
Production-Ready: Phase 2 - SQLite Database Integration
"""
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, get_if_list
from datetime import datetime
import threading
import os
from .database import NetGuardDatabase

class PacketSniffer:
    """
    Core engine to capture and parse network traffic.
    Production-ready with statistics tracking, database storage, and robust error handling.
    """
    
    def __init__(self, interface=None, db_path="data/netguard.db"):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to sniff (None = all interfaces)
            db_path: Path to SQLite database file (default: data/netguard.db)
        """
        self.interface = interface
        self.db_path = db_path
        self.stop_sniffing = threading.Event()
        self.packets_captured = 0
        
        # Traffic statistics tracking
        self.protocol_counts = {}
        self.total_bytes = 0
        
        # Initialize database
        self.db = NetGuardDatabase(db_path)
        self.session_id = None

    def _validate_interface(self):
        """Validate that the specified interface exists."""
        if self.interface is None:
            return True  # None means use default/all interfaces
        
        available_interfaces = get_if_list()
        if self.interface not in available_interfaces:
            raise ValueError(
                f"Interface '{self.interface}' not found!\n"
                f"Available interfaces: {', '.join(available_interfaces)}"
            )
        return True

    def _truncate_ipv6(self, ipv6_addr):
        """Truncate IPv6 address to 15 characters for display."""
        if len(ipv6_addr) > 15:
            return ipv6_addr[:15] + "..."
        return ipv6_addr

    def get_protocol_name(self, protocol_num):
        """Helper to convert protocol numbers to names."""
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocol_map.get(protocol_num, str(protocol_num))

    def analyze_packet(self, packet):
        """
        Extracts structured data from a raw packet.
        
        Architectural Design:
        - Returns a dictionary with FULL data (src, dst) for storage
        - Adds display_src and display_dst for terminal output
        - Keeps data extraction separate from presentation logic
        
        Returns:
            Dictionary with packet data, or None if packet should be ignored
        """
        packet_data = {}
        
        # 1. Basic Info
        packet_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_data["size"] = len(packet)
        
        # 2. Extract IP Layer (store FULL addresses)
        is_ipv6 = False
        
        if IP in packet:
            packet_data["src"] = packet[IP].src
            packet_data["dst"] = packet[IP].dst
            packet_data["protocol"] = self.get_protocol_name(packet[IP].proto)
            
        elif IPv6 in packet:
            # Store FULL IPv6 address
            packet_data["src"] = packet[IPv6].src
            packet_data["dst"] = packet[IPv6].dst
            packet_data["protocol"] = "IPv6"
            is_ipv6 = True
            
        elif ARP in packet:
            packet_data["src"] = packet[ARP].psrc
            packet_data["dst"] = packet[ARP].pdst
            packet_data["protocol"] = "ARP"
            packet_data["info"] = f"Who has {packet[ARP].pdst}?"
            # Display addresses (no truncation needed for ARP)
            packet_data["display_src"] = packet_data["src"]
            packet_data["display_dst"] = packet_data["dst"]
            return packet_data
            
        else:
            return None  # Ignore non-IP/ARP traffic
        
        # 3. Create display versions (truncate IPv6 if needed)
        if is_ipv6:
            packet_data["display_src"] = self._truncate_ipv6(packet_data["src"])
            packet_data["display_dst"] = self._truncate_ipv6(packet_data["dst"])
        else:
            packet_data["display_src"] = packet_data["src"]
            packet_data["display_dst"] = packet_data["dst"]
        
        # 4. Protocol-specific details & Human-Readable Info
        packet_data["info"] = "Unknown Protocol"  # Default (never empty)
        
        if TCP in packet:
            packet_data["protocol"] = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Smart Tagging (NetGuard Intelligence) - Enhanced
            if dst_port == 80 or src_port == 80:
                packet_data["info"] = "HTTP | Unencrypted Web Traffic"
            elif dst_port == 443 or src_port == 443:
                packet_data["info"] = "HTTPS | Encrypted Web Browsing"
            elif dst_port == 22 or src_port == 22:
                packet_data["info"] = "SSH | Secure Remote Shell"
            elif dst_port == 21 or src_port == 21:
                packet_data["info"] = "FTP | File Transfer (Unencrypted)"
            elif dst_port == 20 or src_port == 20:
                packet_data["info"] = "FTP-DATA | Active File Transfer"
            elif dst_port == 3389 or src_port == 3389:
                packet_data["info"] = "RDP | Remote Desktop Connection"
            elif dst_port == 25 or src_port == 25:
                packet_data["info"] = "SMTP | Outgoing Email Server"
            elif dst_port == 587 or src_port == 587:
                packet_data["info"] = "SMTP | Email Submission (TLS)"
            elif dst_port == 110 or src_port == 110:
                packet_data["info"] = "POP3 | Email Retrieval"
            elif dst_port == 143 or src_port == 143:
                packet_data["info"] = "IMAP | Email Sync"
            elif dst_port == 993 or src_port == 993:
                packet_data["info"] = "IMAPS | Secure Email Sync"
            elif dst_port == 3306 or src_port == 3306:
                packet_data["info"] = "MySQL | Database Connection"
            elif dst_port == 5432 or src_port == 5432:
                packet_data["info"] = "PostgreSQL | Database Query"
            elif dst_port == 27017 or src_port == 27017:
                packet_data["info"] = "MongoDB | NoSQL Database"
            elif dst_port == 6379 or src_port == 6379:
                packet_data["info"] = "Redis | Cache/Data Store"
            elif dst_port == 8080 or src_port == 8080:
                packet_data["info"] = "HTTP-ALT | Web Proxy/Dev Server"
            elif dst_port == 8443 or src_port == 8443:
                packet_data["info"] = "HTTPS-ALT | Alternate Secure Web"
            elif dst_port == 23 or src_port == 23:
                packet_data["info"] = "Telnet | Insecure Remote Access"
            else:
                # Provide context based on TCP flags
                if flags == 0x02:  # SYN
                    packet_data["info"] = f"TCP SYN | Connection Attempt :{dst_port}"
                elif flags == 0x12:  # SYN-ACK
                    packet_data["info"] = f"TCP SYN-ACK | Connection Accepted :{src_port}"
                elif flags == 0x11:  # FIN-ACK
                    packet_data["info"] = f"TCP FIN | Connection Closing :{dst_port}"
                elif flags == 0x04:  # RST
                    packet_data["info"] = f"TCP RST | Connection Refused :{dst_port}"
                else:
                    packet_data["info"] = f"TCP Data Transfer :{dst_port}"
        
        elif UDP in packet:
            packet_data["protocol"] = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Enhanced UDP Protocol Detection
            if dst_port == 443 or src_port == 443:
                packet_data["protocol"] = "QUIC"
                packet_data["info"] = "QUIC | HTTP/3 Fast Web"
            elif dst_port == 53 or src_port == 53:
                packet_data["protocol"] = "DNS"
                packet_data["info"] = "DNS | Domain Name Lookup"
            elif dst_port == 67 or src_port == 67:
                packet_data["protocol"] = "DHCP"
                packet_data["info"] = "DHCP Server | IP Address Assignment"
            elif dst_port == 68 or src_port == 68:
                packet_data["protocol"] = "DHCP"
                packet_data["info"] = "DHCP Client | Requesting IP Address"
            elif dst_port == 123 or src_port == 123:
                packet_data["protocol"] = "NTP"
                packet_data["info"] = "NTP | Time Synchronization"
            elif dst_port == 161 or src_port == 161:
                packet_data["info"] = "SNMP | Network Monitoring"
            elif dst_port == 162 or src_port == 162:
                packet_data["info"] = "SNMP-TRAP | Network Alert"
            elif dst_port == 500 or src_port == 500:
                packet_data["info"] = "IPSec/IKE | VPN Key Exchange"
            elif dst_port == 1194 or src_port == 1194:
                packet_data["info"] = "OpenVPN | Encrypted Tunnel"
            elif dst_port == 5353 or src_port == 5353:
                packet_data["protocol"] = "mDNS"
                packet_data["info"] = "mDNS | Local Network Discovery"
            elif dst_port == 137 or src_port == 137:
                packet_data["info"] = "NetBIOS | Windows Name Service"
            elif dst_port == 138 or src_port == 138:
                packet_data["info"] = "NetBIOS | Windows Datagram Service"
            elif dst_port == 1900 or src_port == 1900:
                packet_data["info"] = "SSDP | UPnP Device Discovery"
            else:
                packet_data["info"] = f"UDP Datagram :{dst_port}"
        
        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
            icmp_type = packet[ICMP].type
            
            # Detailed ICMP type detection
            if icmp_type == 8:
                packet_data["info"] = "ICMP Echo Request | Ping Outgoing"
            elif icmp_type == 0:
                packet_data["info"] = "ICMP Echo Reply | Ping Response"
            elif icmp_type == 3:
                packet_data["info"] = "ICMP Dest Unreachable | Route Problem"
            elif icmp_type == 11:
                packet_data["info"] = "ICMP Time Exceeded | TTL Expired"
            else:
                packet_data["info"] = f"ICMP Type {icmp_type}"
        
        # Ensure info is never empty for IPv6-only packets
        if packet_data["info"] == "Unknown Protocol" and is_ipv6:
            packet_data["info"] = "Raw IPv6"
        
        return packet_data

    def _log_to_database(self, packet_data):
        """
        Store packet data in SQLite database.
        Uses FULL src/dst addresses (not truncated display versions).
        """
        try:
            self.db.insert_packet(packet_data)
        except Exception as e:
            print(f"[!] Warning: Could not log to database: {e}")

    def _update_statistics(self, protocol):
        """Update protocol count statistics."""
        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts[protocol] = 1

    def _print_session_summary(self):
        """Print traffic statistics summary with enhanced details."""
        print("\n" + "=" * 70)
        print("🛡️  NetGuard Session Summary")
        print("=" * 70)
        print(f"Total Packets Captured: {self.packets_captured}")
        print(f"Total Data Transferred: {self._format_bytes(self.total_bytes)}")
        print(f"Average Packet Size: {self.total_bytes // self.packets_captured if self.packets_captured > 0 else 0} bytes")
        print(f"Database: {self.db_path} ({self.db.get_database_size()})")
        print("\nProtocol Breakdown:")
        print("-" * 40)
        
        # Sort protocols by count (descending)
        sorted_protocols = sorted(
            self.protocol_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for protocol, count in sorted_protocols:
            percentage = (count / self.packets_captured * 100) if self.packets_captured > 0 else 0
            bar_length = int(percentage / 2)  # Scale to 50 chars max
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"  {protocol:<10} : {count:>6} packets ({percentage:>5.1f}%) {bar}")
        
        print("=" * 70 + "\n")
    
    def _format_bytes(self, bytes_value):
        """Convert bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"

    def packet_callback(self, packet):
        """
        Callback executed for every captured packet.
        Separates data extraction from display/logging logic.
        """
        self.packets_captured += 1
        
        # Extract clean data from raw packet
        data = self.analyze_packet(packet)
        
        if data:
            # Update statistics
            self._update_statistics(data['protocol'])
            self.total_bytes += data['size']
            
            # Log to database
            self._log_to_database(data)
            
            # Display to console (uses TRUNCATED display addresses)
            print(
                f"[{data['timestamp']}] "
                f"{data['protocol']:<6} | "
                f"{data['display_src']:<18} → "
                f"{data['display_dst']:<18} | "
                f"Size: {data['size']:<5} | "
                f"{data['info']}"
            )

    def start(self, count=0):
        """
        Start packet capture.
        
        Args:
            count: Number of packets to capture (0 = infinite)
        """
        try:
            # Validate interface before starting
            self._validate_interface()
            
            # Start database session
            self.session_id = self.db.start_session(self.interface)
            
            print(f"🛡️  NetGuard Monitoring Started")
            print(f"Interface: {self.interface or 'All'}")
            print(f"Database: {self.db_path}")
            print(f"Session ID: {self.session_id}")
            print(f"Packets to Capture: {count if count > 0 else '∞'}")
            print("-" * 70 + "\n")
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=count,
                store=False
            )
            
        except KeyboardInterrupt:
            print("\n\n[!] Capture interrupted by user (Ctrl+C)")
            
        except PermissionError:
            print("[!] Error: Root/sudo privileges required for packet capture!")
            print("    Run with: sudo python3 test_sniffer.py")
            
        except ValueError as e:
            print(f"[!] Configuration Error: {e}")
            
        except Exception as e:
            print(f"[!] Sniffer Error: {e}")
            
        finally:
            # End database session
            if self.session_id:
                self.db.end_session(self.session_id, self.packets_captured, self.total_bytes)
            
            # Always print summary on exit
            if self.packets_captured > 0:
                self._print_session_summary()
