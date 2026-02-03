"""
NetGuard Packet Sniffer Module
Production-Ready: Phase 3 - Wireshark-Inspired Enhanced Monitoring
"""
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6MLReport2, ARP, Raw, get_if_list, conf
from datetime import datetime
import threading
import os
import socket
import csv
from .database import NetGuardDatabase

class PacketSniffer:
    """
    Core engine to capture and parse network traffic.
    Production-ready with statistics tracking, database storage, and robust error handling.
    """
    
    def __init__(self, interface=None, db_path="data/netguard.db", csv_file=None):
        """
        Initialize the packet sniffer with Wireshark-inspired features.
        
        Args:
            interface: Network interface to sniff (None = all interfaces)
            db_path: Path to SQLite database file (default: data/netguard.db)
            csv_file: Optional CSV file for real-time logging
        """
        self.interface = interface
        self.db_path = db_path
        self.csv_file = csv_file
        self.stop_sniffing = threading.Event()
        
        # Packet indexing and timing
        self.packet_id = 0
        self.capture_start_time = None
        self.packets_captured = 0
        
        # Traffic statistics tracking (enhanced)
        self.transport_counts = {}  # TCP, UDP, ICMP, ARP
        self.application_counts = {}  # HTTP, HTTPS, DNS, QUIC, etc.
        self.direction_counts = {'INCOMING': 0, 'OUTGOING': 0}
        self.total_bytes = 0
        
        # Get local IP for direction detection
        self.local_ip = self._get_local_ip()
        
        # Initialize database
        self.db = NetGuardDatabase(db_path)
        self.session_id = None
        
        # Initialize CSV logging if requested
        self.csv_writer = None
        if csv_file:
            self._init_csv_logging()

    def _get_local_ip(self):
        """Get the local IP address for traffic direction detection."""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google DNS, doesn't actually send data
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"  # Fallback
    
    def _classify_ipv6_address(self, ipv6_addr):
        """Classify IPv6 address type for better understanding."""
        addr_str = str(ipv6_addr)
        
        if addr_str.startswith("fe80:"):
            return "Link-Local"  # Local network only
        elif addr_str.startswith("ff02:"):
            return "Multicast-Link"  # All nodes on local link
        elif addr_str.startswith("ff"):
            return "Multicast"
        elif addr_str.startswith("fc") or addr_str.startswith("fd"):
            return "Unique-Local"  # Private IPv6
        elif addr_str.startswith("2") or addr_str.startswith("3"):
            return "Global-Unicast"  # Public internet
        elif addr_str == "::1":
            return "Loopback"
        else:
            return "Other"
    
    def _init_csv_logging(self):
        """Initialize CSV file with headers."""
        try:
            os.makedirs(os.path.dirname(self.csv_file) if os.path.dirname(self.csv_file) else '.', exist_ok=True)
            csv_file_handle = open(self.csv_file, 'w', newline='')
            self.csv_writer = csv.writer(csv_file_handle)
            self.csv_writer.writerow([
                'Packet_ID', 'Absolute_Timestamp', 'Relative_Time',
                'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port',
                'Transport_Protocol', 'Application_Protocol', 'TCP_Flags',
                'Direction', 'Packet_Length', 'Info'
            ])
            self.csv_file_handle = csv_file_handle
        except Exception as e:
            print(f"[!] Warning: Could not initialize CSV logging: {e}")
            self.csv_writer = None
    
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

    def _extract_tcp_flags(self, tcp_flags):
        """Extract human-readable TCP flags from flags field."""
        flag_names = []
        if tcp_flags & 0x02:  # SYN
            flag_names.append('SYN')
        if tcp_flags & 0x10:  # ACK
            flag_names.append('ACK')
        if tcp_flags & 0x01:  # FIN
            flag_names.append('FIN')
        if tcp_flags & 0x04:  # RST
            flag_names.append('RST')
        if tcp_flags & 0x08:  # PSH
            flag_names.append('PSH')
        if tcp_flags & 0x20:  # URG
            flag_names.append('URG')
        return ','.join(flag_names) if flag_names else ''
    
    def _detect_tls_handshake(self, packet):
        """Detect TLS handshake by checking for 0x16 byte in payload."""
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            if len(payload) > 0 and payload[0] == 0x16:
                return True
        return False
    
    def _determine_direction(self, src_ip, dst_ip):
        """Determine if traffic is INCOMING or OUTGOING."""
        if src_ip == self.local_ip:
            return 'OUTGOING'
        elif dst_ip == self.local_ip:
            return 'INCOMING'
        else:
            # For packets not directly to/from local IP (e.g., promiscuous mode)
            return 'OUTGOING' if src_ip.startswith('192.168.') or src_ip.startswith('10.') else 'INCOMING'
    
    def analyze_packet(self, packet):
        """
        Extracts structured data from a raw packet with Wireshark-inspired detail.
        
        Architectural Design:
        - Two-tier protocol classification (transport + application)
        - Dynamic TCP connection state detection via flags
        - Separate port fields for proper analysis
        - TLS handshake detection
        - Traffic direction analysis
        - High-precision timestamps with relative timing
        
        Returns:
            Dictionary with comprehensive packet data, or None if packet should be ignored
        """
        packet_data = {}
        
        # 1. Packet Identification and Timing
        self.packet_id += 1
        packet_data['packet_id'] = self.packet_id
        
        # High-precision timestamp
        now = datetime.now()
        packet_data['absolute_timestamp'] = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # milliseconds
        
        # Relative time (seconds since capture start)
        if self.capture_start_time is None:
            self.capture_start_time = now
            packet_data['relative_time'] = 0.0
        else:
            delta = (now - self.capture_start_time).total_seconds()
            packet_data['relative_time'] = round(delta, 6)
        
        packet_data['packet_length'] = len(packet)
        
        # 2. Extract IP Layer (store FULL addresses)
        is_ipv6 = False
        
        if IP in packet:
            packet_data['src'] = packet[IP].src
            packet_data['dst'] = packet[IP].dst
            transport_proto_num = packet[IP].proto
            
        elif IPv6 in packet:
            # IPv6 packet - extract source/destination and parse next header
            packet_data['src'] = packet[IPv6].src
            packet_data['dst'] = packet[IPv6].dst
            is_ipv6 = True
            
            # Display addresses (truncated)
            packet_data['display_src'] = self._truncate_ipv6(packet_data['src'])
            packet_data['display_dst'] = self._truncate_ipv6(packet_data['dst'])
            
            # IPv6 Next Header field indicates the protocol inside
            # Protocol numbers: 6=TCP, 17=UDP, 58=ICMPv6
            transport_proto_num = packet[IPv6].nh
            
        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_data['src'] = arp_layer.psrc
            packet_data['dst'] = arp_layer.pdst
            packet_data['transport_protocol'] = 'ARP'
            packet_data['application_protocol'] = 'ARP'
            
            # Distinguish between ARP request and reply
            if arp_layer.op == 1:  # ARP Request
                packet_data['info'] = f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
                packet_data['direction'] = 'OUTGOING'
            elif arp_layer.op == 2:  # ARP Reply
                packet_data['info'] = f"{arp_layer.psrc} is at {arp_layer.hwsrc}"
                packet_data['direction'] = 'INCOMING'
            else:
                packet_data['info'] = f"ARP Operation {arp_layer.op}"
                packet_data['direction'] = 'OUTGOING'
            
            # Display addresses
            packet_data['display_src'] = packet_data['src']
            packet_data['display_dst'] = packet_data['dst']
            return packet_data
            
        else:
            return None  # Ignore non-IP/ARP traffic
        
        # 3. Create display versions (for terminal output) - only for IPv4
        if not is_ipv6:
            packet_data['display_src'] = packet_data['src']
            packet_data['display_dst'] = packet_data['dst']
        
        # 4. Determine traffic direction
        packet_data['direction'] = self._determine_direction(packet_data['src'], packet_data['dst'])
        
        # 5. Protocol-specific details with two-tier classification
        packet_data['transport_protocol'] = 'UNKNOWN'
        packet_data['application_protocol'] = 'UNKNOWN'
        packet_data['info'] = 'Unknown Protocol'
        
        # ==== TCP Protocol Handling ====
        if TCP in packet:
            packet_data['transport_protocol'] = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags_raw = packet[TCP].flags
            
            # Store ports as separate fields
            packet_data['src_port'] = src_port
            packet_data['dst_port'] = dst_port
            
            # Extract TCP flags
            packet_data['tcp_flags'] = self._extract_tcp_flags(tcp_flags_raw)
            
            # Application protocol detection
            app_proto = 'UNKNOWN'
            if dst_port == 443 or src_port == 443:
                # Check for TLS handshake
                if self._detect_tls_handshake(packet):
                    app_proto = 'TLS'
                else:
                    app_proto = 'HTTPS'
            # Application protocol detection
            app_proto = 'UNKNOWN'
            if dst_port == 443 or src_port == 443:
                # Check for TLS handshake
                if self._detect_tls_handshake(packet):
                    app_proto = 'TLS'
                else:
                    app_proto = 'HTTPS'
            elif dst_port == 80 or src_port == 80:
                app_proto = 'HTTP'
            elif dst_port == 22 or src_port == 22:
                app_proto = 'SSH'
            elif dst_port == 21 or src_port == 21:
                app_proto = 'FTP'
            elif dst_port == 20 or src_port == 20:
                app_proto = 'FTP-DATA'
            elif dst_port == 3389 or src_port == 3389:
                app_proto = 'RDP'
            elif dst_port == 25 or src_port == 25:
                app_proto = 'SMTP'
            elif dst_port == 587 or src_port == 587:
                app_proto = 'SMTP'
            elif dst_port == 110 or src_port == 110:
                app_proto = 'POP3'
            elif dst_port == 143 or src_port == 143:
                app_proto = 'IMAP'
            elif dst_port == 993 or src_port == 993:
                app_proto = 'IMAPS'
            elif dst_port == 3306 or src_port == 3306:
                app_proto = 'MySQL'
            elif dst_port == 5432 or src_port == 5432:
                app_proto = 'PostgreSQL'
            elif dst_port == 27017 or src_port == 27017:
                app_proto = 'MongoDB'
            elif dst_port == 6379 or src_port == 6379:
                app_proto = 'Redis'
            elif dst_port == 8080 or src_port == 8080:
                app_proto = 'HTTP-ALT'
            elif dst_port == 8443 or src_port == 8443:
                app_proto = 'HTTPS-ALT'
            elif dst_port == 23 or src_port == 23:
                app_proto = 'Telnet'
            
            packet_data['application_protocol'] = app_proto
            
            # === CRITICAL: Dynamic TCP Info based on FLAGS ===
            # This provides connection state visibility, not just protocol labels
            has_syn = bool(tcp_flags_raw & 0x02)
            has_ack = bool(tcp_flags_raw & 0x10)
            has_fin = bool(tcp_flags_raw & 0x01)
            has_rst = bool(tcp_flags_raw & 0x04)
            has_psh = bool(tcp_flags_raw & 0x08)
            
            # Payload check for keep-alive detection
            payload_len = len(packet[TCP].payload) if packet[TCP].payload else 0
            
            # Build flag display string for Info column
            flag_display = f"[{packet_data['tcp_flags']}]" if packet_data['tcp_flags'] else ""
            
            # Determine action based on flags (priority-based)
            if has_syn and not has_ack:
                # SYN flag only = Connection initiation
                action = f'Connection Request → :{dst_port}'
            elif has_syn and has_ack:
                # SYN-ACK = Connection accepted
                action = f'Connection Accepted ← :{src_port}'
            elif has_fin:
                # FIN flag = Connection closing
                action = f'Closing Connection :{dst_port}'
            elif has_rst:
                # RST flag = Connection reset/refused
                action = f'Connection Reset/Refused :{dst_port}'
            elif has_psh and has_ack and payload_len > 0:
                # PSH+ACK = Data transfer
                if app_proto == 'TLS':
                    action = f'TLS Handshake / Client Hello'
                elif app_proto != 'UNKNOWN':
                    action = f'{app_proto} Data Transfer ({payload_len} bytes)'
                else:
                    action = f'TCP Data Transfer :{dst_port} ({payload_len} bytes)'
            elif has_ack and payload_len == 0:
                # ACK with no payload = Keep-alive or acknowledgment
                action = f'Keep-Alive / Acknowledgment'
            else:
                # Default: Use application protocol if known
                if app_proto == 'TLS':
                    action = 'TLS Encrypted Communication'
                elif app_proto == 'HTTP':
                    action = 'HTTP | Unencrypted Web Traffic'
                elif app_proto == 'HTTPS':
                    action = 'HTTPS | Encrypted Web Browsing'
                elif app_proto == 'SSH':
                    action = 'SSH | Secure Remote Shell'
                elif app_proto == 'FTP':
                    action = 'FTP | File Transfer (Unencrypted)'
                elif app_proto == 'FTP-DATA':
                    action = 'FTP-DATA | Active File Transfer'
                elif app_proto == 'RDP':
                    action = 'RDP | Remote Desktop Connection'
                elif app_proto == 'SMTP':
                    action = 'SMTP | Email Server Communication'
                elif app_proto == 'POP3':
                    action = 'POP3 | Email Retrieval'
                elif app_proto == 'IMAP':
                    action = 'IMAP | Email Sync'
                elif app_proto == 'IMAPS':
                    action = 'IMAPS | Secure Email Sync'
                elif app_proto == 'MySQL':
                    action = 'MySQL | Database Connection'
                elif app_proto == 'PostgreSQL':
                    action = 'PostgreSQL | Database Query'
                elif app_proto == 'MongoDB':
                    action = 'MongoDB | NoSQL Database'
                elif app_proto == 'Redis':
                    action = 'Redis | Cache/Data Store'
                elif app_proto == 'HTTP-ALT':
                    action = 'HTTP-ALT | Web Proxy/Dev Server'
                elif app_proto == 'HTTPS-ALT':
                    action = 'HTTPS-ALT | Alternate Secure Web'
                elif app_proto == 'Telnet':
                    action = 'Telnet | Insecure Remote Access'
                else:
                    action = f'TCP Communication :{dst_port}'
            
            # Combine flags and action
            packet_data['info'] = f'{flag_display} {action}' if flag_display else action
        
        # ==== UDP Protocol Handling ====
        elif UDP in packet:
            packet_data['transport_protocol'] = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Store ports as separate fields
            packet_data['src_port'] = src_port
            packet_data['dst_port'] = dst_port
            
            # Application protocol detection
            app_proto = 'UNKNOWN'
            if dst_port == 443 or src_port == 443:
                # QUIC detection (HTTP/3 over UDP port 443)
                app_proto = 'QUIC'
                
                # Check for QUIC packet patterns in payload
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load)
                    # QUIC Initial packets often start with 0xc0-0xff (long header)
                    if len(payload) > 0 and (payload[0] & 0x80):
                        packet_data['info'] = 'QUIC: Connection Handshake'
                    else:
                        packet_data['info'] = f'QUIC: Encrypted Data (Port {dst_port})'
                else:
                    packet_data['info'] = f'QUIC: Traffic (Port {dst_port})'
            elif dst_port == 53 or src_port == 53:
                app_proto = 'DNS'
                packet_data['info'] = 'DNS | Domain Name Lookup'
            elif dst_port == 67 or src_port == 67:
                app_proto = 'DHCP'
                packet_data['info'] = 'DHCP Server | IP Address Assignment'
            elif dst_port == 68 or src_port == 68:
                app_proto = 'DHCP'
                packet_data['info'] = 'DHCP Client | Requesting IP Address'
            elif dst_port == 123 or src_port == 123:
                app_proto = 'NTP'
                packet_data['info'] = 'NTP | Time Synchronization'
            elif dst_port == 161 or src_port == 161:
                app_proto = 'SNMP'
                packet_data['info'] = 'SNMP | Network Monitoring'
            elif dst_port == 162 or src_port == 162:
                app_proto = 'SNMP-TRAP'
                packet_data['info'] = 'SNMP-TRAP | Network Alert'
            elif dst_port == 500 or src_port == 500:
                app_proto = 'IPSec'
                packet_data['info'] = 'IPSec/IKE | VPN Key Exchange'
            elif dst_port == 1194 or src_port == 1194:
                app_proto = 'OpenVPN'
                packet_data['info'] = 'OpenVPN | Encrypted Tunnel'
            elif dst_port == 5353 or src_port == 5353:
                app_proto = 'mDNS'
                packet_data['info'] = 'mDNS | Local Network Discovery'
            elif dst_port == 137 or src_port == 137:
                app_proto = 'NetBIOS-NS'
                packet_data['info'] = 'NetBIOS | Windows Name Service'
            elif dst_port == 138 or src_port == 138:
                app_proto = 'NetBIOS-DGM'
                packet_data['info'] = 'NetBIOS | Windows Datagram Service'
            elif dst_port == 1900 or src_port == 1900:
                app_proto = 'SSDP'
                packet_data['info'] = 'SSDP | UPnP Device Discovery'
            else:
                packet_data['info'] = f'UDP Datagram :{dst_port}'
            
            packet_data['application_protocol'] = app_proto
        
        # ==== ICMP Protocol Handling ====
        elif ICMP in packet:
            packet_data['transport_protocol'] = 'ICMP'
            packet_data['application_protocol'] = 'ICMP'
            icmp_type = packet[ICMP].type
            
            # Detailed ICMP type detection
            if icmp_type == 8:
                packet_data['info'] = 'ICMP Echo Request | Ping Outgoing'
            elif icmp_type == 0:
                packet_data['info'] = 'ICMP Echo Reply | Ping Response'
            elif icmp_type == 3:
                packet_data['info'] = 'ICMP Dest Unreachable | Route Problem'
            elif icmp_type == 11:
                packet_data['info'] = 'ICMP Time Exceeded | TTL Expired'
            else:
                packet_data['info'] = f'ICMP Type {icmp_type}'
        
        # ==== ICMPv6 Protocol Handling (IPv6 only) ====
        elif transport_proto_num == 58:  # ICMPv6 protocol number
            packet_data['transport_protocol'] = 'ICMPv6'
            packet_data['application_protocol'] = 'ICMPv6'
            
            # ICMPv6 type mapping (for reference)
            icmpv6_type_names = {
                1: "Destination Unreachable",
                2: "Packet Too Big",
                3: "Time Exceeded",
                4: "Parameter Problem",
                128: "Echo Request (Ping)",
                129: "Echo Reply (Pong)",
                133: "Router Solicitation",
                134: "Router Advertisement",
                135: "Neighbor Solicitation",
                136: "Neighbor Advertisement",
                143: "Multicast Listener Report v2"
            }
            
            # Check for specific ICMPv6 layers
            if packet.haslayer(ICMPv6ND_NS):
                packet_data['info'] = 'ICMPv6: Neighbor Solicitation (IPv6 ARP Request)'
            elif packet.haslayer(ICMPv6ND_NA):
                packet_data['info'] = 'ICMPv6: Neighbor Advertisement (IPv6 ARP Reply)'
            elif packet.haslayer(ICMPv6ND_RA):
                dst_type = self._classify_ipv6_address(packet_data['dst'])
                if dst_type == "Multicast-Link":
                    packet_data['info'] = 'ICMPv6: Router Advertisement (Broadcast to all local devices)'
                else:
                    packet_data['info'] = 'ICMPv6: Router Advertisement'
            elif packet.haslayer(ICMPv6MLReport2):
                packet_data['info'] = 'ICMPv6: Multicast Listener Report v2'
            elif packet.haslayer(ICMPv6EchoRequest):
                packet_data['info'] = 'ICMPv6: Echo Request (Ping)'
            elif packet.haslayer(ICMPv6EchoReply):
                packet_data['info'] = 'ICMPv6: Echo Reply (Pong)'
            elif packet.haslayer(ICMPv6DestUnreach):
                packet_data['info'] = 'ICMPv6: Destination Unreachable'
            elif packet.haslayer(ICMPv6PacketTooBig):
                packet_data['info'] = 'ICMPv6: Packet Too Big'
            elif packet.haslayer(ICMPv6TimeExceeded):
                packet_data['info'] = 'ICMPv6: Time Exceeded'
            else:
                # Try to get type from any ICMPv6 layer
                packet_data['info'] = 'ICMPv6: Network Control Protocol'
        
        else:
            # Unknown transport protocol
            packet_data['transport_protocol'] = 'UNKNOWN'
            packet_data['application_protocol'] = 'UNKNOWN'
            packet_data['info'] = 'Unknown Transport Protocol'
        
        return packet_data

    def _log_to_database(self, packet_data):
        """
        Store packet data in SQLite database with all enhanced fields.
        Uses FULL src/dst addresses (not truncated display versions).
        """
        try:
            self.db.insert_packet(packet_data)
        except Exception as e:
            print(f"[!] Warning: Could not log to database: {e}")
    
    def _log_to_csv(self, packet_data):
        """Write packet data to CSV file."""
        if self.csv_writer:
            try:
                self.csv_writer.writerow([
                    packet_data['packet_id'],
                    packet_data['absolute_timestamp'],
                    packet_data['relative_time'],
                    packet_data['src'],
                    packet_data['dst'],
                    packet_data.get('src_port', ''),
                    packet_data.get('dst_port', ''),
                    packet_data['transport_protocol'],
                    packet_data['application_protocol'],
                    packet_data.get('tcp_flags', ''),
                    packet_data['direction'],
                    packet_data['packet_length'],
                    packet_data['info']
                ])
            except Exception as e:
                print(f"[!] Warning: Could not log to CSV: {e}")
    
    def _update_statistics(self, packet_data):
        """Update comprehensive traffic statistics."""
        # Transport protocol counts
        transport = packet_data['transport_protocol']
        if transport in self.transport_counts:
            self.transport_counts[transport] += 1
        else:
            self.transport_counts[transport] = 1
        
        # Application protocol counts
        application = packet_data['application_protocol']
        if application in self.application_counts:
            self.application_counts[application] += 1
        else:
            self.application_counts[application] = 1
        
        # Direction counts
        direction = packet_data['direction']
        self.direction_counts[direction] += 1

    def _print_session_summary(self):
        """Print comprehensive traffic statistics summary with enhanced details."""
        print("\n" + "=" * 80)
        print("🛡️  NetGuard Session Summary - Wireshark-Inspired Analysis")
        print("=" * 80)
        print(f"Total Packets Captured: {self.packets_captured}")
        print(f"Total Data Transferred: {self._format_bytes(self.total_bytes)}")
        print(f"Average Packet Size: {self.total_bytes // self.packets_captured if self.packets_captured > 0 else 0} bytes")
        print(f"Capture Duration: {self._format_capture_time()}")
        print(f"Database: {self.db_path} ({self.db.get_database_size()})")
        if self.csv_file:
            print(f"CSV Export: {self.csv_file}")
        
        # Traffic Direction
        print("\n📊 Traffic Direction:")
        print("-" * 40)
        for direction, count in self.direction_counts.items():
            percentage = (count / self.packets_captured * 100) if self.packets_captured > 0 else 0
            print(f"  {direction:<12} : {count:>6} packets ({percentage:>5.1f}%)")
        
        # Transport Protocol Breakdown
        print("\n🔌 Transport Protocol Breakdown:")
        print("-" * 40)
        sorted_transport = sorted(
            self.transport_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        for protocol, count in sorted_transport:
            percentage = (count / self.packets_captured * 100) if self.packets_captured > 0 else 0
            bar_length = int(percentage / 2)
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"  {protocol:<10} : {count:>6} packets ({percentage:>5.1f}%) {bar}")
        
        # Application Protocol Breakdown
        print("\n🌐 Application Protocol Breakdown:")
        print("-" * 40)
        sorted_application = sorted(
            self.application_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        for protocol, count in sorted_application[:15]:  # Top 15
            percentage = (count / self.packets_captured * 100) if self.packets_captured > 0 else 0
            bar_length = int(percentage / 2)
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"  {protocol:<12} : {count:>6} packets ({percentage:>5.1f}%) {bar}")
        
        print("=" * 80 + "\n")
    
    def _format_capture_time(self):
        """Format the total capture duration."""
        if self.capture_start_time:
            delta = datetime.now() - self.capture_start_time
            total_seconds = delta.total_seconds()
            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            seconds = int(total_seconds % 60)
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        return "0s"
    
    def _format_bytes(self, bytes_value):
        """Convert bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"

    def packet_callback(self, packet):
        """
        Callback executed for every captured packet with enhanced processing.
        Separates data extraction from display/logging logic.
        """
        self.packets_captured += 1
        
        # Extract comprehensive data from raw packet
        data = self.analyze_packet(packet)
        
        if data:
            # Update statistics
            self._update_statistics(data)
            self.total_bytes += data['packet_length']
            
            # Log to database
            self._log_to_database(data)
            
            # Log to CSV if enabled
            if self.csv_writer:
                self._log_to_csv(data)
            
            # Display to console with enhanced formatting
            # Format: [ID] [Timestamp] [RelTime] PROTO | SRC:PORT → DST:PORT | DIR | SIZE | INFO
            src_display = f"{data['display_src']}:{data.get('src_port', '')}" if data.get('src_port') else data['display_src']
            dst_display = f"{data['display_dst']}:{data.get('dst_port', '')}" if data.get('dst_port') else data['display_dst']
            
            # Build protocol display (show application if available)
            proto_display = data['application_protocol'] if data['application_protocol'] != 'UNKNOWN' else data['transport_protocol']
            
            print(
                f"[{data['packet_id']:<5}] "
                f"[{data['absolute_timestamp']}] "
                f"[{data['relative_time']:>8.3f}s] "
                f"{proto_display:<8} | "
                f"{src_display:<22} → {dst_display:<22} | "
                f"{data['direction']:<8} | "
                f"{data['packet_length']:<5}B | "
                f"{data['info']}"
            )

    def start(self, count=0):
        """
        Start packet capture with Wireshark-inspired monitoring.
        
        Args:
            count: Number of packets to capture (0 = infinite)
        """
        try:
            # Validate interface before starting
            self._validate_interface()
            
            # Start database session
            self.session_id = self.db.start_session(self.interface)
            
            # Initialize capture start time
            self.capture_start_time = datetime.now()
            
            print(f"🛡️  NetGuard Wireshark-Inspired Monitoring Started")
            print(f"Interface: {self.interface or 'All'}")
            print(f"Local IP: {self.local_ip}")
            print(f"Database: {self.db_path}")
            if self.csv_file:
                print(f"CSV Export: {self.csv_file}")
            print(f"Session ID: {self.session_id}")
            print(f"Packets to Capture: {count if count > 0 else '∞'}")
            print("-" * 100)
            print(f"{'[ID]':<7} {'[Timestamp]':<27} {'[RelTime]':<10} {'PROTOCOL':<9} | {'SOURCE':<22} → {'DESTINATION':<22} | {'DIRECTION':<9} | {'SIZE':<6} | INFO")
            print("-" * 100 + "\n")
            
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
            # Close CSV file if open
            if hasattr(self, 'csv_file_handle') and self.csv_file_handle:
                self.csv_file_handle.close()
            
            # End database session
            if self.session_id:
                self.db.end_session(self.session_id, self.packets_captured, self.total_bytes)
            
            # Always print summary on exit
            if self.packets_captured > 0:
                self._print_session_summary()
