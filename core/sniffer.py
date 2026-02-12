"""
NetGuard Packet Sniffer Module
Production-Ready: Phase 3 - Wireshark-Inspired Enhanced Monitoring
"""
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6MLReport2, ARP, Raw, get_if_list, conf, DNS, DNSQR, DNSRR, Ether
from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime
import threading
import queue
import struct
import os
import socket
import csv
from .database import NetGuardDatabase

# DNS query type mapping
DNS_QTYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS',
    46: 'RRSIG', 48: 'DNSKEY', 52: 'TLSA', 65: 'HTTPS', 255: 'ANY'
}

# TLS version mapping
TLS_VERSIONS = {
    0x0300: 'SSLv3', 0x0301: 'TLSv1.0', 0x0302: 'TLSv1.1',
    0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3'
}

# Set of known TLS record versions for validation (prevents false positives
# from encrypted data whose random bytes happen to look like TLS content types)
KNOWN_TLS_RECORD_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303, 0x0304}

# TLS handshake type mapping
TLS_HS_TYPES = {
    1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket',
    11: 'Certificate', 12: 'Server Key Exchange', 14: 'Server Hello Done',
    16: 'Client Key Exchange', 20: 'Finished'
}

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
        
        # Queue-based capture: producer-consumer pattern for zero-drop capture
        self._packet_queue = queue.Queue(maxsize=0)  # Unlimited buffer
        self._worker_thread = None
        self._processing_done = threading.Event()
        
        # Packet indexing and timing
        self.packet_id = 0
        self.capture_start_time = None
        self.packets_captured = 0
        
        # Traffic statistics tracking (enhanced)
        self.transport_counts = {}  # TCP, UDP, ICMP, ARP
        self.application_counts = {}  # HTTP, HTTPS, DNS, QUIC, etc.
        self.direction_counts = {'INCOMING': 0, 'OUTGOING': 0}
        self.total_bytes = 0
        
        # Per-flow TLS version tracking: once a handshake is seen on a TCP
        # flow, all subsequent packets (ACKs, Application Data, etc.) on that
        # flow inherit the negotiated TLS version instead of showing as bare TCP.
        # Key: frozenset({(ip1, port1), (ip2, port2)})  Value: version string
        self._tls_flow_versions = {}
        
        # Per-direction TCP stream state tracking for analysis labels.
        # Key: (src_ip, src_port, dst_ip, dst_port)  — directional, NOT symmetric.
        # Value: dict with 'next_expected_seq', 'last_ack', 'last_win', 'last_payload_len'
        # This allows detecting Keep-Alive, Dup ACK, Out-Of-Order, Retransmission,
        # and Window Update, matching Wireshark's TCP analysis behaviour.
        self._tcp_stream_state = {}
        
        # Per-flow ISN (Initial Sequence Number) tracking for relative seq/ack
        # Key: (ip, port, ip, port) directional  Value: ISN from that direction's SYN
        self._tcp_isn_state = {}
        
        # Per-direction window scale factor tracking
        # Key: (ip, port, ip, port) directional  Value: scale factor (e.g., 1024)
        self._tcp_win_scale = {}
        
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
        """Get the local IP addresses (IPv4 and IPv6) for traffic direction detection."""
        local_ips = set()
        
        # Get IPv4
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            local_ips.add("127.0.0.1")
        
        # Get IPv6
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            local_ips.add(s6.getsockname()[0])
            s6.close()
        except Exception:
            pass  # IPv6 not available
        
        # Also add common local addresses
        local_ips.add("127.0.0.1")
        local_ips.add("::1")
        
        return local_ips
    
    def _is_private_ip(self, ip):
        """Check if IP is a private/local address."""
        # IPv4 private ranges
        if ip.startswith('10.'):
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            # 172.16.0.0 - 172.31.255.255
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except:
                pass
        # IPv6 link-local (fe80::) and unique local (fc00::/7)
        if ip.startswith('fe80:') or ip.startswith('fc') or ip.startswith('fd'):
            return True
        return False
    
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
        """Extract TCP flags in Wireshark's canonical order: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR."""
        flag_names = []
        if tcp_flags & 0x01:  # FIN
            flag_names.append('FIN')
        if tcp_flags & 0x02:  # SYN
            flag_names.append('SYN')
        if tcp_flags & 0x04:  # RST
            flag_names.append('RST')
        if tcp_flags & 0x08:  # PSH
            flag_names.append('PSH')
        if tcp_flags & 0x10:  # ACK
            flag_names.append('ACK')
        if tcp_flags & 0x20:  # URG
            flag_names.append('URG')
        if tcp_flags & 0x80:  # ECE
            flag_names.append('ECE')
        if tcp_flags & 0x40:  # CWR
            flag_names.append('CWR')
        return ', '.join(flag_names) if flag_names else ''
    
    def _extract_tcp_options(self, packet, fwd_isn=None):
        """
        Extract TCP options in Wireshark format (TSval, TSecr, MSS, WS, SACK_PERM, SLE, SRE).
        
        Args:
            packet: The packet containing TCP options
            fwd_isn: ISN of the reverse direction (for relative SACK values)
        """
        opts = []
        try:
            for opt_name, opt_val in packet[TCP].options:
                if opt_name == 'Timestamp':
                    tsval, tsecr = opt_val
                    opts.append(f'TSval={tsval}')
                    opts.append(f'TSecr={tsecr}')
                elif opt_name == 'MSS':
                    opts.append(f'MSS={opt_val}')
                elif opt_name == 'WScale':
                    opts.append(f'WS={1 << opt_val}')
                elif opt_name == 'SAckOK':
                    opts.append('SACK_PERM')
                elif opt_name == 'SAck':
                    # SACK blocks: tuples of (left_edge, right_edge)
                    # These acknowledge data from the peer, so use peer's ISN (fwd_isn)
                    if opt_val:
                        for sle, sre in opt_val:
                            # Apply relative seq calculation if ISN is available
                            if fwd_isn is not None:
                                rel_sle = (sle - fwd_isn) & 0xFFFFFFFF
                                rel_sre = (sre - fwd_isn) & 0xFFFFFFFF
                                opts.append(f'SLE={rel_sle}')
                                opts.append(f'SRE={rel_sre}')
                            else:
                                opts.append(f'SLE={sle}')
                                opts.append(f'SRE={sre}')
        except Exception:
            pass
        return ' '.join(opts)
    
    def _extract_sni(self, payload):
        """Extract Server Name Indication (SNI) from TLS Client Hello payload."""
        try:
            # TLS record header: type(1) + version(2) + length(2) = 5 bytes
            # Handshake header: type(1) + length(3) + version(2) + random(32) = 38 bytes from record payload
            # After random: session_id_len(1) + session_id + cipher_suites_len(2) + ...
            if len(payload) < 44:
                return None
            
            offset = 5  # Skip TLS record header
            offset += 1 + 3  # Skip handshake type + length
            offset += 2  # Skip client version
            offset += 32  # Skip random
            
            if offset >= len(payload):
                return None
            
            # Session ID
            sid_len = payload[offset]
            offset += 1 + sid_len
            
            if offset + 2 > len(payload):
                return None
            
            # Cipher suites
            cs_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2 + cs_len
            
            if offset >= len(payload):
                return None
            
            # Compression methods
            comp_len = payload[offset]
            offset += 1 + comp_len
            
            if offset + 2 > len(payload):
                return None
            
            # Extensions
            ext_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_len
            
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = struct.unpack('!H', payload[offset:offset + 2])[0]
                ext_data_len = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
                offset += 4
                
                if ext_type == 0:  # SNI extension
                    if offset + 5 <= len(payload):
                        # SNI list length(2) + type(1) + name_length(2) + name
                        sni_list_len = struct.unpack('!H', payload[offset:offset + 2])[0]
                        name_type = payload[offset + 2]
                        name_len = struct.unpack('!H', payload[offset + 3:offset + 5])[0]
                        if name_type == 0 and offset + 5 + name_len <= len(payload):
                            return payload[offset + 5:offset + 5 + name_len].decode('ascii', errors='replace')
                    return None
                
                offset += ext_data_len
            
            return None
        except Exception:
            return None
    
    def _analyze_tls_payload(self, payload):
        """
        Deep TLS analysis: detect version, handshake type, and SNI.
        
        Handles:
        - TLS record types: Handshake (0x16), ChangeCipherSpec (0x14),
          Application Data (0x17), Alert (0x15)
        - SSLv2-style Client Hello detection (legacy compatibility)
        - TLS 1.3 detection via supported_versions extension in both
          Client Hello and Server Hello
        
        Returns:
            tuple: (tls_version_str, info_str) or (None, None) if not TLS
        """
        if len(payload) < 6:
            return None, None
        
        content_type = payload[0]
        record_ver = (payload[1] << 8) | payload[2]
        
        # --- SSLv2-style Client Hello detection ---
        # SSLv2 records start with a length byte where bit 7 is set (>= 0x80)
        # and byte[2] == 0x01 indicates a Client Hello message type
        if (payload[0] & 0x80) != 0 and payload[2] == 0x01 and len(payload) >= 5:
            # SSLv2 Client Hello: bytes[3:5] contain the version the client wants
            client_ver = (payload[3] << 8) | payload[4]
            tls_version = TLS_VERSIONS.get(client_ver, 'SSLv2')
            return tls_version, 'Client Hello'
        
        # --- Validate record version to prevent false positives ---
        # Encrypted data can have random first bytes that look like TLS content types.
        # Only proceed if the record version is a known TLS version.
        if record_ver not in KNOWN_TLS_RECORD_VERSIONS:
            return None, None
        
        # Content type 0x16 = Handshake
        if content_type == 0x16:
            # TLS Handshake - identify type
            handshake_type = payload[5] if len(payload) > 5 else None
            handshake_name = TLS_HS_TYPES.get(handshake_type, f"Handshake Type {handshake_type}")
            
            # Initialize tls_version with the record header version
            tls_version = TLS_VERSIONS.get(record_ver, f'TLS(0x{record_ver:04x})')
            
            # Helper: scan extensions for supported_versions (0x002b)
            def _scan_extensions_for_tls13(payload, offset, ext_end, is_server_hello=False):
                """Scan TLS extensions for supported_versions. Returns 'TLSv1.3' or None."""
                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                    ext_type = struct.unpack('!H', payload[offset:offset+2])[0]
                    ext_len = struct.unpack('!H', payload[offset+2:offset+4])[0]
                    offset += 4
                    
                    if ext_type == 0x002b:  # supported_versions
                        if is_server_hello:
                            # Server Hello: directly 2-byte selected version (no list)
                            if offset + 2 <= len(payload):
                                sv = struct.unpack('!H', payload[offset:offset+2])[0]
                                if sv == 0x0304:
                                    return 'TLSv1.3'
                        else:
                            # Client Hello: 1-byte list length + version list
                            if offset + 1 <= len(payload):
                                sv_offset = offset + 1
                                while sv_offset + 2 <= offset + ext_len:
                                    sv = struct.unpack('!H', payload[sv_offset:sv_offset+2])[0]
                                    if sv == 0x0304:
                                        return 'TLSv1.3'
                                    sv_offset += 2
                    
                    offset += ext_len
                return None
            
            # Special handling for Client Hello to check extensions for TLS 1.3
            if handshake_type == 1:  # Client Hello
                try:
                    # Skip: 
                    # - Record Header (5 bytes)
                    # - Handshake Header (4 bytes: type + len)
                    # - Protocol Version (2 bytes)
                    # - Random (32 bytes)
                    offset = 5 + 4 + 2 + 32
                    
                    # Session ID
                    if offset < len(payload):
                        sess_id_len = payload[offset]
                        offset += 1 + sess_id_len
                        
                        # Cipher Suites
                        if offset + 2 <= len(payload):
                            cipher_len = struct.unpack('!H', payload[offset:offset+2])[0]
                            offset += 2 + cipher_len
                            
                            # Compression Methods
                            if offset < len(payload):
                                comp_len = payload[offset]
                                offset += 1 + comp_len
                                
                                # Extensions
                                if offset + 2 <= len(payload):
                                    ext_total_len = struct.unpack('!H', payload[offset:offset+2])[0]
                                    offset += 2
                                    ext_end = offset + ext_total_len
                                    
                                    result = _scan_extensions_for_tls13(payload, offset, ext_end, is_server_hello=False)
                                    if result:
                                        tls_version = result
                except Exception:
                    pass # Gracefully handle parsing errors in Client Hello
                
                sni = self._extract_sni(payload)
                info = f'Client Hello'
                if sni:
                    info += f' (SNI={sni})'
                return tls_version, info
            
            elif handshake_type == 2:  # Server Hello
                try:
                    # Skip:
                    # - Record Header (5 bytes)
                    # - Handshake Header (4 bytes: type + len)
                    # - Protocol Version (2 bytes)
                    # - Random (32 bytes)
                    # - Session ID (1 byte len + variable)
                    offset = 5 + 4 + 2 + 32
                    
                    if offset < len(payload):
                        sess_id_len = payload[offset]
                        offset += 1 + sess_id_len
                        
                        # Cipher Suite (2 bytes, selected single suite)
                        offset += 2
                        
                        # Compression Method (1 byte)
                        offset += 1
                        
                        # Extensions
                        if offset + 2 <= len(payload):
                            ext_total_len = struct.unpack('!H', payload[offset:offset+2])[0]
                            offset += 2
                            ext_end = offset + ext_total_len
                            
                            result = _scan_extensions_for_tls13(payload, offset, ext_end, is_server_hello=True)
                            if result:
                                tls_version = result
                except Exception:
                    pass  # Gracefully handle parsing errors in Server Hello
                
                # Parse remaining TLS records after the Server Hello handshake record
                # (e.g., Change Cipher Spec, Application Data in the same TCP segment)
                # Per Wireshark behavior: exclude Application Data after Change Cipher Spec
                # (it belongs to the new encryption context and is shown separately)
                first_rec_len = struct.unpack('!H', payload[3:5])[0]  # Length from TLS record header
                remaining_offset = 5 + first_rec_len  # Skip past the first TLS record (5-byte header + payload)
                info_parts = ['Server Hello']
                if remaining_offset < len(payload):
                    remaining_payload = payload[remaining_offset:]
                    _, extra_info = self._parse_tls_records(remaining_payload)
                    if extra_info:
                        # Filter out Application Data after Change Cipher Spec
                        # (Wireshark behavior: Application Data in new encryption context
                        # is shown as a separate layer, not combined with Server Hello)
                        extra_records = [r.strip() for r in extra_info.split(',')]
                        filtered_records = []
                        seen_ccs = False
                        for record in extra_records:
                            if record == 'Change Cipher Spec':
                                filtered_records.append(record)
                                seen_ccs = True
                            elif record == 'Application Data' and seen_ccs:
                                # Skip Application Data after CCS per Wireshark behavior
                                break
                            else:
                                filtered_records.append(record)
                        if filtered_records:
                            info_parts.extend(filtered_records)
                
                return tls_version, ', '.join(info_parts)
            else:
                return tls_version, handshake_name
        
        # For non-handshake record types, collect them and parse multiple records
        elif content_type in (0x14, 0x15, 0x17):
            return self._parse_tls_records(payload)
        
        return None, None
    
    def _parse_tls_records(self, payload):
        """
        Parse all TLS records in a payload and return combined info.
        Handles multiple TLS records in a single TCP segment (e.g.,
        'Change Cipher Spec, Application Data' or 'Application Data, Application Data').
        Uses flow-negotiated version when available.
        For Client Hello records, extracts SNI and checks TLS 1.3 extensions.
        """
        records = []
        offset = 0
        tls_version = None
        found_sni = None
        found_tls13 = False
        
        while offset + 5 <= len(payload):
            ct = payload[offset]
            rv = (payload[offset + 1] << 8) | payload[offset + 2]
            
            if rv not in KNOWN_TLS_RECORD_VERSIONS:
                break
            
            rec_len = struct.unpack('!H', payload[offset + 3:offset + 5])[0]
            ver = TLS_VERSIONS.get(rv, f'TLS(0x{rv:04x})')
            if tls_version is None:
                tls_version = ver
            
            if ct == 0x14:
                records.append('Change Cipher Spec')
            elif ct == 0x17:
                records.append('Application Data')
            elif ct == 0x15:
                records.append('Alert')
            elif ct == 0x16:
                # Handshake record — extract detailed info
                if offset + 5 < len(payload):
                    hs_type = payload[offset + 5]
                    hs_name = TLS_HS_TYPES.get(hs_type, f'Handshake Type {hs_type}')
                    
                    # For Client Hello: extract SNI and check TLS 1.3
                    if hs_type == 1:
                        # Parse this individual TLS record with _analyze_tls_payload
                        record_end = min(offset + 5 + rec_len, len(payload))
                        single_record = payload[offset:record_end]
                        _, ch_info = self._analyze_tls_payload(single_record)
                        if ch_info and 'Client Hello' in ch_info:
                            hs_name = ch_info  # Includes SNI if found
                        # Also try direct SNI extraction from this record
                        if 'SNI=' not in hs_name:
                            sni = self._extract_sni(payload[offset:])
                            if sni:
                                hs_name = f'Client Hello (SNI={sni})'
                        # Check for TLS 1.3
                        try:
                            self._check_tls13_in_record(payload, offset, rec_len)
                            found_tls13 = True
                        except Exception:
                            pass
                    elif hs_type == 2:
                        # Server Hello — check TLS 1.3
                        single_record = payload[offset:min(offset + 5 + rec_len, len(payload))]
                        ch_ver, _ = self._analyze_tls_payload(single_record)
                        if ch_ver == 'TLSv1.3':
                            found_tls13 = True
                    
                    records.append(hs_name)
                else:
                    records.append('Handshake')
            else:
                break
            
            offset += 5 + rec_len
        
        if found_tls13:
            tls_version = 'TLSv1.3'
        
        if records:
            return tls_version, ', '.join(records)
        return None, None
    
    def _check_tls13_in_record(self, payload, offset, rec_len):
        """Check if a Client Hello record at offset contains TLS 1.3 supported_versions."""
        # Skip record header (5) + handshake header (4) + version (2) + random (32)
        pos = offset + 5 + 4 + 2 + 32
        if pos >= len(payload):
            return
        sess_id_len = payload[pos]
        pos += 1 + sess_id_len
        if pos + 2 > len(payload):
            return
        cipher_len = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2 + cipher_len
        if pos >= len(payload):
            return
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return
        ext_total = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_total
        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
            ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0x002b:  # supported_versions
                sv_pos = pos + 1  # skip list length byte
                while sv_pos + 2 <= pos + ext_len:
                    sv = struct.unpack('!H', payload[sv_pos:sv_pos+2])[0]
                    if sv == 0x0304:
                        return True
                    sv_pos += 2
            pos += ext_len
        return False
    
    def _analyze_tcp_stream(self, packet, src_ip, src_port, dst_ip, dst_port, seq, ack_num, win, payload_len, flag_str):
        """
        Analyze TCP stream state to detect Wireshark-style analysis labels.
        
        Uses per-direction state tracking (src→dst) to compare sequence/ack
        numbers against expected values and detect anomalies.
        
        Detected labels:
        - TCP Keep-Alive:  seq = next_expected - 1, payload 0-1 byte, ACK only
        - TCP Keep-Alive ACK: ACK-only response to a Keep-Alive (same ack, zero payload)
        - TCP Dup ACK:     same ack number repeated, zero payload, ACK only
        - TCP Retransmission: seq < next_expected_seq AND payload > 0
        - TCP Out-Of-Order: seq < next_expected_seq AND could be reordered segment
        - TCP Window Update: same ack but different window size, zero payload
        
        Args:
            packet: The raw packet object (for TCP option inspection)
            src_ip, src_port, dst_ip, dst_port: Flow identifiers
            seq: TCP sequence number
            ack_num: TCP acknowledgment number  
            win: TCP window size
            payload_len: TCP payload length
            flag_str: TCP flags string
            
        Returns:
            str or None: Analysis label like 'TCP Keep-Alive' or None
        """
        # Only analyze established connections (ignore SYN/RST)
        # NOTE: FIN packets must NOT be excluded — Wireshark detects retransmission,
        # out-of-order, and prev-segment-not-captured on FIN packets.
        if 'SYN' in flag_str or 'RST' in flag_str:
            # Still update state for SYN packets (initial seq tracking)
            fwd_key = (src_ip, src_port, dst_ip, dst_port)
            if 'SYN' in flag_str:
                self._tcp_stream_state[fwd_key] = {
                    'next_expected_seq': seq + 1,
                    'last_ack': ack_num,
                    'last_win': win,
                    'last_payload_len': 0,
                    'last_seq': seq,
                    'seen_keepalive': False,
                    'dup_ack_count': 0,
                    'orig_ack_pkt_id': self.packet_id,
                    'highest_ack_seen': ack_num if 'ACK' in flag_str else 0
                }
                # Store ISN for this direction (for relative seq calculation)
                self._tcp_isn_state[fwd_key] = seq
            return None
        
        fwd_key = (src_ip, src_port, dst_ip, dst_port)
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        
        # === Pre-existing Connection Handling ===
        # If this is the first packet we've seen from this direction (no ISN stored
        # and no SYN seen), use this seq as ISN-1 so the packet shows as Seq=1
        if fwd_key not in self._tcp_isn_state:
            # Use seq-1 as ISN so first packet shows as relative seq=1 (matches Wireshark)
            self._tcp_isn_state[fwd_key] = seq - 1
        
        # Same for reverse direction ACK numbers - if we're ACKing data but don't
        # have reverse ISN, initialize it based on the ACK number
        if 'ACK' in flag_str and rev_key not in self._tcp_isn_state and ack_num > 0:
            # Use ack-1 as reverse ISN so ack shows as relative ack=1
            self._tcp_isn_state[rev_key] = ack_num - 1
        
        fwd_key = (src_ip, src_port, dst_ip, dst_port)
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        
        label = None
        
        # Get forward state (our previous state for this direction)
        fwd_state = self._tcp_stream_state.get(fwd_key)
        rev_state = self._tcp_stream_state.get(rev_key)
        
        # === Track highest ACK seen in reverse direction for spurious retransmission detection ===
        if 'ACK' in flag_str and rev_state:
            # Update highest ACK seen from this direction (to detect spurious retransmissions)
            if 'highest_ack_seen' not in rev_state or ack_num > rev_state['highest_ack_seen']:
                rev_state['highest_ack_seen'] = ack_num
        
        # FIN consumes 1 sequence number (like SYN), account for it in payload_len
        effective_payload_len = payload_len
        if 'FIN' in flag_str:
            effective_payload_len = payload_len + 1  # FIN counts as 1 byte
        
        if fwd_state and 'ACK' in flag_str:
            next_expected = fwd_state['next_expected_seq']
            
            # --- Skip Keep-Alive / Dup ACK checks for FIN packets ---
            # These heuristics only apply to pure ACK packets on established connections
            if 'FIN' not in flag_str:
                # --- TCP Keep-Alive Detection ---
                # Wireshark heuristic: seq = next_expected - 1, payload 0 or 1 byte,
                # flags are ACK only (no PSH)
                if (payload_len <= 1 and 
                    seq == next_expected - 1 and
                    'PSH' not in flag_str):
                    label = 'TCP Keep-Alive'
                    # Mark reverse direction so next ACK can be labeled Keep-Alive ACK
                    if rev_state:
                        rev_state['seen_keepalive'] = True
                
                # --- TCP Keep-Alive ACK Detection ---
                # ACK-only response where the reverse direction just sent a Keep-Alive
                elif (payload_len == 0 and
                      'PSH' not in flag_str and
                      fwd_state.get('seen_keepalive', False)):
                    label = 'TCP Keep-Alive ACK'
                    fwd_state['seen_keepalive'] = False
                
                # --- TCP Dup ACK Detection ---
                # Wireshark heuristic: same ack number, zero payload, ACK-only.
                # Window must match UNLESS SACK blocks are present (SACK-based
                # Dup ACKs often have different window sizes).
                elif (payload_len == 0 and
                      ack_num == fwd_state['last_ack'] and
                      seq == next_expected and
                      'PSH' not in flag_str):
                    # Check if SACK blocks are present in TCP options
                    has_sack = False
                    try:
                        for opt_name, _ in packet[TCP].options:
                            if opt_name == 'SAck':
                                has_sack = True
                                break
                    except Exception:
                        pass
                    
                    # Dup ACK if window matches OR SACK data is present
                    if win == fwd_state['last_win'] or has_sack:
                        dup_count = fwd_state.get('dup_ack_count', 0) + 1
                        fwd_state['dup_ack_count'] = dup_count
                        orig_pkt = fwd_state.get('orig_ack_pkt_id', self.packet_id - 1)
                        label = f'TCP Dup ACK {orig_pkt}#{dup_count}'
            
            # --- TCP Retransmission / Spurious Retransmission / Out-Of-Order Detection ---
            # Applies to both data packets AND FIN packets
            if label is None and (payload_len > 0 or 'FIN' in flag_str) and seq < next_expected:
                # Check if this data was already ACKed by the peer (spurious retransmission)
                fwd_isn = self._tcp_isn_state.get(fwd_key, 0)
                abs_seq_end = seq + effective_payload_len
                
                # Check reverse direction's highest ACK (in absolute terms)
                if rev_state and 'highest_ack_seen' in rev_state:
                    highest_ack = rev_state['highest_ack_seen']
                    
                    # If the retransmitted data was already fully ACKed, it's spurious
                    if abs_seq_end <= highest_ack:
                        label = 'TCP Spurious Retransmission'
                    elif seq + effective_payload_len <= next_expected:
                        label = 'TCP Retransmission'
                    else:
                        label = 'TCP Out-Of-Order'
                else:
                    # No reverse state, use original logic
                    if seq + effective_payload_len <= next_expected:
                        label = 'TCP Retransmission'
                    else:
                        label = 'TCP Out-Of-Order'
            
            # --- TCP ZeroWindow Detection ---
            # ACK packet with window size = 0 (receiver's buffer is full)
            if label is None and payload_len == 0 and win == 0 and 'FIN' not in flag_str:
                label = 'TCP ZeroWindow'
            
            # --- TCP Window Update Detection ---
            elif (label is None and
                  payload_len == 0 and
                  ack_num == fwd_state['last_ack'] and
                  win != fwd_state['last_win'] and
                  'PSH' not in flag_str and
                  'FIN' not in flag_str):
                label = 'TCP Window Update'
            
            # --- TCP ACKed unseen segment Detection ---
            # Our ACK references data from the peer that we haven't tracked yet
            elif (label is None and
                  payload_len == 0 and
                  'PSH' not in flag_str and
                  'FIN' not in flag_str and
                  rev_state is None and
                  ack_num > 0):
                label = 'TCP ACKed unseen segment'
        
        # --- TCP Previous segment not captured ---
        # Data packet (or FIN) where seq > next_expected_seq (gap)
        if fwd_state and (payload_len > 0 or 'FIN' in flag_str) and label is None:
            if seq > fwd_state['next_expected_seq']:
                label = 'TCP Previous segment not captured'
        
        # Update forward state for next packet comparison
        # Use effective_payload_len to account for FIN consuming 1 seq number
        new_next_expected = seq + effective_payload_len if effective_payload_len > 0 else (fwd_state['next_expected_seq'] if fwd_state else seq)
        # Only advance next_expected_seq if the new data goes beyond what we've seen
        if fwd_state and effective_payload_len > 0:
            new_next_expected = max(fwd_state['next_expected_seq'], seq + effective_payload_len)
        
        # Reset dup_ack_count when ack number changes
        dup_ack_count = fwd_state.get('dup_ack_count', 0) if fwd_state else 0
        orig_ack_pkt_id = fwd_state.get('orig_ack_pkt_id', self.packet_id) if fwd_state else self.packet_id
        if fwd_state and ack_num != fwd_state['last_ack']:
            dup_ack_count = 0
            orig_ack_pkt_id = self.packet_id
        
        self._tcp_stream_state[fwd_key] = {
            'next_expected_seq': new_next_expected,
            'last_ack': ack_num,
            'last_win': win,
            'last_payload_len': payload_len,
            'last_seq': seq,
            'seen_keepalive': fwd_state.get('seen_keepalive', False) if fwd_state else False,
            'dup_ack_count': dup_ack_count,
            'orig_ack_pkt_id': orig_ack_pkt_id,
            'highest_ack_seen': max(fwd_state.get('highest_ack_seen', ack_num), ack_num) if fwd_state else ack_num
        }
        
        return label
    
    def _format_tcp_info_wireshark(self, packet, src_port, dst_port, flag_str, seq, ack_num, win, payload_len, tcp_analysis_label=None, extra_suffix=''):
        """
        Generate Wireshark-exact info string for TCP packets.
        Uses relative seq/ack (ISN-based) and scaled window values.
        
        Format: [analysis] src_port  >  dst_port [FLAGS] Seq=X Ack=X Win=X Len=X OPTIONS [suffix]
        """
        parts = []
        
        # == Compute relative seq/ack ==
        src_ip = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else '')
        dst_ip = packet[IP].dst if IP in packet else (packet[IPv6].dst if IPv6 in packet else '')
        
        fwd_key = (src_ip, src_port, dst_ip, dst_port)
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        
        # Relative seq: subtract this direction's ISN
        rel_seq = seq
        fwd_isn = self._tcp_isn_state.get(fwd_key)
        if fwd_isn is not None:
            rel_seq = (seq - fwd_isn) & 0xFFFFFFFF  # Handle wrap-around
        
        # Relative ack: subtract the peer direction's ISN
        rel_ack = ack_num
        rev_isn = self._tcp_isn_state.get(rev_key)
        if rev_isn is not None:
            rel_ack = (ack_num - rev_isn) & 0xFFFFFFFF
        
        # == Compute scaled window ==
        # CRITICAL: Do NOT scale SYN/SYN-ACK packets per Wireshark behavior
        # The window scale factor is negotiated during the handshake but not
        # applied to the handshake packets themselves
        scaled_win = win
        if 'SYN' not in flag_str:  # Only scale after handshake completes
            win_scale = self._tcp_win_scale.get(fwd_key)
            if win_scale is not None and win_scale > 0:
                scaled_win = win * win_scale
        
        # 1. Analysis label prefix (if any)
        if tcp_analysis_label:
            parts.append(f'[{tcp_analysis_label}]')
        
        # 2. Port > Port [FLAGS]
        parts.append(f'{src_port}  >  {dst_port} [{flag_str}]')
        
        # 3. Seq/Ack/Win/Len
        parts.append(f'Seq={rel_seq}')
        if 'ACK' in flag_str:
            parts.append(f'Ack={rel_ack}')
        parts.append(f'Win={scaled_win}')
        parts.append(f'Len={payload_len}')
        
        # 4. TCP options (TSval, TSecr, MSS, WS, SACK_PERM, SLE, SRE)
        # Pass reverse ISN for SACK relative sequence calculation
        rev_isn = self._tcp_isn_state.get(rev_key)
        tcp_opts = self._extract_tcp_options(packet, fwd_isn=rev_isn)
        if tcp_opts:
            parts.append(tcp_opts)
        
        # 5. Extra suffix (e.g., '[TCP segment of a reassembled PDU]')
        if extra_suffix:
            parts.append(extra_suffix)
        
        return ' '.join(parts)
    
    def _extract_dns_info(self, packet):
        """
        Extract Wireshark-format DNS information: transaction ID, query type, domain name, response records.
        
        Returns:
            str: Wireshark-format DNS info string
        """
        try:
            if not packet.haslayer(DNS):
                return 'DNS'
            
            dns = packet[DNS]
            
            # Transaction ID in hex
            txn_id = f'0x{dns.id:04x}' if dns.id is not None else ''
            
            # Get query name and type
            qname = ''
            qtype_name = ''
            if dns.qd:
                raw_qname = dns.qd.qname
                if isinstance(raw_qname, bytes):
                    qname = raw_qname.decode('utf-8', errors='replace').rstrip('.')
                else:
                    qname = str(raw_qname).rstrip('.')
                qtype_name = DNS_QTYPES.get(dns.qd.qtype, str(dns.qd.qtype))
            
            # EDNS0 (OPT record) detection
            has_opt = False
            if dns.ar:
                try:
                    rr = dns.ar
                    while rr:
                        if hasattr(rr, 'type') and rr.type == 41:  # OPT record
                            has_opt = True
                            break
                        rr = rr.payload if hasattr(rr, 'payload') and rr.payload and rr.payload.name != 'NoPayload' else None
                except Exception:
                    pass
            opt_suffix = ' OPT' if has_opt else ''
            
            if dns.qr == 0:  # Query
                return f'Standard query {txn_id} {qtype_name} {qname}{opt_suffix}'
            else:  # Response
                answers = []
                if dns.an:
                    for i, rr in enumerate(dns.an):
                        if i >= 8:  # Wireshark shows many
                            break
                        try:
                            if hasattr(rr, 'type') and hasattr(rr, 'rdata'):
                                rtype = DNS_QTYPES.get(rr.type, str(rr.type))
                                rdata = rr.rdata
                                # Clean up bytes objects (CNAME, SOA, etc.)
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode('utf-8', errors='replace').rstrip('.')
                                else:
                                    rdata = str(rdata).rstrip('.')
                                answers.append(f'{rtype} {rdata}')
                        except Exception:
                            pass
                
                # Check additional records for SOA (authority section)
                if dns.ns:
                    try:
                        for i, rr in enumerate(dns.ns):
                            if i >= 2:
                                break
                            if hasattr(rr, 'type') and rr.type == 6:  # SOA
                                mname = rr.mname
                                if isinstance(mname, bytes):
                                    mname = mname.decode('utf-8', errors='replace').rstrip('.')
                                else:
                                    mname = str(mname).rstrip('.')
                                answers.append(f'SOA {mname}')
                    except Exception:
                        pass
                
                if not answers:
                    answer_str = ''
                else:
                    answer_str = ' ' + ' '.join(answers)
                
                return f'Standard query response {txn_id} {qtype_name} {qname}{answer_str}{opt_suffix}'
        except Exception:
            return 'DNS'
    
    def _extract_http_info(self, packet):
        """
        Extract detailed HTTP information: method, URL, status code, content type.
        
        Returns:
            tuple: (app_proto, info_str)
        """
        try:
            if packet.haslayer(HTTPRequest):
                req = packet[HTTPRequest]
                method = req.Method.decode() if req.Method else 'GET'
                path = req.Path.decode() if req.Path else '/'
                version = req.Http_Version.decode() if req.Http_Version else 'HTTP/1.1'
                host = req.Host.decode() if req.Host else ''
                return 'HTTP', f'{method} {path} {version}'
            
            elif packet.haslayer(HTTPResponse):
                resp = packet[HTTPResponse]
                version = resp.Http_Version.decode() if resp.Http_Version else '1.1'
                code = resp.Status_Code.decode() if resp.Status_Code else '???'
                reason = resp.Reason_Phrase.decode() if resp.Reason_Phrase else ''
                ctype = ''
                if resp.Content_Type:
                    ctype = resp.Content_Type.decode().split(';')[0].strip()
                    return 'HTTP', f'HTTP/{version} {code} {reason} ({ctype})'
                return 'HTTP', f'HTTP/{version} {code} {reason}'
        except Exception:
            pass
        return None, None
    
    def _detect_tls_handshake(self, packet):
        """Detect TLS handshake by checking for 0x16 byte in payload."""
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            if len(payload) > 0 and payload[0] == 0x16:
                return True
        return False
    
    def _fast_callback(self, packet):
        """Ultra-fast sniff callback — just queue raw bytes, zero processing."""
        self._packet_queue.put(bytes(packet))
    
    def _raw_capture(self, iface, count=0):
        """
        High-speed packet capture using Linux AF_PACKET raw socket.
        Bypasses Scapy's sniff() overhead for kernel-level speed.
        
        KEY PERFORMANCE OPTIMIZATIONS:
        1. 64MB SO_RCVBUF — kernel can buffer 40,000+ packets during bursts
        2. Raw bytes queued directly — NO Scapy parsing in capture loop
        3. Non-blocking recv with select/poll for fast loop control
        
        Args:
            iface: Network interface name (required for AF_PACKET)
            count: Number of packets to capture (0 = infinite)
        """
        import select
        
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        raw_sock.bind((iface, 0))
        
        # === CRITICAL: Massive receive buffer ===
        # Default rmem_max is ~208KB which caps SO_RCVBUF at ~425KB.
        # This causes packet drops during 2000+ pkt/s bursts.
        # We auto-raise rmem_max (we're root since AF_PACKET requires it).
        target_buf = 64 * 1024 * 1024  # 64 MB
        try:
            with open('/proc/sys/net/core/rmem_max', 'w') as f:
                f.write(str(target_buf))
        except (PermissionError, OSError):
            pass  # Non-fatal: will use whatever rmem_max allows
        
        try:
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, target_buf)
        except OSError:
            try:
                raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
        
        actual_buf = raw_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        buf_mb = actual_buf / 1024 / 1024
        if buf_mb < 1.0:
            print(f"  ⚠️  Socket Buffer: {buf_mb:.1f} MB (LOW — may drop packets during bursts)")
            print(f"      Fix: sudo sysctl -w net.core.rmem_max={target_buf}")
        else:
            print(f"  Socket Buffer: {buf_mb:.1f} MB")
        
        # Use non-blocking with select() for responsive shutdown
        raw_sock.setblocking(False)
        
        captured = 0
        try:
            while not self.stop_sniffing.is_set():
                # Wait for data with 0.5s timeout (allows stop check)
                ready, _, _ = select.select([raw_sock], [], [], 0.5)
                if not ready:
                    continue
                
                # Drain all available packets in tight loop
                while True:
                    try:
                        raw_data = raw_sock.recv(65535)
                        # Queue RAW BYTES — no Scapy parsing here!
                        # Worker thread will call Ether(raw_data) later
                        self._packet_queue.put(raw_data)
                        captured += 1
                        if count > 0 and captured >= count:
                            return
                    except BlockingIOError:
                        break  # No more data available right now
                    except Exception:
                        if self.stop_sniffing.is_set():
                            return
                        break
        finally:
            raw_sock.close()
    
    def _packet_worker(self):
        """Worker thread: drain queue, parse raw bytes, and process packets."""
        from scapy.all import Ether
        
        while not (self.stop_sniffing.is_set() and self._packet_queue.empty()):
            try:
                raw_data = self._packet_queue.get(timeout=0.5)
                # Parse raw bytes into Scapy packet here (NOT in capture thread)
                try:
                    packet = Ether(raw_data)
                except Exception:
                    self._packet_queue.task_done()
                    continue
                self.packet_callback(packet)
                self._packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                # Only print errors if we're not shutting down
                if not self.stop_sniffing.is_set():
                    print(f"[!] Worker error: {e}")
        self._processing_done.set()
    
    def _determine_direction(self, src_ip, dst_ip):
        """Determine if traffic is INCOMING or OUTGOING."""
        # Check if source is our local IP (outgoing)
        if src_ip in self.local_ip:
            return 'OUTGOING'
        # Check if destination is our local IP (incoming)
        elif dst_ip in self.local_ip:
            return 'INCOMING'
        else:
            # For packets not directly to/from local IP (e.g., promiscuous mode)
            # If source is private/local, assume outgoing; otherwise incoming
            if self._is_private_ip(src_ip):
                return 'OUTGOING'
            else:
                return 'INCOMING'
    
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
                # If someone is asking for OUR IP, it's incoming; if WE are asking, it's outgoing
                if arp_layer.pdst in self.local_ip:
                    packet_data['direction'] = 'INCOMING'
                else:
                    packet_data['direction'] = 'OUTGOING'
            elif arp_layer.op == 2:  # ARP Reply
                packet_data['info'] = f"{arp_layer.psrc} is at {arp_layer.hwsrc}"
                # If WE are replying (source is our IP), it's outgoing
                if arp_layer.psrc in self.local_ip:
                    packet_data['direction'] = 'OUTGOING'
                else:
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
            seq = packet[TCP].seq
            ack_num = packet[TCP].ack
            win = packet[TCP].window
            
            # Store ports as separate fields
            packet_data['src_port'] = src_port
            packet_data['dst_port'] = dst_port
            
            # Extract TCP flags
            packet_data['tcp_flags'] = self._extract_tcp_flags(tcp_flags_raw)
            
            # Payload length
            payload_len = len(packet[TCP].payload) if packet[TCP].payload else 0
            
            # Flag display
            flag_str = packet_data['tcp_flags']
            flag_display = f"[{flag_str}]" if flag_str else ""
            
            # Extract window scale from SYN/SYN-ACK for future window scaling
            if tcp_flags_raw & 0x02:  # SYN flag set
                fwd_key = (packet_data['src'], src_port, packet_data['dst'], dst_port)
                try:
                    for opt_name, opt_val in packet[TCP].options:
                        if opt_name == 'WScale':
                            self._tcp_win_scale[fwd_key] = (1 << opt_val) if opt_val else 1
                            break
                except Exception:
                    pass
            
            # === TCP Stream Analysis (Wireshark-style labels) ===
            # MUST run BEFORE application-layer detection (TLS, HTTP) so that
            # every TCP packet updates stream state (next_expected_seq, etc.).
            # Without this, TLS packets that return early leave stale state,
            # causing Keep-Alive/Dup ACK/Retransmission detection to fail.
            tcp_analysis_label = self._analyze_tcp_stream(
                packet, packet_data['src'], src_port,
                packet_data['dst'], dst_port,
                seq, ack_num, win, payload_len, flag_str
            )
            
            # === Detect [TCP segment of a reassembled PDU] ===
            # Data packets without PSH flag (not the last segment)
            extra_suffix = ''
            if payload_len > 0 and 'PSH' not in flag_str and 'SYN' not in flag_str and 'FIN' not in flag_str:
                extra_suffix = '[TCP segment of a reassembled PDU]'
            
            # === Deep Protocol Detection (content-based, like Wireshark) ===
            
            # 1. Try HTTP layer detection first (Scapy auto-detects HTTP content)
            http_proto, http_info = self._extract_http_info(packet)
            if http_proto:
                # If a TCP analysis label was found, it takes priority over HTTP
                if tcp_analysis_label:
                    packet_data['application_protocol'] = 'TCP'
                    packet_data['info'] = self._format_tcp_info_wireshark(
                        packet, src_port, dst_port, flag_str,
                        seq, ack_num, win, payload_len,
                        tcp_analysis_label=tcp_analysis_label,
                        extra_suffix=extra_suffix)
                    return packet_data
                packet_data['application_protocol'] = http_proto
                packet_data['info'] = http_info
                return packet_data
            
            # 2. Try deep TLS analysis (version, SNI, handshake type)
            #    Try BOTH Raw payload and TCP payload bytes — Scapy may
            #    put the TCP payload in different layers depending on dissection.
            tls_payload = None
            if Raw in packet:
                tls_payload = bytes(packet[Raw].load)
            
            # Also get raw TCP payload bytes as fallback
            tcp_raw_payload = None
            if TCP in packet and packet[TCP].payload:
                try:
                    tcp_raw_payload = bytes(packet[TCP].payload)
                except Exception:
                    pass
            
            # Try TLS parsing on Raw first, then TCP payload as fallback
            tls_ver, tls_info = None, None
            if tls_payload:
                tls_ver, tls_info = self._analyze_tls_payload(tls_payload)
            if not tls_ver and tcp_raw_payload and tcp_raw_payload != tls_payload:
                tls_ver, tls_info = self._analyze_tls_payload(tcp_raw_payload)
                if tls_ver:
                    tls_payload = tcp_raw_payload  # Use this payload going forward
            
            if tls_ver and tls_info:
                # Record the TLS version for this flow so subsequent
                # packets (ACKs, empty data) inherit the correct version
                flow_key = frozenset({
                    (packet_data['src'], src_port),
                    (packet_data['dst'], dst_port)
                })
                # Server Hello determines the *negotiated* version, so it
                # takes precedence over Client Hello (which only advertises)
                if 'Server Hello' in tls_info or 'Hello Retry Request' in tls_info or flow_key not in self._tls_flow_versions:
                    self._tls_flow_versions[flow_key] = tls_ver
                
                # Override TLS record version with flow-negotiated version
                # (e.g., record says TLSv1.0 but flow negotiated TLSv1.3)
                known_ver = self._tls_flow_versions.get(flow_key)
                if known_ver and known_ver != tls_ver:
                    # For non-handshake records — use negotiated version
                    if any(x in tls_info for x in ('Application Data', 'Change Cipher Spec', 'Alert', 'Continuation Data')):
                        tls_ver = known_ver
                    # Also upgrade Client Hello that detected TLS 1.3 via extensions
                    elif 'Client Hello' in tls_info and known_ver == 'TLSv1.3':
                        tls_ver = known_ver
                
                # If TCP analysis label found (Retransmission, Out-Of-Order, etc.),
                # it takes priority — show as TCP with the analysis label prefix,
                # matching Wireshark behavior
                if tcp_analysis_label:
                    packet_data['application_protocol'] = 'TCP'
                    packet_data['info'] = self._format_tcp_info_wireshark(
                        packet, src_port, dst_port, flag_str,
                        seq, ack_num, win, payload_len,
                        tcp_analysis_label=tcp_analysis_label,
                        extra_suffix=extra_suffix)
                    return packet_data
                
                # If this is a non-PSH segment (part of a reassembled PDU),
                # show as protocol=TCP with reassembly suffix — matching Wireshark
                # which only shows TLS content on the final reassembled frame
                if extra_suffix:
                    packet_data['application_protocol'] = 'TCP'
                    packet_data['info'] = self._format_tcp_info_wireshark(
                        packet, src_port, dst_port, flag_str,
                        seq, ack_num, win, payload_len,
                        tcp_analysis_label=tcp_analysis_label,
                        extra_suffix=extra_suffix)
                    return packet_data
                
                packet_data['application_protocol'] = tls_ver
                packet_data['info'] = tls_info
                return packet_data
            
            # === TLS flow detection fallback ===
            # If TLS parsing failed but this flow is known to be TLS
            if tls_payload or tcp_raw_payload:
                effective_payload = tls_payload or tcp_raw_payload
                flow_key = frozenset({
                    (packet_data['src'], src_port),
                    (packet_data['dst'], dst_port)
                })
                known_tls_ver = self._tls_flow_versions.get(flow_key)
                if known_tls_ver and payload_len > 0:
                    # If TCP analysis label found, it takes priority
                    if tcp_analysis_label:
                        packet_data['application_protocol'] = 'TCP'
                        packet_data['info'] = self._format_tcp_info_wireshark(
                            packet, src_port, dst_port, flag_str,
                            seq, ack_num, win, payload_len,
                            tcp_analysis_label=tcp_analysis_label,
                            extra_suffix=extra_suffix)
                        return packet_data
                    # If non-PSH segment, show as reassembled PDU
                    if extra_suffix:
                        packet_data['application_protocol'] = 'TCP'
                        packet_data['info'] = self._format_tcp_info_wireshark(
                            packet, src_port, dst_port, flag_str,
                            seq, ack_num, win, payload_len,
                            tcp_analysis_label=tcp_analysis_label,
                            extra_suffix=extra_suffix)
                        return packet_data
                    
                    # Try _parse_tls_records as a more lenient fallback parser
                    # It handles multi-record payloads and now extracts SNI
                    fallback_ver, fallback_info = self._parse_tls_records(effective_payload)
                    if fallback_ver and fallback_info:
                        # Use flow version instead of record version
                        packet_data['application_protocol'] = known_tls_ver
                        packet_data['info'] = fallback_info
                        return packet_data
                    
                    # Last resort: show as Application Data on known TLS flow
                    packet_data['application_protocol'] = known_tls_ver
                    packet_data['info'] = 'Application Data'
                    return packet_data
            
            # 3. Port-based application protocol fallback
            #    Wireshark rule: protocol = TCP unless there's actual TLS payload.
            #    ACK-only packets on port 443 stay as 'TCP', not 'TLSv1.3'.
            app_proto = 'TCP'
            if dst_port == 80 or src_port == 80:
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
            elif dst_port == 9050 or src_port == 9050:
                app_proto = 'Tor-SOCKS'
            elif dst_port == 9150 or src_port == 9150:
                app_proto = 'Tor-Browser'
            elif dst_port == 1080 or src_port == 1080:
                app_proto = 'SOCKS'
            elif dst_port == 3128 or src_port == 3128:
                app_proto = 'Squid-Proxy'
            elif dst_port == 8888 or src_port == 8888:
                app_proto = 'HTTP-Proxy'
            elif dst_port == 6881 or src_port == 6881:
                app_proto = 'BitTorrent'
            elif 6881 <= dst_port <= 6889 or 6881 <= src_port <= 6889:
                app_proto = 'BitTorrent'
            elif dst_port == 9200 or src_port == 9200:
                app_proto = 'Elasticsearch'
            elif dst_port == 5984 or src_port == 5984:
                app_proto = 'CouchDB'
            elif dst_port == 11211 or src_port == 11211:
                app_proto = 'Memcached'
            elif dst_port == 5672 or src_port == 5672:
                app_proto = 'AMQP'
            elif dst_port == 1883 or src_port == 1883:
                app_proto = 'MQTT'
            elif dst_port == 9092 or src_port == 9092:
                app_proto = 'Kafka'
            elif dst_port == 25565 or src_port == 25565:
                app_proto = 'Minecraft'
            elif dst_port == 2375 or src_port == 2375:
                app_proto = 'Docker'
            elif dst_port == 2376 or src_port == 2376:
                app_proto = 'Docker-TLS'
            elif dst_port == 6443 or src_port == 6443:
                app_proto = 'Kubernetes'
            elif dst_port == 9418 or src_port == 9418:
                app_proto = 'Git'
            elif dst_port == 389 or src_port == 389:
                app_proto = 'LDAP'
            elif dst_port == 636 or src_port == 636:
                app_proto = 'LDAPS'
            elif dst_port == 43 or src_port == 43:
                app_proto = 'WHOIS'
            
            packet_data['application_protocol'] = app_proto
            
            # === Wireshark-exact TCP Info ===
            # tcp_analysis_label and extra_suffix were already computed
            # before the protocol detection block above
            packet_data['info'] = self._format_tcp_info_wireshark(
                packet, src_port, dst_port, flag_str,
                seq, ack_num, win, payload_len,
                tcp_analysis_label=tcp_analysis_label,
                extra_suffix=extra_suffix
            )
        
        # ==== UDP Protocol Handling ====
        elif UDP in packet:
            packet_data['transport_protocol'] = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Store ports as separate fields
            packet_data['src_port'] = src_port
            packet_data['dst_port'] = dst_port
            
            # Application protocol detection with deep inspection
            app_proto = 'UDP'
            if dst_port == 443 or src_port == 443:
                # QUIC detection (HTTP/3 over UDP port 443)
                app_proto = 'QUIC'
                
                # Check for QUIC packet patterns in payload
                # QUIC v1 (RFC 9000): All packets have the Fixed Bit (0x40) set.
                # Long Header: bit 7 (0x80) set — Initial, 0-RTT, Handshake, Retry
                # Short Header: bit 7 clear, but Fixed Bit (0x40) still set
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load)
                    if len(payload) > 0:
                        first_byte = payload[0]
                        if first_byte & 0x80:  # Long Header
                            # Determine specific long header type from bits 4-5
                            long_type = (first_byte & 0x30) >> 4
                            if long_type == 0:
                                packet_data['info'] = 'QUIC: Initial'
                            elif long_type == 1:
                                packet_data['info'] = 'QUIC: 0-RTT'
                            elif long_type == 2:
                                packet_data['info'] = 'QUIC: Handshake'
                            elif long_type == 3:
                                packet_data['info'] = 'QUIC: Retry'
                            else:
                                packet_data['info'] = 'QUIC: Connection Handshake'
                        elif first_byte & 0x40:  # Short Header (Fixed Bit set)
                            packet_data['info'] = f'QUIC: Protected Payload ({len(payload)} bytes)'
                        else:
                            # Neither long nor short header — possibly Version Negotiation
                            packet_data['info'] = f'QUIC: Encrypted Data ({len(payload)} bytes)'
                    else:
                        packet_data['info'] = 'QUIC: Empty Payload'
                else:
                    packet_data['info'] = f'QUIC: Protected Payload'
            elif dst_port == 53 or src_port == 53:
                app_proto = 'DNS'
                packet_data['info'] = self._extract_dns_info(packet)
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
                # mDNS also uses DNS format, so extract details
                packet_data['info'] = self._extract_dns_info(packet)
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
                packet_data['info'] = f'UDP Datagram :{dst_port} ({len(packet[UDP].payload)} bytes)'
            
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
        elif transport_proto_num == 58 or (is_ipv6 and (
            packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA) or
            packet.haslayer(ICMPv6ND_RA) or packet.haslayer(ICMPv6MLReport2) or
            packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply) or
            packet.haslayer(ICMPv6DestUnreach) or packet.haslayer(ICMPv6PacketTooBig) or
            packet.haslayer(ICMPv6TimeExceeded)
        )):  # ICMPv6: direct or behind extension headers (e.g. Hop-by-Hop)
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
                ns_layer = packet[ICMPv6ND_NS]
                target_addr = ns_layer.tgt
                # Extract source link-layer address from options if present
                src_mac = ''
                if packet.haslayer(ICMPv6NDOptSrcLLAddr):
                    src_mac = packet[ICMPv6NDOptSrcLLAddr].lladdr
                elif hasattr(packet, 'src') and Ether in packet:
                    src_mac = packet[Ether].src
                if src_mac:
                    packet_data['info'] = f'Neighbor Solicitation for {target_addr} from {src_mac}'
                else:
                    packet_data['info'] = f'Neighbor Solicitation for {target_addr}'
            elif packet.haslayer(ICMPv6ND_NA):
                na_layer = packet[ICMPv6ND_NA]
                target_addr = na_layer.tgt
                # Check if solicited flag is set (R=0, S=1, O=1 typical for solicited)
                sol_flag = '(sol)' if na_layer.S else '(rtr)'
                packet_data['info'] = f'Neighbor Advertisement {target_addr} {sol_flag}'
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
            pass  # Silent during shutdown
    
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
        # Skip processing if we're shutting down
        if self.stop_sniffing.is_set():
            return
        
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
        Uses queue-based architecture for zero-drop capture.
        
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
            print(f"Local IPs: {', '.join(self.local_ip)}")
            print(f"Database: {self.db_path}")
            if self.csv_file:
                print(f"CSV Export: {self.csv_file}")
            print(f"Session ID: {self.session_id}")
            print(f"Packets to Capture: {count if count > 0 else '∞'}")
            print(f"Capture Mode: Queue-based (zero-drop)")
            print("-" * 100)
            print(f"{'[ID]':<7} {'[Timestamp]':<27} {'[RelTime]':<10} {'PROTOCOL':<9} | {'SOURCE':<22} → {'DESTINATION':<22} | {'DIRECTION':<9} | {'SIZE':<6} | INFO")
            print("-" * 100 + "\n")
            
            # Start worker thread for packet processing
            self._worker_thread = threading.Thread(
                target=self._packet_worker,
                name="NetGuard-PacketWorker",
                daemon=True
            )
            self._worker_thread.start()
            
            # Start sniffing — use AF_PACKET raw socket when possible (Linux + specific interface)
            # AF_PACKET bypasses Scapy's internal overhead for kernel-level speed
            if self.interface and hasattr(socket, 'AF_PACKET'):
                print("Capture Engine: AF_PACKET raw socket (kernel-level speed)")
                self._raw_capture(self.interface, count=count)
            else:
                # Fallback to Scapy's sniff() for cross-platform or all-interface capture
                sniff(
                    iface=self.interface,
                    prn=self._fast_callback,
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
            # Signal worker to stop and wait for it to drain the queue
            self.stop_sniffing.set()
            if self._worker_thread and self._worker_thread.is_alive():
                try:
                    print("[*] Processing remaining queued packets...")
                    self._worker_thread.join(timeout=10)
                except KeyboardInterrupt:
                    print("\n[!] Skipping queue drain (interrupted)")
            
            # Close CSV file if open
            try:
                if hasattr(self, 'csv_file_handle') and self.csv_file_handle:
                    self.csv_file_handle.close()
            except Exception:
                pass
            
            # End database session
            try:
                if self.session_id:
                    self.db.end_session(self.session_id, self.packets_captured, self.total_bytes)
            except Exception:
                pass
            
            # Close database connection
            try:
                self.db.close()
            except Exception:
                pass
            
            # Always print summary on exit
            try:
                if self.packets_captured > 0:
                    self._print_session_summary()
            except Exception:
                pass


