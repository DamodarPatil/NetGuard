"""
TsharkCapture — dumpcap + tshark zero-drop capture backend for FlowSentrix.

Architecture (true zero-drop):
  Process 1 (dumpcap):   Captures at kernel speed → writes .pcapng directly (pure C, no Python)
  Process 2 (tshark):    Captures independently → dissects → text output for live display
  Thread 1 (reader):     tshark stdout → fast drain into in-memory queue
  Thread 2 (worker):     queue → parse → batch DB insert + on_packet callback

dumpcap writes to file in pure C with kernel ring buffers — zero packet loss
guaranteed regardless of Python processing speed. tshark runs independently
for live display and may lag slightly under extreme load, but the pcap file
always has every packet.
"""

import subprocess
import threading
import queue
import socket
import os
import time
from datetime import datetime

from core.database import FlowSentrixDatabase
from core.connection_tracker import ConnectionTracker
from core.behavior_engine import BehaviorEngine
from intelligence.suricata import SuricataEngine
from config import load_tuning_config


# Protocols that are transport-layer
TRANSPORT_PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IGMP', 'GRE', 'SCTP', 'RTP', 'RTCP', 'SRTP', 'SRTCP'}

# tshark fields — order matters for parsing
TSHARK_FIELDS = [
    'frame.number',        # 0
    'frame.time_epoch',    # 1
    'frame.time_relative', # 2
    'ip.src',              # 3
    'ipv6.src',            # 4
    'ip.dst',              # 5
    'ipv6.dst',            # 6
    'tcp.srcport',         # 7
    'udp.srcport',         # 8
    'tcp.dstport',         # 9
    'udp.dstport',         # 10
    '_ws.col.Protocol',    # 11
    'frame.len',           # 12
    'tcp.flags.str',       # 13
    'tls.handshake.extensions.supported_version',  # 14  TLS 1.3 detection
    'eth.src',             # 15  MAC src (for ARP etc.)
    'eth.dst',             # 16  MAC dst (for ARP etc.)
    '_ws.col.Info',        # 17  MUST be last (may contain tab chars)
]

FIELD_SEP = '\t'


class TsharkCapture:
    """
    Zero-drop packet capture using dumpcap + tshark (Wireshark engine).

    Same interface as PacketSniffer so shell.py works unchanged:
      - packets_captured, total_bytes
      - transport_counts, application_counts, direction_counts
      - stop_sniffing (threading.Event)
      - start(count=0)
      - on_packet callback
    """

    def __init__(self, interface=None, db_path="data/flowsentrix.db", csv_file=None, on_packet=None):
        self.interface = interface
        self.db_path = db_path
        self.csv_file = csv_file
        self.on_packet = on_packet
        self.stop_sniffing = threading.Event()

        # Statistics (same attribute names as PacketSniffer)
        self.packets_captured = 0
        self.total_bytes = 0
        self.transport_counts = {}
        self.application_counts = {}
        self.direction_counts = {'INCOMING': 0, 'OUTGOING': 0}

        # Accurate packet count from pcapng file (updated by monitor thread)
        self.pcap_packets_captured = 0
        self.pcap_total_bytes = 0

        # Subprocesses
        self._dumpcap = None
        self._tshark = None

        # Database
        self._db = FlowSentrixDatabase(db_path)
        self.session_id = None
        self.local_ips = self._get_local_ips()

        # Thread-safe queue for producer-consumer pattern
        self._packet_queue = queue.Queue(maxsize=0)  # Unbounded

        # Pcap file path (saved for user — can open in Wireshark)
        self.pcap_file = None

        # Reprocessing flag
        self._reprocessing = False

        # Frame dedup for live processing (prevents count inflation
        # if TCP reassembly causes duplicate tshark output lines)
        self._live_seen_frames = set()

        # Connection/flow tracker (replaces per-packet DB storage)
        self._tracker = ConnectionTracker()

        # Behavioral tagging engine (complements Suricata)
        self._behavior_engine = BehaviorEngine(db=self._db)

        # DNS reverse lookup: IP → domain name (for CDN-aware beaconing detection)
        # Populated from DNS response packets during capture
        self._ip_to_domain = {}

        # Per-flow TLS version tracking: upgrade TLSv1.2 → TLSv1.3 on flows
        # where 1.3 was negotiated (tshark without reassembly uses record-header
        # version 0x0303 which maps to TLSv1.2 even for TLS 1.3 connections)
        # Key: frozenset({(ip, port), (ip, port)})  Value: 'TLSv1.3' etc.
        self._tls_flow_versions = {}

        # Track which behavioral alerts we've already sent (avoid duplicates on each flush)
        self._alerted_behaviors = set()  # {(dst_ip_or_domain, tag_name), ...}

        # Suricata IDS engine (Process 3)
        self._suricata = None
        self.alerts = []  # Live alerts for CLI access

        # ── Tuning config: severity remap + do-not-suppress ──
        tuning_cfg = load_tuning_config()
        self._severity_remap = tuning_cfg.get('severity_remap', {})
        self._do_not_suppress = tuning_cfg.get('do_not_suppress', {})

        # CSV logging
        self._csv_writer = None
        self._csv_fh = None
        if csv_file:
            self._init_csv(csv_file)

    # ── Local IP detection ───────────────────────────────────────

    def _get_local_ips(self):
        """Get local IP addresses for direction detection."""
        ips = {'127.0.0.1', '::1'}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            ips.add(s6.getsockname()[0])
            s6.close()
        except Exception:
            pass
        return ips

    # ── CSV ──────────────────────────────────────────────────────

    def _init_csv(self, csv_file):
        import csv
        self._csv_fh = open(csv_file, 'w', newline='')
        self._csv_writer = csv.writer(self._csv_fh)
        self._csv_writer.writerow([
            'packet_id', 'absolute_timestamp', 'relative_time',
            'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'transport_protocol', 'application_protocol', 'tcp_flags',
            'direction', 'packet_length', 'info'
        ])

    def _log_csv(self, data):
        if self._csv_writer:
            self._csv_writer.writerow([
                data.get('packet_id', ''), data.get('absolute_timestamp', ''),
                data.get('relative_time', ''), data.get('src', ''),
                data.get('dst', ''), data.get('src_port', ''),
                data.get('dst_port', ''), data.get('transport_protocol', ''),
                data.get('application_protocol', ''), data.get('tcp_flags', ''),
                data.get('direction', ''), data.get('packet_length', ''),
                data.get('info', ''),
            ])
            self._csv_fh.flush()

    # ── IPv6 display ─────────────────────────────────────────────

    @staticmethod
    def _truncate_ipv6(addr):
        if len(addr) > 20:
            return addr[:17] + "..."
        return addr

    # ── Line parser ──────────────────────────────────────────────

    def _parse_line(self, line):
        """Parse a single tshark -T fields output line into packet_data dict."""
        parts = line.rstrip('\n').split(FIELD_SEP)
        if len(parts) < 15:
            return None

        frame_num    = parts[0]
        epoch_str    = parts[1]
        rel_time_str = parts[2]
        ip4_src      = parts[3]
        ip6_src      = parts[4]
        ip4_dst      = parts[5]
        ip6_dst      = parts[6]
        tcp_sport    = parts[7]
        udp_sport    = parts[8]
        tcp_dport    = parts[9]
        udp_dport    = parts[10]
        ws_proto     = parts[11]
        frame_len    = parts[12]
        tcp_flags    = parts[13]
        tls_sup_ver  = parts[14]  # tls.handshake.extensions.supported_version
        eth_src      = parts[15] if len(parts) > 15 else ''
        eth_dst      = parts[16] if len(parts) > 16 else ''
        ws_info      = FIELD_SEP.join(parts[17:]) if len(parts) > 17 else ''

        src = ip4_src or ip6_src or ''
        dst = ip4_dst or ip6_dst or ''
        # ARP and other non-IP packets: use MAC addresses like Wireshark
        if not src and not dst:
            src = eth_src or 'N/A'
            dst = eth_dst or 'N/A'

        src_port = tcp_sport or udp_sport or ''
        dst_port = tcp_dport or udp_dport or ''

        # Numeric conversions
        try:
            packet_id = int(frame_num)
        except ValueError:
            packet_id = 0
        try:
            rel_time = float(rel_time_str)
        except ValueError:
            rel_time = 0.0
        try:
            pkt_len = int(frame_len)
        except ValueError:
            pkt_len = 0
        try:
            src_port_int = int(src_port) if src_port else None
        except ValueError:
            src_port_int = None
        try:
            dst_port_int = int(dst_port) if dst_port else None
        except ValueError:
            dst_port_int = None

        # Timestamp
        try:
            epoch = float(epoch_str)
            abs_ts = datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except (ValueError, OSError):
            abs_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        # Two-tier protocol classification
        # Trust _ws.col.Protocol as-is — it's tshark's dissector output
        proto = ws_proto.strip() if ws_proto else 'UNKNOWN'

        # Fix TLSv1 → TLSv1.3: tshark shows "TLSv1" for Client Hello that
        # negotiates TLS 1.3 (record version 0x0301 is legacy). The real
        # version is in the supported_versions extension.
        if proto == 'TLSv1' and tls_sup_ver:
            # supported_version field contains the TLS version(s)
            # e.g. '0x0304' for TLS 1.3, '0x0303' for TLS 1.2
            versions = tls_sup_ver.replace(',', ' ').split()
            if '0x0304' in versions:
                proto = 'TLSv1.3'
            elif '0x0303' in versions:
                proto = 'TLSv1.2'

        # --- Per-flow TLS version tracking ---
        # TLS 1.3 uses 0x0303 (TLSv1.2) in record headers for compatibility.
        # Without reassembly, tshark labels most data packets as TLSv1.2 even
        # if TLS 1.3 was negotiated.  Track the negotiated version from
        # handshake packets and upgrade subsequent packets on the same flow.
        is_tls_proto = proto.startswith('TLS') or proto.startswith('SSL')
        if is_tls_proto and src_port_int is not None and dst_port_int is not None:
            flow_key = frozenset({(src, src_port_int), (dst, dst_port_int)})

            # If this packet has supported_versions info (handshake),
            # record the negotiated version for the flow
            if tls_sup_ver:
                versions = tls_sup_ver.replace(',', ' ').split()
                if '0x0304' in versions:
                    self._tls_flow_versions[flow_key] = 'TLSv1.3'
                elif '0x0303' in versions and flow_key not in self._tls_flow_versions:
                    self._tls_flow_versions[flow_key] = 'TLSv1.2'

            # Upgrade protocol using stored flow version
            known_ver = self._tls_flow_versions.get(flow_key)
            if known_ver and proto != known_ver:
                proto = known_ver

        if proto in TRANSPORT_PROTOCOLS:
            transport = proto
            application = proto
        else:
            if tcp_sport or tcp_dport:
                transport = 'TCP'
            elif udp_sport or udp_dport:
                transport = 'UDP'
            else:
                transport = 'UNKNOWN'
            application = proto

        # TCP flags
        flags_str = ''
        if tcp_flags and tcp_flags.strip('·'):
            flag_map = {
                'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST',
                'P': 'PSH', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
            }
            flags = [flag_map.get(c, c) for c in tcp_flags if c != '·' and c != ' ']
            flags_str = ', '.join(flags) if flags else ''

        # Direction
        if src in self.local_ips:
            direction = 'OUTGOING'
        elif dst in self.local_ips:
            direction = 'INCOMING'
        else:
            direction = 'OUTGOING'

        # Display addresses
        display_src = self._truncate_ipv6(src) if ':' in src else src
        display_dst = self._truncate_ipv6(dst) if ':' in dst else dst

        # --- Wireshark-matching for anomalous TLS segment labels ---
        # Fallback: if tshark ever labels a segment as "Continuation Data"
        # or "Ignored Unknown Record", convert to TCP segment indicator.
        # With tcp.desegment_tcp_streams:TRUE this rarely triggers, but
        # provides safety for edge cases.
        info_clean = ws_info.strip() if ws_info else ''
        if transport == 'TCP' and info_clean in ('Continuation Data', 'Ignored Unknown Record'):
            application = 'TCP'
            info_clean = '[TCP segment of a reassembled PDU]'

        # Normalize arrow: tshark -i - uses → but Wireshark GUI uses  >  
        info_clean = info_clean.replace('\u2192', '→')

        # Extract DNS domain→IP mappings from response packets
        if application == 'DNS' and info_clean:
            self._update_dns_mapping(info_clean)

        return {
            'packet_id': packet_id,
            'absolute_timestamp': abs_ts,
            'relative_time': rel_time,
            'src': src, 'dst': dst,
            'display_src': display_src, 'display_dst': display_dst,
            'src_port': src_port_int, 'dst_port': dst_port_int,
            'transport_protocol': transport,
            'application_protocol': application,
            'tcp_flags': flags_str,
            'direction': direction,
            'packet_length': pkt_len,
            'info': info_clean,
        }

    # ── DNS domain tracking ────────────────────────────────────

    def _update_dns_mapping(self, info_str):
        """Extract IP→domain mappings from DNS response info strings.

        tshark DNS response info looks like:
          'Standard query response 0x1234 A example.com A 104.18.27.120 A 104.18.26.120'
          'Standard query response 0x5678 AAAA example.com AAAA 2606:4700::1'

        We extract the domain and all resolved IPs, building a reverse lookup
        so the beaconing detector can group by domain instead of raw IP.
        """
        if 'response' not in info_str:
            return

        parts = info_str.split()
        domain = None
        ips = []

        i = 0
        while i < len(parts):
            if parts[i] in ('A', 'AAAA') and i + 1 < len(parts):
                next_val = parts[i + 1]
                if '.' in next_val and not next_val.startswith('0x'):
                    # Could be a domain name or an IP address
                    # Domain names have letters; IPs are all digits and dots
                    has_alpha = any(c.isalpha() for c in next_val)
                    if has_alpha and domain is None:
                        # This is the queried domain name
                        domain = next_val
                    elif not has_alpha or ':' in next_val:
                        # This is an IP address (IPv4 or IPv6)
                        ips.append(next_val)
                elif ':' in next_val:
                    # IPv6 address
                    ips.append(next_val)
                i += 2
            else:
                i += 1

        if domain and ips:
            for ip in ips:
                self._ip_to_domain[ip] = domain

    # ── Pcapng file helpers ────────────────────────────────────

    def _count_pcap_packets(self):
        """Count packets in pcapng file by scanning block headers (fast)."""
        import struct
        count = 0
        try:
            with open(self.pcap_file, 'rb') as f:
                data = f.read()
            pos = 0
            while pos + 8 <= len(data):
                block_type = struct.unpack('<I', data[pos:pos+4])[0]
                block_len = struct.unpack('<I', data[pos+4:pos+8])[0]
                if block_len < 12 or block_len > 268435456:
                    break
                if pos + block_len > len(data):
                    break
                if block_type == 0x00000006:  # Enhanced Packet Block
                    count += 1
                pos += block_len
        except Exception:
            pass
        return count

    # ── Pcapng file monitor ────────────────────────────────────

    def _monitor_pcap_count(self):
        """Monitor pcapng file for accurate packet count (fast, incremental).
        
        Reads only NEW data since last check and counts Enhanced Packet Blocks
        (type 0x00000006) by scanning 4-byte block type headers. Runs in ~1ms
        even on multi-GB files since it only reads new bytes each iteration.
        """
        import struct
        offset = 0  # Bytes already scanned
        count = 0   # Packets found so far
        
        while not self.stop_sniffing.is_set():
            try:
                if self.pcap_file and os.path.exists(self.pcap_file):
                    file_size = os.path.getsize(self.pcap_file)
                    self.pcap_total_bytes = file_size
                    
                    if file_size > offset:
                        with open(self.pcap_file, 'rb') as f:
                            f.seek(offset)
                            new_data = f.read(file_size - offset)
                        
                        # Scan for pcapng block headers in new data
                        # Each block starts with: Block Type (4 bytes) + Block Total Length (4 bytes)
                        # Enhanced Packet Block type = 0x00000006
                        pos = 0
                        while pos + 8 <= len(new_data):
                            block_type = struct.unpack('<I', new_data[pos:pos+4])[0]
                            block_len = struct.unpack('<I', new_data[pos+4:pos+8])[0]
                            
                            if block_len < 12 or block_len > 268435456:  # Sanity check (256MB max block)
                                break  # Corrupt or incomplete block
                            
                            if pos + block_len > len(new_data):
                                break  # Incomplete block, wait for more data
                            
                            if block_type == 0x00000006:  # Enhanced Packet Block
                                count += 1
                            
                            pos += block_len
                        
                        offset += pos  # Only advance past complete blocks
                    
                    self.pcap_packets_captured = count
            except Exception:
                pass
            # Poll every 1 second
            self.stop_sniffing.wait(1.0)

    # ── Post-capture reprocessing ─────────────────────────────────

    def reprocess(self, on_progress=None):
        """Reprocess the complete pcapng file with tshark -r for accurate stats.
        
        Runs after capture stops. Rebuilds all stats, CSV, and DB entries
        from the complete pcapng file that dumpcap wrote (zero-drop).
        
        Args:
            on_progress: callback(packets_done, total_packets) for progress display
        """
        # Signal any still-running _process_packets() to stop immediately.
        # This prevents the race condition where the live thread keeps
        # incrementing packets_captured while we're resetting and recounting.
        self._reprocessing = True

        # Drain any remaining items in the queue so _process_packets()
        # can exit its loop quickly (it checks _reprocessing AND empty queue).
        while not self._packet_queue.empty():
            try:
                self._packet_queue.get_nowait()
            except queue.Empty:
                break

        # Put a sentinel to unblock _process_packets() if it's waiting on get()
        try:
            self._packet_queue.put_nowait(None)
        except queue.Full:
            pass

        # Give the capture thread a moment to notice and exit
        import time
        time.sleep(0.3)

        if not self.pcap_file or not os.path.exists(self.pcap_file):
            return

        # Get total packet count for progress (use monitor's count or fast scan)
        total = self.pcap_packets_captured or 0
        if total == 0:
            total = self._count_pcap_packets()

        # Reset stats for clean recount
        self.packets_captured = 0
        self.total_bytes = 0
        self.transport_counts = {}
        self.application_counts = {}
        self.direction_counts = {'INCOMING': 0, 'OUTGOING': 0}
        self._tls_flow_versions = {}  # Rebuild from pcap handshakes

        # Clear DB and tracker for clean rebuild from pcapng
        self._tracker.reset()
        self._db.clear_session_connections(self.session_id)

        # Reset CSV if active
        if self._csv_fh:
            try:
                self._csv_fh.close()
            except Exception:
                pass
        if self.csv_file:
            self._init_csv(self.csv_file)

        # Build tshark -r command
        # NOTE: Do NOT enable heuristic RTP/RTCP — they cause tshark to
        # output duplicate lines for the same frame (up to 72x per packet).
        # TCP desegmentation is ON (default) so tshark reassembles TCP
        # segments into complete TLS/HTTP records — matching Wireshark GUI.
        # Frame dedup (seen_frames set below) prevents any count inflation.
        tshark_cmd = [
            'tshark', '-r', self.pcap_file,
            '-l', '-n',
            '-T', 'fields',
            '-E', f'separator={FIELD_SEP}',
            '-E', 'quote=n',
            '-E', 'occurrence=f',
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(['-e', field])

        self._reprocessing = True
        seen_frames = set()  # Dedup safety net
        try:
            proc = subprocess.Popen(
                tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            batch = []
            BATCH_SIZE = 500  # Larger batches for reprocessing (no live display pressure)

            for raw_line in proc.stdout:
                try:
                    line = raw_line.decode('utf-8', errors='replace')
                except Exception:
                    continue

                data = self._parse_line(line)
                if data is None:
                    continue

                # Deduplicate by frame number
                frame_id = data.get('packet_id', 0)
                if frame_id in seen_frames:
                    continue
                seen_frames.add(frame_id)

                # Update stats
                self.packets_captured += 1
                self.total_bytes += data['packet_length']

                transport = data['transport_protocol']
                self.transport_counts[transport] = self.transport_counts.get(transport, 0) + 1

                application = data['application_protocol']
                self.application_counts[application] = self.application_counts.get(application, 0) + 1

                direction = data['direction']
                if direction in self.direction_counts:
                    self.direction_counts[direction] += 1

                # CSV logging
                if self._csv_writer:
                    self._log_csv(data)

                # Update connection tracker
                self._tracker.update(data)

                # Update protocol_stats in DB periodically
                if self.packets_captured % BATCH_SIZE == 0:
                    self._flush_protocol_stats()
                    # Progress callback
                    if on_progress and total > 0:
                        on_progress(self.packets_captured, total)

            # Final flush: write all connections to DB
            self._flush_tracker()

            proc.wait(timeout=10)

            if on_progress and total > 0:
                on_progress(self.packets_captured, self.packets_captured)

        except Exception as e:
            pass  # Don't crash on reprocessing errors
        finally:
            self._reprocessing = False

    # ── Thread 1: Fast reader — drain tshark into queue ──────────

    def _read_tshark(self):
        """Read tshark binary output, decode to text, and queue lines."""
        try:
            for raw_line in self._tshark.stdout:
                if self.stop_sniffing.is_set():
                    break
                try:
                    line = raw_line.decode('utf-8', errors='replace')
                except Exception:
                    continue
                self._packet_queue.put(line)
        except Exception:
            pass
        finally:
            self._packet_queue.put(None)  # Sentinel

    # ── Thread 3: Worker — parse + batch DB + callback ───────────

    def _process_packets(self):
        """Process packets from queue: parse, update stats, track connections."""
        FLUSH_INTERVAL = 2.0  # Flush tracker to DB every 2s
        last_flush = time.time()

        while True:
            # Stop immediately if reprocessing has been requested — this
            # prevents the race where we keep incrementing packets_captured
            # while reprocess() is also counting from the pcapng file.
            if self._reprocessing:
                break

            try:
                line = self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                # Periodically flush tracker to DB
                now = time.time()
                if (now - last_flush) >= FLUSH_INTERVAL:
                    self._flush_tracker()
                    last_flush = now
                if self.stop_sniffing.is_set() and self._packet_queue.empty():
                    break
                continue

            if line is None:  # Sentinel from reader thread
                break

            data = self._parse_line(line)
            if data is None:
                continue

            # Deduplicate by frame number (safety net — TCP reassembly
            # can occasionally produce duplicate output for the same frame)
            frame_id = data.get('packet_id', 0)
            if frame_id in self._live_seen_frames:
                continue
            self._live_seen_frames.add(frame_id)

            # Update running stats
            self.packets_captured += 1
            self.total_bytes += data['packet_length']

            transport = data['transport_protocol']
            self.transport_counts[transport] = self.transport_counts.get(transport, 0) + 1

            application = data['application_protocol']
            self.application_counts[application] = self.application_counts.get(application, 0) + 1

            direction = data['direction']
            if direction in self.direction_counts:
                self.direction_counts[direction] += 1

            # Live display callback
            if self.on_packet:
                self.on_packet(data)

            # CSV logging
            if self._csv_writer:
                self._log_csv(data)

            # Update connection tracker (in-memory, fast)
            self._tracker.update(data)

            # Periodically flush to DB
            now = time.time()
            if (now - last_flush) >= FLUSH_INTERVAL:
                self._flush_tracker()
                last_flush = now

        # Final flush
        self._flush_tracker()

    # ── Tuning helpers: severity remap + do-not-suppress ─────────

    def _remap_behavioral_severity(self, tag_name: str, original_severity: str) -> str:
        """Apply severity remap from severity_remap.yaml for behavioral alerts.

        Returns the remapped severity string (e.g. 'SUPPRESS', 'LOW', etc.).
        If no remap is configured, returns original severity unchanged.
        """
        behavioral = self._severity_remap.get('behavioral', {})
        remap = behavioral.get(tag_name, {})
        if not remap:
            return original_severity

        remapped = remap.get('severity', original_severity)
        # Check if whitelisted destination should get a different severity
        wl_severity = remap.get('severity_for_whitelisted')
        if wl_severity:
            # This is handled in behavior_engine already, but if somehow
            # a whitelisted alert slips through, apply the override here
            return remapped
        return remapped

    def _remap_suricata_severity(self, alert: dict) -> str:
        """Apply severity remap from severity_remap.yaml for Suricata alerts.

        Checks the alert signature against Suricata category mappings.
        Returns remapped severity or original if no match.
        """
        suricata_remap = self._severity_remap.get('suricata', {})
        signature = alert.get('signature', '')
        original_sev = alert.get('severity', 'LOW')

        for category_key, remap in suricata_remap.items():
            # Match by checking if the signature contains keywords
            # e.g. FLOWSENTRIX_BRUTE_FORCE matches 'BRUTE-FORCE' or 'BRUTE_FORCE'
            check_key = category_key.replace('_', ' ').replace('-', ' ').upper()
            sig_upper = signature.upper().replace('-', ' ').replace('_', ' ')
            if check_key in sig_upper:
                return remap.get('severity', original_sev)

        return original_sev

    def _is_protected_alert(self, alert: dict) -> bool:
        """Check if an alert matches the do_not_suppress.yaml protection rules.

        Protected alerts must NEVER be suppressed or severity-demoted,
        regardless of any other tuning configuration.

        Returns True if this alert is protected.
        """
        if not self._do_not_suppress:
            return False

        signature = alert.get('signature', '')
        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')
        dst_port = alert.get('dst_port')

        # Check confirmed alerts (exact signature pattern match)
        for entry in self._do_not_suppress.get('confirmed_alerts', []):
            pattern = entry.get('signature_pattern', '')
            if pattern and pattern in signature:
                return True

        # Check protected categories (keyword match in signature)
        for entry in self._do_not_suppress.get('protected_categories', []):
            match_sig = entry.get('match_signature', '')
            if match_sig and match_sig.upper() in signature.upper():
                return True

        # Check protected IP pairs
        for pair in self._do_not_suppress.get('protected_ip_pairs', []):
            if (src_ip == pair.get('source', '') and
                dst_ip == pair.get('destination', '') and
                (pair.get('port') is None or dst_port == pair.get('port'))):
                return True

        # Check protected Suricata SIDs
        sig_id = alert.get('signature_id', 0)
        if sig_id:
            for entry in self._do_not_suppress.get('protected_sids', []):
                if sig_id == entry.get('sid'):
                    return True

        return False

    # ── Flush tracker ────────────────────────────────────────────

    def _flush_tracker(self):
        """Flush connection tracker flows to the database with behavioral tags.

        Applies severity remapping from severity_remap.yaml and enforces
        do_not_suppress.yaml protection rules before surfacing alerts.
        """
        flows = self._tracker.get_flows()
        if flows:
            # Run behavioral analysis and attach tags to flows
            # Pass IP→domain mapping so beaconing detector can group by domain
            tags_map = self._behavior_engine.analyze(flows, ip_to_domain=self._ip_to_domain)
            for i, flow in enumerate(flows):
                if i in tags_map:
                    tag_list = tags_map[i]
                    flow['tags'] = ','.join(t[0] for t in tag_list)
                    # Use highest severity
                    sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                    flow['severity'] = max(
                        (t[1] for t in tag_list),
                        key=lambda s: sev_order.get(s, 0)
                    )

                    # Surface behavioral tags as alerts (so they appear in `show alerts`)
                    for tag_name, severity, reason in tag_list:
                        dst = flow.get('dst_ip', '')
                        # Use domain name if available
                        dst_display = self._ip_to_domain.get(dst, dst)
                        alert_key = (dst_display, tag_name)

                        if alert_key not in self._alerted_behaviors:
                            self._alerted_behaviors.add(alert_key)

                            # Map tag names to user-friendly alert signatures
                            tag_signatures = {
                                'beaconing': f'FLOWSENTRIX BEHAVIOR Beaconing Detected — {reason}',
                                'data_exfil': f'FLOWSENTRIX BEHAVIOR Data Exfiltration — {reason}',
                                'new_dest': f'FLOWSENTRIX BEHAVIOR New Destination — {reason}',
                                'traffic_anomaly': f'FLOWSENTRIX BEHAVIOR Traffic Anomaly — {reason}',
                            }
                            signature = tag_signatures.get(tag_name, f'FLOWSENTRIX BEHAVIOR {tag_name} — {reason}')

                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'severity': severity.upper(),
                                'severity_num': {'low': 3, 'medium': 2, 'high': 1, 'critical': 1}.get(severity, 3),
                                'signature': signature,
                                'signature_id': 0,
                                'category': f'Behavioral: {tag_name}',
                                'src_ip': flow.get('src_ip', ''),
                                'dst_ip': dst,
                                'src_port': flow.get('src_port'),
                                'dst_port': flow.get('dst_port'),
                                'proto': flow.get('protocol', ''),
                                'action': 'allowed',
                            }

                            # ── Apply severity remap (unless protected) ──
                            if self._is_protected_alert(alert):
                                # Protected alert — keep original severity, never suppress
                                pass
                            else:
                                remapped = self._remap_behavioral_severity(tag_name, severity)
                                if remapped.upper() == 'SUPPRESS':
                                    # Silently drop this alert — do not show or persist
                                    continue
                                # Apply remapped severity
                                alert['severity'] = remapped.upper()
                                sev_num_map = {'low': 3, 'medium': 2, 'high': 1, 'critical': 1, 'info': 4}
                                alert['severity_num'] = sev_num_map.get(remapped.lower(), 3)

                            # Add to live alerts list and persist to DB
                            self.alerts.append(alert)
                            try:
                                self._db.insert_alert(alert, self.session_id)
                            except Exception:
                                pass
                            # Trigger real-time display (same as Suricata alerts)
                            if self.on_packet:
                                try:
                                    self.on_packet({'_alert': alert})
                                except Exception:
                                    pass

            self._db.flush_connections(flows, self.session_id)
            # Update known destinations for future new_dest / anomaly detection
            self._db.update_known_destinations(flows)

    def _flush_protocol_stats(self):
        """Update protocol_stats table from current in-memory counts."""
        try:
            with self._db._lock:
                for proto, count in self.application_counts.items():
                    if not proto:
                        continue
                    self._db.cursor.execute("""
                        INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                        VALUES (?, ?, 0, datetime('now'))
                        ON CONFLICT(protocol) DO UPDATE SET
                            packet_count = ?,
                            last_seen = datetime('now')
                    """, (proto, count, count))
                self._db.conn.commit()
        except Exception:
            pass  # Don't crash capture on DB errors

    # ── Main entry point ─────────────────────────────────────────

    def start(self, count=0):
        """
        Start true zero-drop packet capture.

        Architecture:
          Process 1: dumpcap -w file.pcapng  (pure C, zero-drop, no Python)
          Process 2: tshark -i interface     (independent capture for live dissection)
          Thread 1:  read tshark stdout → queue
          Thread 2:  queue → parse → DB + callbacks  (this thread)
        """
        # Ensure data directory exists and is writable by dumpcap
        # dumpcap is setuid wireshark group — it drops root privileges,
        # so the directory must be world-writable for direct file writes
        os.makedirs('data', exist_ok=True)
        os.chmod('data', 0o777)

        # Pcap file path (timestamped, can be opened in Wireshark)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = f"data/capture_{ts}.pcapng"

        # Pre-create the file with open permissions so dumpcap can write it
        with open(self.pcap_file, 'wb') as f:
            pass
        os.chmod(self.pcap_file, 0o666)

        iface = self.interface or 'any'

        # Process 1: dumpcap writes DIRECTLY to pcapng file (pure C, zero-drop)
        # No Python in the data path — kernel → dumpcap → file
        dumpcap_cmd = [
            'dumpcap',
            '-i', iface,
            '-w', self.pcap_file,     # Write directly to file (NOT stdout)
            '-q',                      # Quiet
            '-B', '128',               # 128 MB kernel ring buffer
        ]
        if count > 0:
            dumpcap_cmd.extend(['-c', str(count)])

        # Process 2: tshark captures INDEPENDENTLY for live dissection
        # Reads from the same interface — both get copies via PF_PACKET
        # TCP desegmentation is ON (default) for Wireshark-matching TLS labels.
        # Frame dedup in _process_packets prevents any count inflation.
        tshark_cmd = [
            'tshark', '-i', iface,     # Capture independently (NOT from stdin)
            '-l',                       # Line-buffered output
            '-n',                       # No DNS resolution
            '-T', 'fields',
            '-E', f'separator={FIELD_SEP}',
            '-E', 'quote=n',
            '-E', 'occurrence=f',
            # NOTE: Do NOT enable heuristic RTP/RTCP — causes duplicate output lines
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(['-e', field])

        # Start database session
        self.session_id = self._db.start_session(iface, self.pcap_file)

        try:
            # Launch dumpcap — writes to file in pure C (zero-drop guaranteed)
            self._dumpcap = subprocess.Popen(
                dumpcap_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Launch tshark — independent capture for live display
            self._tshark = subprocess.Popen(
                tshark_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            # Thread 1: Fast reader — drain tshark output into queue
            reader_thread = threading.Thread(
                target=self._read_tshark,
                name="FlowSentrix-TsharkReader",
                daemon=True
            )
            reader_thread.start()

            # Thread 2: Monitor pcapng file for accurate packet count
            monitor_thread = threading.Thread(
                target=self._monitor_pcap_count,
                name="FlowSentrix-PcapMonitor",
                daemon=True
            )
            monitor_thread.start()

            # Process 3: Suricata IDS — independent capture for threat detection
            if SuricataEngine.is_available():
                self._suricata = SuricataEngine(
                    interface=iface,
                    log_dir='data/suricata'
                )
                if self._suricata.start():
                    # Thread 3: Alert reader — tail eve.json for real-time alerts
                    alert_thread = threading.Thread(
                        target=self._read_suricata_alerts,
                        name="FlowSentrix-AlertReader",
                        daemon=True
                    )
                    alert_thread.start()

            # Thread 4 (this thread): Process queue → batch DB + callbacks
            self._process_packets()

        except FileNotFoundError:
            raise FileNotFoundError(
                "dumpcap/tshark not found. Install: sudo apt install tshark"
            )
        except PermissionError:
            raise PermissionError(
                "Root privileges required. Run with: sudo python3 flowsentrix.py"
            )
        finally:
            self._cleanup()

    def _read_suricata_alerts(self):
        """Read Suricata alerts from eve.json in real-time.

        Applies severity remapping from severity_remap.yaml and enforces
        do_not_suppress.yaml protection before displaying/persisting.
        """
        if not self._suricata:
            return
        try:
            for alert in self._suricata.tail_alerts():
                # ── Apply severity remap for Suricata alerts ──
                if self._is_protected_alert(alert):
                    # Protected alert — keep original severity, never suppress
                    pass
                else:
                    remapped = self._remap_suricata_severity(alert)
                    if remapped.upper() == 'SUPPRESS':
                        continue  # Silently drop this alert
                    alert['severity'] = remapped
                    sev_num_map = {'LOW': 3, 'MEDIUM': 2, 'HIGH': 1, 'CRITICAL': 1}
                    alert['severity_num'] = sev_num_map.get(remapped.upper(), 3)

                self.alerts.append(alert)
                # Store in DB
                try:
                    self._db.insert_alert(alert, self.session_id)
                except Exception:
                    pass
                # Trigger on_packet callback with alert (for live display)
                if self.on_packet:
                    try:
                        self.on_packet({'_alert': alert})
                    except Exception:
                        pass
        except Exception:
            pass

    def _cleanup(self):
        """Clean up subprocesses and database session."""
        # Stop Suricata IDS
        if self._suricata:
            try:
                self._suricata.stop()
            except Exception:
                pass
            self._suricata = None

        # Gracefully stop dumpcap — SIGINT lets it flush and close the
        # pcapng file properly (SIGTERM can truncate mid-write → corrupt file)
        if self._dumpcap:
            import signal
            try:
                self._dumpcap.send_signal(signal.SIGINT)
                self._dumpcap.wait(timeout=5)
            except Exception:
                try:
                    self._dumpcap.terminate()
                    self._dumpcap.wait(timeout=3)
                except Exception:
                    try:
                        self._dumpcap.kill()
                    except Exception:
                        pass
            self._dumpcap = None

        # Terminate tshark
        if self._tshark:
            try:
                self._tshark.terminate()
                self._tshark.wait(timeout=3)
            except Exception:
                try:
                    self._tshark.kill()
                except Exception:
                    pass
            self._tshark = None

        # End database session
        if self.session_id and self._db:
            try:
                self._db.end_session(self.session_id, self.packets_captured, self.total_bytes)
            except Exception:
                pass

        # Close CSV
        if self._csv_fh:
            try:
                self._csv_fh.close()
            except Exception:
                pass

    @staticmethod
    def is_available():
        """Check if dumpcap and tshark are both installed."""
        try:
            r1 = subprocess.run(['dumpcap', '--version'], capture_output=True, timeout=5)
            r2 = subprocess.run(['tshark', '--version'], capture_output=True, timeout=5)
            return r1.returncode == 0 and r2.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
