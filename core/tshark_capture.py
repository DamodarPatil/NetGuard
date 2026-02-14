"""
TsharkCapture — dumpcap + tshark zero-drop capture backend for NetGuard.

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

from core.database import NetGuardDatabase


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

    def __init__(self, interface=None, db_path="data/netguard.db", csv_file=None, on_packet=None):
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
        self._db = NetGuardDatabase(db_path)
        self.session_id = None
        self.local_ips = self._get_local_ips()

        # Thread-safe queue for producer-consumer pattern
        self._packet_queue = queue.Queue(maxsize=0)  # Unbounded

        # Pcap file path (saved for user — can open in Wireshark)
        self.pcap_file = None

        # Reprocessing flag
        self._reprocessing = False

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

        # Wireshark-matching: "Continuation Data" packets are TCP segments
        # In pipe mode tshark labels them SSL/TLSvX but Wireshark GUI shows
        # them as TCP "[TCP segment of a reassembled PDU]"
        info_clean = ws_info.strip() if ws_info else ''
        if info_clean == 'Continuation Data' and transport == 'TCP':
            application = 'TCP'
            info_clean = '[TCP segment of a reassembled PDU]'

        # Normalize arrow: tshark -i - uses → but Wireshark GUI uses  >  
        info_clean = info_clean.replace('\u2192', '→')

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

        # Clear DB data from the live capture (will be rebuilt from pcapng)
        try:
            with self._db._lock:
                self._db.cursor.execute("DELETE FROM packets")
                self._db.cursor.execute("DELETE FROM protocol_stats")
                self._db.conn.commit()
        except Exception:
            pass

        # Reset CSV if active
        if self._csv_fh:
            try:
                self._csv_fh.close()
            except Exception:
                pass
        if self.csv_file:
            self._init_csv(self.csv_file)

        # Build tshark -r command
        tshark_cmd = [
            'tshark', '-r', self.pcap_file,
            '-l', '-n',
            '-T', 'fields',
            '-E', f'separator={FIELD_SEP}',
            '-E', 'quote=n',
            '-E', 'occurrence=f',
            '-o', 'rtp.heuristic_rtp:TRUE',
            '-o', 'rtcp.heuristic_rtcp:TRUE',
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(['-e', field])

        self._reprocessing = True
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

                # Batch for DB
                batch.append(data)
                if len(batch) >= BATCH_SIZE:
                    self._batch_insert(batch)
                    batch = []
                    # Progress callback
                    if on_progress and total > 0:
                        on_progress(self.packets_captured, total)

            # Final flush
            if batch:
                self._batch_insert(batch)

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
        """Process packets from queue: parse, update stats, batch DB insert, callback."""
        batch = []
        BATCH_SIZE = 100
        FLUSH_INTERVAL = 0.5  # seconds
        last_flush = time.time()

        while True:
            try:
                line = self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                # Flush partial batch on timeout
                if batch:
                    self._batch_insert(batch)
                    batch = []
                    last_flush = time.time()
                if self.stop_sniffing.is_set() and self._packet_queue.empty():
                    break
                continue

            if line is None:  # Sentinel from reader thread
                break

            data = self._parse_line(line)
            if data is None:
                continue

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

            # Batch for DB
            batch.append(data)
            now = time.time()
            if len(batch) >= BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL:
                self._batch_insert(batch)
                batch = []
                last_flush = now

        # Final flush
        if batch:
            self._batch_insert(batch)

    def _batch_insert(self, batch):
        """Insert a batch of packets into the database in one transaction."""
        try:
            with self._db._lock:
                for data in batch:
                    self._db.cursor.execute("""
                        INSERT INTO packets (
                            absolute_timestamp, relative_time,
                            src_ip, dst_ip, src_port, dst_port,
                            transport_protocol, application_protocol, tcp_flags,
                            direction, packet_length, info
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        data['absolute_timestamp'], data['relative_time'],
                        data['src'], data['dst'],
                        data.get('src_port'), data.get('dst_port'),
                        data['transport_protocol'], data['application_protocol'],
                        data.get('tcp_flags'), data['direction'],
                        data['packet_length'], data['info']
                    ))

                    # Update protocol_stats
                    proto_for_stats = data['application_protocol'] or data['transport_protocol']
                    self._db.cursor.execute("""
                        INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                        VALUES (?, 1, ?, ?)
                        ON CONFLICT(protocol) DO UPDATE SET
                            packet_count = packet_count + 1,
                            total_bytes = total_bytes + ?,
                            last_seen = ?
                    """, (
                        proto_for_stats, data['packet_length'], data['absolute_timestamp'],
                        data['packet_length'], data['absolute_timestamp']
                    ))

                self._db.conn.commit()  # Single commit for entire batch
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
        tshark_cmd = [
            'tshark', '-i', iface,     # Capture independently (NOT from stdin)
            '-l',                       # Line-buffered output
            '-n',                       # No DNS resolution
            '-T', 'fields',
            '-E', f'separator={FIELD_SEP}',
            '-E', 'quote=n',
            '-E', 'occurrence=f',
            '-o', 'rtp.heuristic_rtp:TRUE',
            '-o', 'rtcp.heuristic_rtcp:TRUE',
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(['-e', field])

        # Start database session
        self.session_id = self._db.start_session(iface)

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
                name="NetGuard-TsharkReader",
                daemon=True
            )
            reader_thread.start()

            # Thread 2: Monitor pcapng file for accurate packet count
            monitor_thread = threading.Thread(
                target=self._monitor_pcap_count,
                name="NetGuard-PcapMonitor",
                daemon=True
            )
            monitor_thread.start()

            # Thread 3 (this thread): Process queue → batch DB + callbacks
            self._process_packets()

        except FileNotFoundError:
            raise FileNotFoundError(
                "dumpcap/tshark not found. Install: sudo apt install tshark"
            )
        except PermissionError:
            raise PermissionError(
                "Root privileges required. Run with: sudo python3 netguard.py"
            )
        finally:
            self._cleanup()

    def _cleanup(self):
        """Clean up subprocesses and database session."""
        # Terminate dumpcap
        if self._dumpcap:
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
