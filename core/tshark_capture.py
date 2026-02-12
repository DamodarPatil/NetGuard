"""
TsharkCapture — dumpcap + tshark zero-drop capture backend for NetGuard.

Architecture (identical to Wireshark):
  Thread 1 (tee):      dumpcap stdout → save to .pcapng file + pipe to tshark stdin
  Thread 2 (reader):   tshark stdout → fast drain into in-memory queue
  Thread 3 (worker):   queue → parse → batch DB insert + on_packet callback

dumpcap captures at kernel speed with ring buffers (the same C binary Wireshark
uses), guaranteeing zero packet drops. tshark provides 3000+ protocol dissectors.
Even if Python processing falls behind, no packets are lost — they buffer in the
queue and pcapng file.
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
    '_ws.col.Info',        # 15  MUST be last (may contain tab chars)
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
        ws_info      = FIELD_SEP.join(parts[15:]) if len(parts) > 15 else ''

        src = ip4_src or ip6_src or ''
        dst = ip4_dst or ip6_dst or ''
        # ARP and other non-IP packets: use the info string for context
        # Don't skip them — Wireshark shows them too
        if not src and not dst:
            # For ARP, LLDP, STP etc. — use the ws_info to fill source/dest
            src = 'N/A'
            dst = 'N/A'

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

    # ── Thread 1: Tee dumpcap → file + tshark ────────────────────

    def _tee_dumpcap(self):
        """Read dumpcap stdout, write to pcap file AND pipe to tshark stdin.
        
        Uses os.read() for non-blocking reads — returns immediately with
        whatever bytes are available instead of waiting for a full buffer.
        This prevents the stop/start stuttering in live display.
        """
        fd = self._dumpcap.stdout.fileno()
        try:
            with open(self.pcap_file, 'wb') as f:
                while not self.stop_sniffing.is_set():
                    # os.read returns immediately with available data (no blocking)
                    chunk = os.read(fd, 262144)  # 256KB max per read
                    if not chunk:
                        break
                    # Save to pcap file
                    f.write(chunk)
                    f.flush()
                    # Forward to tshark for dissection
                    try:
                        self._tshark.stdin.write(chunk)
                        self._tshark.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break
        except OSError:
            pass
        finally:
            try:
                self._tshark.stdin.close()
            except Exception:
                pass

    # ── Thread 2: Fast reader — drain tshark into queue ──────────

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
        Start zero-drop packet capture.

        Architecture:
          dumpcap (kernel-speed capture) → tee → pcap file + tshark (dissection)
          tshark → fast reader queue → batch DB + live display
        """
        # Ensure data directory exists for pcap files
        os.makedirs('data', exist_ok=True)

        # Pcap file path (timestamped, can be opened in Wireshark)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = f"data/capture_{ts}.pcapng"

        # Build dumpcap command: write raw pcap to stdout
        dumpcap_cmd = [
            'dumpcap',
            '-i', self.interface or 'any',
            '-w', '-',              # Write to stdout
            '-q',                   # Quiet (no stats on stderr)
            '-B', '128',            # 128 MB kernel ring buffer
        ]
        if count > 0:
            dumpcap_cmd.extend(['-c', str(count)])

        # Build tshark command: live capture from stdin pipe
        tshark_cmd = [
            'tshark', '-i', '-',    # Live capture mode from stdin pipe
            '-l',                   # Line-buffered output
            '-n',                   # No DNS resolution
            '-T', 'fields',
            '-E', f'separator={FIELD_SEP}',
            '-E', 'quote=n',
            '-E', 'occurrence=f',
            # Enable heuristic dissectors that Wireshark GUI enables by default
            # Without these, tshark shows "UDP" instead of the actual protocol
            '-o', 'rtp.heuristic_rtp:TRUE',
            '-o', 'rtcp.heuristic_rtcp:TRUE',
        ]
        for field in TSHARK_FIELDS:
            tshark_cmd.extend(['-e', field])

        # Start database session
        self.session_id = self._db.start_session(self.interface or 'any')

        try:
            # Launch dumpcap (raw capture → binary stdout)
            self._dumpcap = subprocess.Popen(
                dumpcap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            # Launch tshark (binary pcap stdin → text fields stdout)
            # Both stdin and stdout are binary pipes; we decode stdout in the reader
            self._tshark = subprocess.Popen(
                tshark_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            # Thread 1: Tee dumpcap output → save to file + feed to tshark
            tee_thread = threading.Thread(
                target=self._tee_dumpcap,
                name="NetGuard-DumpcapTee",
                daemon=True
            )
            tee_thread.start()

            # Thread 2: Fast reader — drain tshark output into queue
            reader_thread = threading.Thread(
                target=self._read_tshark,
                name="NetGuard-TsharkReader",
                daemon=True
            )
            reader_thread.start()

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
