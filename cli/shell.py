"""
NetGuard Interactive Shell
Metasploit-style CLI with background capture, tab completion, and Rich display.
"""
import cmd
import sys
import os
import threading
import signal
from datetime import datetime

from rich.console import Console

from cli.banner import print_banner
from cli.display import (
    format_packet_line, print_packet_header, print_stats_table,
    print_recent_table, print_top_talkers, print_search_results, console
)

# Try readline for tab completion and history
try:
    import readline
    readline.parse_and_bind("tab: complete")
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False


class NetGuardShell(cmd.Cmd):
    """Interactive NetGuard shell with background capture support."""
    
    prompt = "\033[1;36mnetguard\033[0m \033[1;32m▶\033[0m "
    doc_header = "Available Commands (type help <command> for details)"
    
    def __init__(self):
        super().__init__()
        
        # Config
        self.interface = self._detect_interface()
        self.csv_file = None
        self.db_path = "data/netguard.db"
        self.capture_count = 0  # 0 = infinite
        
        # Capture state
        self.sniffer = None
        self.capture_thread = None
        self.capturing = False
        self.capture_start = None
        self._stopping = False  # Instant Ctrl+C kill switch
        
        # Display state
        self.live_display = True  # Show packets in real-time
        self.packet_buffer = []  # Recent packets for display
        self.max_buffer = 100
        self._display_batch = []  # Batched lines for efficient terminal output
        self._batch_lock = threading.Lock()
        
        # Initialize database for stats
        self._db = None
        self._init_db()
        
        # Show banner
        db_count = self._get_db_packet_count()
        sessions = self._get_session_count()
        print_banner(db_packets=db_count, sessions=sessions, interface=self.interface)
    
    def _detect_interface(self):
        """Auto-detect the primary network interface."""
        interfaces = self._get_interfaces()
        # Prefer wireless or ethernet, skip lo
        for iface in interfaces:
            if iface.startswith(('wl', 'eth', 'en')):
                return iface
        # Fallback to first non-lo
        for iface in interfaces:
            if iface != 'lo':
                return iface
        return None
    
    def _get_interfaces(self):
        """Get list of network interfaces using Linux /sys/class/net."""
        interfaces = []
        try:
            # Linux-native: read /sys/class/net (no scapy needed)
            net_dir = '/sys/class/net'
            if os.path.isdir(net_dir):
                interfaces = [d for d in os.listdir(net_dir) if os.path.isdir(os.path.join(net_dir, d))]
        except Exception:
            pass
        
        if not interfaces:
            # Fallback to scapy
            try:
                from scapy.all import get_if_list
                interfaces = get_if_list()
            except Exception:
                pass
        
        return interfaces
    
    def _init_db(self):
        """Initialize database connection for queries."""
        try:
            from core.database import NetGuardDatabase
            self._db = NetGuardDatabase(self.db_path)
        except Exception:
            self._db = None
    
    def _get_db_packet_count(self):
        """Get packet count from database."""
        try:
            if self._db:
                return self._db.get_packet_count()
        except Exception:
            pass
        return 0
    
    def _get_session_count(self):
        """Get session count from database."""
        try:
            if self._db:
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                cursor = conn.execute("SELECT COUNT(*) FROM sessions")
                count = cursor.fetchone()[0]
                conn.close()
                return count
        except Exception:
            pass
        return 0
    
    # ── Packet callback for background capture ──────────────────
    
    def _on_packet(self, data):
        """Called for each captured packet. Runs in capture thread.
        
        PERFORMANCE CRITICAL: Only append raw data here — no formatting.
        format_packet_line() takes ~50μs per packet which blocks the
        tshark pipe at high rates. Formatting happens in _flush_display()
        on the main thread instead.
        """
        # Instant stop: don't queue after Ctrl+C
        if self._stopping:
            return
        
        self.packet_buffer.append(data)
        if len(self.packet_buffer) > self.max_buffer:
            self.packet_buffer.pop(0)
        
        if self.live_display:
            with self._batch_lock:
                self._display_batch.append(data)
    
    def _flush_display(self):
        """Format and flush batched packets to terminal in one write."""
        with self._batch_lock:
            batch = self._display_batch[:]
            self._display_batch.clear()
        
        if batch:
            import io, sys
            buf = io.StringIO()
            # force_terminal=True preserves ANSI color codes in buffer
            temp_console = Console(
                file=buf, emoji=False, highlight=False,
                force_terminal=True, width=console.width
            )
            for data in batch:
                line = format_packet_line(data)
                temp_console.print(line, highlight=False)
            output = buf.getvalue()
            if output:
                sys.stdout.write(output)
                sys.stdout.flush()
    
    # ── CAPTURE COMMANDS ────────────────────────────────────────
    
    def do_capture(self, args):
        """Start packet capture (Ctrl+C to stop).
        
Usage:
  capture start [interface]  - Start capture (press Ctrl+C to stop)
  capture start              - Use default interface"""
        parts = args.strip().split()
        if not parts:
            console.print("  [dim]Usage: capture start [interface][/dim]")
            return
        
        subcmd = parts[0].lower()
        
        if subcmd == 'start':
            # Optional interface override
            if len(parts) > 1:
                self.interface = parts[1]
            self._capture_start()
        else:
            console.print(f"  [red]Unknown: capture {subcmd}[/red]. Use: capture start")
    
    def complete_capture(self, text, line, begidx, endidx):
        options = ['start']
        return [o for o in options if o.startswith(text)]
    
    def _capture_start(self):
        """Start capture, block until Ctrl+C, then show summary."""
        if self.capturing:
            console.print("  [yellow]⚠ Capture already running.[/yellow]")
            return
        
        if not self.interface:
            console.print("  [red]✗ No interface set. Use 'set interface <name>' first.[/red]")
            console.print("  [dim]  Available: use 'show interfaces' to list[/dim]")
            return
        
        console.print(f"  [green]▸[/green] Starting capture on [bold]{self.interface}[/bold]...")
        
        try:
            # Try tshark backend first (Wireshark-level protocol detection)
            from core.tshark_capture import TsharkCapture
            if TsharkCapture.is_available():
                self.sniffer = TsharkCapture(
                    interface=self.interface,
                    db_path=self.db_path,
                    csv_file=self.csv_file,
                    on_packet=self._on_packet
                )
                console.print("  [dim]  Backend: dumpcap + tshark (zero-drop Wireshark engine)[/dim]")
            else:
                # Fallback to Scapy sniffer
                from core.sniffer import PacketSniffer
                self.sniffer = PacketSniffer(
                    interface=self.interface,
                    db_path=self.db_path,
                    csv_file=self.csv_file,
                    on_packet=self._on_packet
                )
                console.print("  [yellow]⚠ tshark not found, using Scapy backend[/yellow]")
            
            self.capturing = True
            self.capture_start = datetime.now()
            self.packet_buffer.clear()
            self._stopping = False
            self._display_batch.clear()
            
            # Start capture in background thread
            self.capture_thread = threading.Thread(
                target=self._run_capture,
                name="NetGuard-CaptureSession",
                daemon=True
            )
            self.capture_thread.start()
            
            console.print(f"  [green]✓[/green] Capture started. Press [bold]Ctrl+C[/bold] to stop.")
            if self.csv_file:
                console.print(f"  [green]✓[/green] CSV logging to: {self.csv_file}")
            console.print()
            
            print_packet_header()
            
            # Block main thread — flush display + live status
            import time, sys
            status_interval = 0.5  # Update status line every 500ms
            last_status = 0
            try:
                while self.capturing and self.capture_thread.is_alive():
                    self._flush_display()
                    now = time.time()
                    if now - last_status >= status_interval and self.sniffer:
                        self._print_status_line()
                        last_status = now
                    time.sleep(0.05)  # 50ms — smooth display, responsive Ctrl+C
            except KeyboardInterrupt:
                # Instant stop: kill display output immediately
                self._stopping = True
                with self._batch_lock:
                    self._display_batch.clear()
                # Reset terminal title
                sys.stdout.write('\033]0;\007')
                sys.stdout.flush()
            
            # Stop capture cleanly
            self._do_capture_stop()
            
        except PermissionError:
            console.print("  [red]✗ Root privileges required! Run with: sudo python3 netguard.py[/red]")
            self.capturing = False
        except Exception as e:
            console.print(f"  [red]✗ Failed to start capture: {e}[/red]")
            self.capturing = False
    
    def _run_capture(self):
        """Run capture in background thread."""
        try:
            self.sniffer.start(count=self.capture_count)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            if self.capturing:
                console.print(f"\n  [red]✗ Capture error: {e}[/red]")
        finally:
            self.capturing = False
    
    def _print_status_line(self):
        """Show live capture stats in the terminal title bar (no clutter)."""
        import sys
        sniffer = self.sniffer
        if not sniffer:
            return
        
        pcap_count = sniffer.pcap_packets_captured
        displayed = sniffer.packets_captured
        
        elapsed = ""
        if self.capture_start:
            delta = datetime.now() - self.capture_start
            secs = int(delta.total_seconds())
            elapsed = f"{secs}s" if secs < 60 else f"{secs//60}m {secs%60}s"
        
        pcap_mb = sniffer.pcap_total_bytes / (1024 * 1024) if sniffer.pcap_total_bytes else 0
        
        if pcap_count > 0:
            title = f"⚡ NetGuard | {pcap_count:,} captured | {displayed:,} displayed | {pcap_mb:.1f} MB | {elapsed}"
        else:
            title = f"⚡ NetGuard | {displayed:,} packets | {pcap_mb:.1f} MB | {elapsed}"
        
        # Set terminal title bar (ANSI escape — works in all modern terminals)
        sys.stdout.write(f"\033]0;{title}\007")
        sys.stdout.flush()
    
    def _do_capture_stop(self):
        """Stop capture and reprocess pcapng for accurate stats."""
        import sys
        console.print()
        console.print("  [yellow]▸[/yellow] Stopping capture...")
        
        if self.sniffer:
            self.sniffer.stop_sniffing.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        duration = ""
        if self.capture_start:
            delta = datetime.now() - self.capture_start
            secs = int(delta.total_seconds())
            duration = f"{secs}s" if secs < 60 else f"{secs//60}m {secs%60}s"
        
        if self.sniffer and self.sniffer.pcap_file:
            pcap_count = self.sniffer.pcap_packets_captured
            console.print(f"  [green]✓[/green] Capture saved: [bold]{self.sniffer.pcap_file}[/bold]")
            
            if pcap_count > 0:
                console.print(f"  [yellow]▸[/yellow] Analyzing complete capture ({pcap_count:,} packets)...")
                
                # Progress callback for reprocessing
                last_pct = [0]
                def on_progress(done, total):
                    if total > 0:
                        pct = int(done * 100 / total)
                        if pct > last_pct[0]:
                            last_pct[0] = pct
                            bar_len = 40
                            filled = int(bar_len * pct / 100)
                            bar = '█' * filled + '░' * (bar_len - filled)
                            sys.stdout.write(f'\r    {bar} {pct}%  ({done:,} / {total:,})  ')
                            sys.stdout.flush()
                
                # Reprocess the complete pcapng file
                self.sniffer.reprocess(on_progress=on_progress)
                
                # Clear progress line
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                sys.stdout.flush()
                
                console.print(f"  [green]✓[/green] [bold]{self.sniffer.packets_captured:,}[/bold] packets analyzed in {duration}")
            else:
                console.print(f"  [green]✓[/green] Capture stopped. [bold]{self.sniffer.packets_captured:,}[/bold] packets in {duration}")
            
            # Show stats from reprocessed data (accurate)
            if self.sniffer.packets_captured > 0:
                print_stats_table(
                    self.sniffer.transport_counts,
                    self.sniffer.application_counts,
                    self.sniffer.direction_counts,
                    self.sniffer.packets_captured,
                    self.sniffer.total_bytes,
                    duration
                )
        else:
            console.print("  [green]✓[/green] Capture stopped.")
        
        self.capturing = False
        self.sniffer = None
        self.capture_thread = None
        
        # Refresh DB connection to see new data
        self._init_db()
    
    # ── SHOW COMMANDS ───────────────────────────────────────────
    
    def do_show(self, args):
        """Show various information.
        
Usage:
  show stats         - Protocol breakdown & session stats
  show recent [N]    - Show last N packets (default: 20)
  show top-talkers [N] - Most active IPs (default: 10)
  show interfaces    - Available network interfaces
  show config        - Current configuration"""
        parts = args.strip().split()
        if not parts:
            console.print("  [dim]Usage: show stats | recent | top-talkers | interfaces | config[/dim]")
            return
        
        subcmd = parts[0].lower()
        
        if subcmd == 'stats':
            self._show_stats()
        elif subcmd == 'recent':
            n = 20
            if len(parts) > 1:
                try:
                    n = int(parts[1])
                    if n <= 0:
                        console.print("  [red]✗ Count must be a positive number.[/red]")
                        return
                except ValueError:
                    console.print(f"  [red]✗ Invalid number: {parts[1]}[/red]")
                    return
            self._show_recent(n)
        elif subcmd in ('top-talkers', 'talkers'):
            n = 10
            if len(parts) > 1:
                try:
                    n = int(parts[1])
                    if n <= 0:
                        console.print("  [red]✗ Count must be a positive number.[/red]")
                        return
                except ValueError:
                    console.print(f"  [red]✗ Invalid number: {parts[1]}[/red]")
                    return
            self._show_top_talkers(n)
        elif subcmd in ('interfaces', 'iface', 'if'):
            self._show_interfaces()
        elif subcmd in ('config', 'settings'):
            self._show_config()
        else:
            console.print(f"  [red]Unknown: show {subcmd}[/red]")
    
    def complete_show(self, text, line, begidx, endidx):
        options = ['stats', 'recent', 'top-talkers', 'interfaces', 'config']
        return [o for o in options if o.startswith(text)]
    
    def _show_stats(self):
        """Show stats from live capture or database."""
        if self.capturing and self.sniffer:
            # Show live stats
            delta = datetime.now() - self.capture_start if self.capture_start else None
            duration = ""
            if delta:
                secs = int(delta.total_seconds())
                duration = f"{secs}s" if secs < 60 else f"{secs//60}m {secs%60}s"
            
            print_stats_table(
                self.sniffer.transport_counts,
                self.sniffer.application_counts,
                self.sniffer.direction_counts,
                self.sniffer.packets_captured,
                self.sniffer.total_bytes,
                duration
            )
        elif self._db:
            # Show from database
            stats = self._db.get_protocol_stats()
            if stats:
                app_counts = {s[0]: s[1] for s in stats}
                total_pkts = sum(s[1] for s in stats)
                total_bytes = sum(s[2] for s in stats)
                print_stats_table({}, app_counts, {}, total_pkts, total_bytes)
            else:
                console.print("  [dim]No data in database.[/dim]")
        else:
            console.print("  [dim]No capture running and no database available.[/dim]")
    
    def _show_recent(self, limit=20):
        """Show recent packets."""
        if self._db:
            packets = self._db.get_recent_packets(limit)
            if packets:
                print_recent_table(packets)
            else:
                console.print("  [dim]No packets in database.[/dim]")
        else:
            console.print("  [dim]Database not available.[/dim]")
    
    def _show_top_talkers(self, limit=10):
        """Show top talkers."""
        if self._db:
            talkers = self._db.get_top_talkers(limit)
            if talkers:
                print_top_talkers(talkers)
            else:
                console.print("  [dim]No data available.[/dim]")
        else:
            console.print("  [dim]Database not available.[/dim]")
    
    def _show_interfaces(self):
        """Show available network interfaces."""
        interfaces = self._get_interfaces()
        if interfaces:
            console.print("  [bold]Available Interfaces:[/bold]")
            for iface in sorted(interfaces):
                marker = " [green]◀ active[/green]" if iface == self.interface else ""
                # Try to get IP address
                ip_info = ""
                try:
                    import socket
                    import fcntl
                    import struct
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', iface.encode()))[20:24])
                    ip_info = f" [dim]({ip})[/dim]"
                    sock.close()
                except Exception:
                    pass
                # Check if interface is up
                state = ""
                try:
                    with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                        st = f.read().strip()
                        if st == 'up':
                            state = " [green]UP[/green]"
                        elif st == 'down':
                            state = " [red]DOWN[/red]"
                except Exception:
                    pass
                console.print(f"    • {iface}{ip_info}{state}{marker}")
        else:
            console.print("  [red]Cannot list interfaces[/red]")
    
    def _show_config(self):
        """Show current configuration."""
        console.print("  [bold]Current Configuration:[/bold]")
        console.print(f"    Interface:   [cyan]{self.interface or 'not set'}[/cyan]")
        console.print(f"    Database:    [cyan]{self.db_path}[/cyan]")
        console.print(f"    CSV File:    [cyan]{self.csv_file or 'disabled'}[/cyan]")
        console.print(f"    Count:       [cyan]{self.capture_count if self.capture_count > 0 else '∞ (unlimited)'}[/cyan]")
        console.print(f"    Live Display:[cyan] {'on' if self.live_display else 'off'}[/cyan]")
        status = "[green]● running[/green]" if self.capturing else "[dim]○ stopped[/dim]"
        console.print(f"    Capture:     {status}")
    
    # ── SEARCH COMMANDS ─────────────────────────────────────────
    
    def do_search(self, args):
        """Search captured packets.
        
Usage:
  search ip <IP>       - Find packets by IP address
  search proto <PROTO> - Find packets by protocol
  search port <PORT>   - Find packets by port number"""
        parts = args.strip().split()
        if len(parts) < 2:
            console.print("  [dim]Usage: search ip <IP> | search proto <PROTO> | search port <PORT>[/dim]")
            return
        
        if not self._db:
            console.print("  [red]Database not available.[/red]")
            return
        
        subcmd = parts[0].lower()
        value = parts[1]
        
        if subcmd == 'ip':
            console.print(f"  [bold]Searching for IP: {value}[/bold]")
            results = self._db.search_by_ip(value)
            print_search_results(results, f"IP={value}")
        elif subcmd in ('proto', 'protocol'):
            console.print(f"  [bold]Searching for protocol: {value}[/bold]")
            results = self._db.search_by_protocol(value)
            print_search_results(results, f"Protocol={value}")
        elif subcmd == 'port':
            try:
                port_num = int(value)
                if port_num < 0 or port_num > 65535:
                    console.print("  [red]✗ Port must be 0-65535.[/red]")
                    return
            except ValueError:
                console.print(f"  [red]✗ Invalid port number: {value}[/red]")
                return
            console.print(f"  [bold]Searching for port: {port_num}[/bold]")
            # Port search via SQL
            try:
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                cursor = conn.execute("""
                    SELECT absolute_timestamp, src_ip, dst_ip,
                           COALESCE(application_protocol, transport_protocol),
                           packet_length, info
                    FROM packets
                    WHERE src_port = ? OR dst_port = ?
                    ORDER BY packet_id DESC LIMIT 200
                """, (port_num, port_num))
                results = cursor.fetchall()
                conn.close()
                print_search_results(results, f"Port={port_num}")
            except Exception as e:
                console.print(f"  [red]Search error: {e}[/red]")
        else:
            console.print(f"  [red]Unknown: search {subcmd}[/red]. Use: ip, proto, port")
    
    def complete_search(self, text, line, begidx, endidx):
        options = ['ip', 'proto', 'port']
        return [o for o in options if o.startswith(text)]
    
    # ── SET COMMANDS ────────────────────────────────────────────
    
    def do_set(self, args):
        """Configure capture settings.
        
Usage:
  set interface <IF>   - Set capture interface
  set csv <FILE>       - Set CSV export file
  set count <N>        - Set packet count (0=unlimited)
  set display on|off   - Toggle live packet display"""
        # Use maxsplit=1 to preserve spaces in file paths (e.g. set csv /path/my file.csv)
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            console.print("  [dim]Usage: set interface|csv|count|display <value>[/dim]")
            return
        
        key = parts[0].lower()
        value = parts[1]
        
        if key in ('interface', 'iface', 'if'):
            # Validate interface exists
            available = self._get_interfaces()
            if value not in available:
                console.print(f"  [red]✗ Unknown interface: {value}[/red]")
                console.print(f"  [dim]  Available: {', '.join(sorted(available))}[/dim]")
                return
            self.interface = value
            console.print(f"  [green]✓[/green] Interface set to: [bold]{value}[/bold]")
        elif key == 'csv':
            self.csv_file = value
            console.print(f"  [green]✓[/green] CSV export set to: [bold]{value}[/bold]")
        elif key == 'count':
            try:
                n = int(value)
                if n < 0:
                    console.print(f"  [red]✗ Count must be >= 0 (0 = unlimited).[/red]")
                    return
                self.capture_count = n
                display = f"{self.capture_count}" if self.capture_count > 0 else "∞ (unlimited)"
                console.print(f"  [green]✓[/green] Packet count set to: [bold]{display}[/bold]")
            except ValueError:
                console.print(f"  [red]✗ Invalid number: {value}[/red]")
        elif key == 'display':
            valid_on = ('on', 'true', 'yes', '1')
            valid_off = ('off', 'false', 'no', '0')
            val = value.lower()
            if val in valid_on:
                self.live_display = True
            elif val in valid_off:
                self.live_display = False
            else:
                console.print(f"  [red]✗ Invalid value: {value}. Use 'on' or 'off'.[/red]")
                return
            state = "on" if self.live_display else "off"
            console.print(f"  [green]✓[/green] Live display: [bold]{state}[/bold]")
        elif key == 'db':
            self.db_path = value
            self._init_db()
            console.print(f"  [green]✓[/green] Database set to: [bold]{value}[/bold]")
        else:
            console.print(f"  [red]Unknown setting: {key}[/red]")
    
    def complete_set(self, text, line, begidx, endidx):
        parts = line.split()
        if len(parts) == 2 and not text:
            # Completing the value after the setting name
            setting = parts[1].lower()
            if setting in ('interface', 'iface', 'if'):
                return self._get_interfaces()
            elif setting == 'display':
                return ['on', 'off']
            return []
        elif len(parts) <= 2:
            options = ['interface', 'csv', 'count', 'display', 'db']
            return [o for o in options if o.startswith(text)]
        elif len(parts) == 3:
            setting = parts[1].lower()
            if setting in ('interface', 'iface', 'if'):
                return [i for i in self._get_interfaces() if i.startswith(text)]
            elif setting == 'display':
                return [o for o in ['on', 'off'] if o.startswith(text)]
        return []
    
    # ── EXPORT COMMANDS ─────────────────────────────────────────
    
    def do_export(self, args):
        """Export captured data.
        
Usage:
  export csv <filename> - Export packets to CSV file"""
        parts = args.strip().split()
        if len(parts) < 2:
            console.print("  [dim]Usage: export csv <filename>[/dim]")
            return
        
        if parts[0].lower() == 'csv':
            filename = parts[1]
            if self._db:
                try:
                    count = self._db.export_to_csv(filename)
                    console.print(f"  [green]✓[/green] Exported [bold]{count:,}[/bold] packets to [bold]{filename}[/bold]")
                except Exception as e:
                    console.print(f"  [red]✗ Export failed: {e}[/red]")
            else:
                console.print("  [red]Database not available.[/red]")
        else:
            console.print(f"  [red]Unknown format: {parts[0]}[/red]. Use: csv")
    
    def complete_export(self, text, line, begidx, endidx):
        return [o for o in ['csv'] if o.startswith(text)]
    
    # ── UTILITY COMMANDS ────────────────────────────────────────
    
    def do_clear(self, args):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def do_exit(self, args):
        """Exit NetGuard."""
        if self.capturing:
            console.print("  [yellow]Stopping capture...[/yellow]")
            self._capture_stop()
        console.print("  [cyan]Goodbye! 👋[/cyan]")
        return True
    
    def do_quit(self, args):
        """Exit NetGuard."""
        return self.do_exit(args)
    
    def do_EOF(self, args):
        """Handle Ctrl+D."""
        console.print()
        return self.do_exit(args)
    
    # ── HELP ────────────────────────────────────────────────────
    
    def do_help(self, args):
        """Show help for commands."""
        if args:
            # Show help for specific command
            super().do_help(args)
            return
        
        console.print()
        console.print("  [bold cyan]━━━ CAPTURE ━━━[/bold cyan]")
        console.print("    [bold]capture start[/bold]          Start packet capture [dim](Ctrl+C to stop)[/dim]")
        console.print()
        console.print("  [bold cyan]━━━ DISPLAY ━━━[/bold cyan]")
        console.print("    [bold]show stats[/bold]             Protocol breakdown & session stats")
        console.print("    [bold]show recent[/bold] [dim][N][/dim]        Show last N packets [dim](default: 20)[/dim]")
        console.print("    [bold]show top-talkers[/bold] [dim][N][/dim]   Most active IPs [dim](default: 10)[/dim]")
        console.print("    [bold]show interfaces[/bold]        Available network interfaces")
        console.print("    [bold]show config[/bold]            Current configuration")
        console.print()
        console.print("  [bold cyan]━━━ SEARCH ━━━[/bold cyan]")
        console.print("    [bold]search ip[/bold] [dim]<IP>[/dim]         Find packets by IP address")
        console.print("    [bold]search proto[/bold] [dim]<PROTO>[/dim]   Find packets by protocol")
        console.print("    [bold]search port[/bold] [dim]<PORT>[/dim]     Find packets by port")
        console.print()
        console.print("  [bold cyan]━━━ CONFIG ━━━[/bold cyan]")
        console.print("    [bold]set interface[/bold] [dim]<IF>[/dim]     Set capture interface")
        console.print("    [bold]set csv[/bold] [dim]<FILE>[/dim]         Enable CSV export")
        console.print("    [bold]set count[/bold] [dim]<N>[/dim]          Set packet count [dim](0=unlimited)[/dim]")
        console.print("    [bold]set display[/bold] [dim]on|off[/dim]     Toggle live packet display")
        console.print()
        console.print("  [bold cyan]━━━ EXPORT ━━━[/bold cyan]")
        console.print("    [bold]export csv[/bold] [dim]<FILE>[/dim]      Export packets to CSV file")
        console.print()
        console.print("  [bold cyan]━━━ OTHER ━━━[/bold cyan]")
        console.print("    [bold]clear[/bold]                  Clear screen")
        console.print("    [bold]help[/bold] [dim][command][/dim]        Show help")
        console.print("    [bold]exit[/bold]                   Exit NetGuard")
        console.print()
    
    # ── SHELL OVERRIDES ─────────────────────────────────────────
    
    def default(self, line):
        """Handle unknown commands."""
        console.print(f"  [red]Unknown command: {line}[/red]")
        console.print(f"  [dim]Type 'help' for available commands.[/dim]")
    
    def emptyline(self):
        """Do nothing on empty input."""
        pass
    
    def precmd(self, line):
        """Pre-process command line."""
        return line.strip()
    
    def onecmd(self, line):
        """Override to handle Ctrl+C during capture gracefully."""
        try:
            return super().onecmd(line)
        except KeyboardInterrupt:
            if self.capturing:
                console.print("\n")
                self._capture_stop()
            else:
                console.print()
            return False
    
    def cmdloop(self, intro=None):
        """Main loop with Ctrl+C handling."""
        while True:
            try:
                super().cmdloop(intro=intro)
                break  # Normal exit (via do_exit)
            except KeyboardInterrupt:
                if self.capturing:
                    console.print("\n")
                    self._capture_stop()
                else:
                    console.print("\n  [dim]Type 'exit' to quit.[/dim]")
                intro = None  # Don't show banner again
    
    @staticmethod
    def _format_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if b < 1024.0:
                return f"{b:.1f} {unit}"
            b /= 1024.0
        return f"{b:.1f} TB"
