"""
FlowSentrix Interactive Shell
Metasploit-style CLI with background capture, tab completion, and Rich display.
"""
import cmd
import sys
import os
import threading
import signal
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cli.banner import print_banner
from cli.display import (
    format_packet_line, print_packet_header, print_stats_table,
    print_connections_table, print_search_results, console
)
from intelligence.suricata import SuricataEngine
from intelligence.threat_intel import ThreatIntelChecker

# Try readline for tab completion and history
try:
    import readline
    readline.parse_and_bind("tab: complete")
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False


class FlowSentrixShell(cmd.Cmd):
    """Interactive FlowSentrix shell with background capture support."""
    
    prompt = "\033[1;36mflowsentrix\033[0m \033[1;32m▶\033[0m "
    doc_header = "Available Commands (type help <command> for details)"
    
    def __init__(self):
        super().__init__()
        
        # Config
        self.interface = self._detect_interface()
        self.csv_file = None
        self.db_path = "data/flowsentrix.db"
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

        # Session context (None = latest session)
        self.current_active_session_id = None
        
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
            from core.database import FlowSentrixDatabase
            self._db = FlowSentrixDatabase(self.db_path)
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
        
        # Suricata alert — display differently
        if '_alert' in data:
            if self.live_display:
                with self._batch_lock:
                    self._display_batch.append(data)
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
                if '_alert' in data:
                    alert = data['_alert']
                    engine = SuricataEngine()
                    alert_line = engine.format_alert_line(alert)
                    buf.write(alert_line + '\n')
                else:
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
                name="FlowSentrix-CaptureSession",
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
            console.print("  [red]✗ Root privileges required! Run with: sudo python3 flowsentrix.py[/red]")
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
            title = f"⚡ FlowSentrix | {pcap_count:,} captured | {displayed:,} displayed | {pcap_mb:.1f} MB | {elapsed}"
        else:
            title = f"⚡ FlowSentrix | {displayed:,} packets | {pcap_mb:.1f} MB | {elapsed}"
        
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
            # Kill the live tshark and dumpcap FIRST so the reader thread
            # gets EOF and _process_packets() can drain and exit quickly.
            # This prevents the race condition where join() times out and
            # reprocess() runs while _process_packets() is still going.
            if self.sniffer._tshark:
                try:
                    self.sniffer._tshark.terminate()
                except Exception:
                    pass
            if self.sniffer._dumpcap:
                try:
                    self.sniffer._dumpcap.terminate()
                except Exception:
                    pass
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=30)
        
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
  show stats            - Stats for active/latest session
  show stats all        - Cumulative stats from ALL sessions
  show connections [N]  - Show top N connections/flows (default: 10)
  show interfaces       - Available network interfaces
  show config           - Current configuration
  show alerts [N]       - Show alerts for latest session
  show alerts all       - Show alerts from ALL sessions
  show threats          - Threat summary for latest session
  show threats all      - Threat summary from ALL sessions"""
        parts = args.strip().split()
        if not parts:
            console.print("  [dim]Usage: show stats [all] | connections | interfaces | config | alerts [all] | threats [all][/dim]")
            return
        
        subcmd = parts[0].lower()
        
        if subcmd == 'stats':
            # show stats all → cumulative; show stats → active session or latest
            if len(parts) > 1 and parts[1].lower() == 'all':
                self._show_stats_all()
            else:
                self._show_stats()
        elif subcmd == 'recent':
            self._show_recent_stats()
        elif subcmd in ('connections', 'conn', 'flows', 'flow'):
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
            self._show_connections(n)
        elif subcmd in ('interfaces', 'iface', 'if'):
            self._show_interfaces()
        elif subcmd in ('config', 'settings'):
            self._show_config()
        elif subcmd in ('alerts', 'alert'):
            # show alerts all → all sessions; show alerts [N] → latest session
            show_all = False
            n = 50
            if len(parts) > 1:
                if parts[1].lower() == 'all':
                    show_all = True
                else:
                    try:
                        n = int(parts[1])
                    except ValueError:
                        pass
            self._show_alerts(n, all_sessions=show_all)
        elif subcmd in ('threats', 'threat'):
            # show threats all → all sessions; show threats → latest session
            show_all = len(parts) > 1 and parts[1].lower() == 'all'
            self._show_threats(all_sessions=show_all)
        else:
            console.print(f"  [red]Unknown: show {subcmd}[/red]")
    
    def complete_show(self, text, line, begidx, endidx):
        options = ['stats', 'connections', 'interfaces', 'config', 'alerts', 'threats']
        return [o for o in options if o.startswith(text)]
    
    def _show_stats(self):
        """Show stats for the active session (loaded or latest)."""
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
            sid = self.current_active_session_id
            if sid:
                stats = self._db.get_session_stats(sid)
                if stats is None:
                    console.print(f"  [red]✗ Session #{sid} not found.[/red]")
                    return
                label = f"Session #{sid}"
            else:
                # Default: latest session
                sid = self._db.get_recent_session_id()
                if not sid:
                    console.print("  [dim]No sessions in database.[/dim]")
                    return
                stats = self._db.get_session_stats(sid)
                label = f"Latest Session (#{sid})"
            
            if stats and stats['total_packets'] > 0:
                app_counts = {s[0]: s[1] for s in stats['protocol_stats']}
                direction = stats['direction_counts']
                console.print(f"  [dim]Showing data from {label}[/dim]")
                print_stats_table(
                    {}, app_counts, direction,
                    stats['total_packets'], stats['total_bytes']
                )
            else:
                console.print(f"  [dim]No data for {label}.[/dim]")
        else:
            console.print("  [dim]No capture running and no database available.[/dim]")

    def _show_recent_stats(self):
        """Show stats for the most recent capture session."""
        if not self._db:
            console.print("  [dim]Database not available.[/dim]")
            return
        sid = self._db.get_recent_session_id()
        if not sid:
            console.print("  [dim]No sessions in database.[/dim]")
            return
        stats = self._db.get_session_stats(sid)
        if stats and stats['total_packets'] > 0:
            app_counts = {s[0]: s[1] for s in stats['protocol_stats']}
            direction = stats['direction_counts']
            console.print(f"  [dim]Showing data from latest session (#{sid})[/dim]")
            print_stats_table(
                {}, app_counts, direction,
                stats['total_packets'], stats['total_bytes']
            )
        else:
            console.print(f"  [dim]No data for latest session (#{sid}).[/dim]")

    def _show_stats_all(self):
        """Show cumulative stats from ALL sessions."""
        if not self._db:
            console.print("  [dim]Database not available.[/dim]")
            return
        stats = self._db.get_cumulative_stats()
        if stats['total_packets'] > 0:
            app_counts = {s[0]: s[1] for s in stats['protocol_stats']}
            direction = stats['direction_counts']
            console.print(f"  [dim]Showing cumulative data from {stats['session_count']} session(s)[/dim]")
            print_stats_table(
                {}, app_counts, direction,
                stats['total_packets'], stats['total_bytes']
            )
        else:
            console.print("  [dim]No data in database.[/dim]")
    
    def _show_connections(self, limit=20):
        """Show connections/flows."""
        if self._db:
            sid = self.current_active_session_id
            if sid:
                console.print(f"  [dim]Showing connections for session #{sid}[/dim]")
            connections = self._db.get_connections(limit, session_id=sid)
            if connections:
                print_connections_table(connections)
            else:
                console.print("  [dim]No connections in database.[/dim]")
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

    def _show_alerts(self, limit=50, all_sessions=False):
        """Show Suricata IDS alerts (latest session by default, all if requested)."""
        self._init_db()
        if not self._db:
            return

        # Determine session scope
        if all_sessions:
            sid = None
            console.print("  [dim]Showing alerts from all sessions[/dim]")
        elif self.current_active_session_id:
            sid = self.current_active_session_id
            console.print(f"  [dim]Showing alerts for session #{sid}[/dim]")
        else:
            # Default: latest session
            sid = self._db.get_recent_session_id()
            if not sid:
                console.print("  [dim]No sessions in database.[/dim]")
                return
            console.print(f"  [dim]Showing alerts for latest session (#{sid})[/dim]")

        alerts = self._db.get_alerts(limit, session_id=sid)
        if not alerts:
            console.print("  [dim]No alerts detected in this session.[/dim]")
            return

        table = Table(title=f"🔴 Suricata IDS Alerts (last {len(alerts)})",
                      show_lines=False, pad_edge=False)
        table.add_column("Time", style="dim", width=19)
        table.add_column("Sev", width=8)
        table.add_column("Signature", min_width=30)
        table.add_column("Source IP", width=16)
        table.add_column("Dest", width=22)
        table.add_column("Proto", width=6)

        sev_colors = {
            'CRITICAL': 'bold red', 'HIGH': 'red',
            'MEDIUM': 'yellow', 'LOW': 'cyan'
        }

        for ts, severity, sig, category, src_ip, dst_ip, dst_port, proto in alerts:
            sev_style = sev_colors.get(severity, 'dim')
            dst_display = f"{dst_ip}:{dst_port}" if dst_port else dst_ip or ''

            # Truncate timestamp for display
            ts_display = str(ts)[:19] if ts else ''
            # Truncate signature
            sig_display = sig[:45] + '...' if len(sig) > 45 else sig

            table.add_row(
                ts_display,
                f"[{sev_style}]{severity}[/{sev_style}]",
                sig_display,
                src_ip or '',
                dst_display,
                proto or '',
            )

        console.print(table)


    def _show_threats(self, all_sessions=False):
        """Show threat summary from Suricata alerts (latest session by default)."""
        self._init_db()
        if not self._db:
            return

        # Determine session scope
        if all_sessions:
            sid = None
            console.print("  [dim]Showing threats from all sessions[/dim]")
        elif self.current_active_session_id:
            sid = self.current_active_session_id
            console.print(f"  [dim]Showing threats for session #{sid}[/dim]")
        else:
            # Default: latest session
            sid = self._db.get_recent_session_id()
            if not sid:
                console.print("  [dim]No sessions in database.[/dim]")
                return
            console.print(f"  [dim]Showing threats for latest session (#{sid})[/dim]")

        summary = self._db.get_threat_summary(session_id=sid)
        if summary['total'] == 0:
            console.print("  [dim]No threats detected in this session.[/dim]")
            return

        # Header
        console.print(f"\n  [bold red]🛡️  Threat Summary — {summary['total']} alerts detected[/bold red]\n")

        # Severity breakdown
        sev = summary['severity_counts']
        sev_line = "  "
        if sev.get('CRITICAL', 0):
            sev_line += f"[bold red]🔴 CRITICAL: {sev['CRITICAL']}[/bold red]  "
        if sev.get('HIGH', 0):
            sev_line += f"[red]🔴 HIGH: {sev['HIGH']}[/red]  "
        if sev.get('MEDIUM', 0):
            sev_line += f"[yellow]🟡 MEDIUM: {sev['MEDIUM']}[/yellow]  "
        if sev.get('LOW', 0):
            sev_line += f"[cyan]🔵 LOW: {sev['LOW']}[/cyan]  "
        console.print(sev_line)

        # Top attackers
        if summary['top_attackers']:
            console.print("\n  [bold]Top Source IPs:[/bold]")
            for ip, count in summary['top_attackers'][:5]:
                console.print(f"    [red]{ip}[/red] — {count} alerts")

        # Top signatures
        if summary['top_signatures']:
            console.print("\n  [bold]Top Signatures:[/bold]")
            for sig, count in summary['top_signatures'][:5]:
                sig_display = sig[:60] + '...' if len(sig) > 60 else sig
                console.print(f"    • {sig_display} — [yellow]{count}x[/yellow]")

        console.print()

    # ── SESSION COMMANDS ─────────────────────────────────────────

    def do_session(self, args):
        """Manage capture session history.
    
Usage:
  session list             List all past capture sessions
  session load <ID>        Load a session — filters all commands to that session
  session load 0           Unload session — resets to show all data (default)
  session delete <ID>      Delete a specific session & its data
  session clear            Wipe all session history

Session-Aware Commands:
  When a session is loaded, these commands show data only from that session:
    show connections, show top-talkers, show alerts, show threats,
    search ip/proto/port/tag, export csv
  When no session is loaded (default), all commands show data from all sessions."""
        parts = args.strip().split()
        if not parts:
            console.print("  [dim]Usage: session list | load <ID> | delete <ID> | clear[/dim]")
            return

        subcmd = parts[0].lower()

        if subcmd not in ('list', 'load', 'delete', 'clear'):
            console.print(f"  [red]Unknown: session {subcmd}[/red]. Use: list, load, delete, clear")
            return

        # Validate ID argument for load/delete
        sid = None
        if subcmd in ('load', 'delete'):
            if len(parts) < 2:
                console.print(f"  [dim]Usage: session {subcmd} <ID>[/dim]")
                return
            try:
                sid = int(parts[1])
            except ValueError:
                console.print(f"  [red]✗ Invalid session ID: {parts[1]}[/red]")
                return

        if not self._db:
            console.print("  [red]Database not available.[/red]")
            return

        if subcmd == 'list':
            self._session_list()
        elif subcmd == 'load':
            self._session_load(sid)
        elif subcmd == 'delete':
            self._session_delete(sid)
        elif subcmd == 'clear':
            self._session_clear()

    def complete_session(self, text, line, begidx, endidx):
        options = ['list', 'load', 'delete', 'clear']
        return [o for o in options if o.startswith(text)]

    def _session_list(self):
        """List all capture sessions."""
        sessions = self._db.get_all_sessions()
        if not sessions:
            console.print("  [dim]No capture sessions found.[/dim]")
            return

        table = Table(title=f"📁 Capture Sessions ({len(sessions)})", border_style="cyan")
        table.add_column("ID", style="bold cyan", width=5)
        table.add_column("Date/Time", width=20)
        table.add_column("Packets", justify="right", width=10)
        table.add_column("Bytes", justify="right", width=10)
        table.add_column("Alerts", justify="right", width=7)
        table.add_column("Interface", width=10)
        table.add_column("PCAP File", width=30)

        for sid, start, end, pkts, bts, iface, pcap, alerts in sessions:
            # Format start time
            ts_display = str(start)[:19] if start else '-'
            # Format bytes
            bytes_display = self._format_bytes(bts) if bts else '0 B'
            # Active session marker
            id_display = f"#{sid}"
            if sid == self.current_active_session_id:
                id_display += " ◀"
            # PCAP file basename
            pcap_display = os.path.basename(pcap) if pcap else '-'

            table.add_row(
                id_display,
                ts_display,
                f"{pkts:,}" if pkts else "0",
                bytes_display,
                str(alerts),
                iface or '-',
                pcap_display,
            )

        console.print(table)
        if self.current_active_session_id:
            console.print(f"  [dim]Active context: Session #{self.current_active_session_id}[/dim]")
        else:
            console.print("  [dim]No session loaded (showing latest by default)[/dim]")

    def _session_load(self, session_id):
        """Load a specific session as the active context."""
        # Special case: 0 resets to latest-session-by-default
        if session_id == 0:
            self.current_active_session_id = None
            console.print("  [green]✓[/green] Reset to [bold]latest session[/bold] (no specific session loaded)")
            return
        # Verify session exists
        stats = self._db.get_session_stats(session_id)
        if stats is None:
            console.print(f"  [red]✗ Session #{session_id} not found.[/red]")
            return
        self.current_active_session_id = session_id
        console.print(f"  [green]✓[/green] Switched context to [bold]Session #{session_id}[/bold]")
        console.print(f"  [dim]  show/search commands now filter by this session. Use 'session load 0' to reset.[/dim]")

    def _session_delete(self, session_id):
        """Delete a session and all its data."""
        deleted = self._db.delete_session(session_id)
        if deleted:
            console.print(f"  [green]✓[/green] Deleted Session #{session_id} and all related data.")
            # Reset active session if it was the one deleted
            if self.current_active_session_id == session_id:
                self.current_active_session_id = None
                console.print("  [dim]  Active session reset to latest.[/dim]")
        else:
            console.print(f"  [red]✗ Session #{session_id} not found.[/red]")

    def _session_clear(self):
        """Wipe all session history."""
        count = self._db.clear_all_sessions()
        if count < 0:
            console.print("  [red]✗ Cannot clear sessions (database may be read-only).[/red]")
            return
        self.current_active_session_id = None
        console.print(f"  [green]✓[/green] Cleared [bold]{count}[/bold] session(s) and all related data.")

    # ── SEARCH COMMANDS ─────────────────────────────────────────
    
    def do_search(self, args):
        """Search captured packets.
        
Usage:
  search ip <IP>       - Find packets by IP address
  search proto <PROTO> - Find packets by protocol
  search port <PORT>   - Find packets by port number
  search threat <IP>   - Check IP reputation (AbuseIPDB)"""
        parts = args.strip().split()
        if len(parts) < 2:
            console.print("  [dim]Usage: search ip <IP> | proto <PROTO> | port <PORT> | threat <IP>[/dim]")
            return
        
        subcmd = parts[0].lower()
        value = parts[1]

        # Validate arguments BEFORE checking DB
        if subcmd not in ('ip', 'proto', 'protocol', 'port', 'threat'):
            console.print(f"  [red]Unknown: search {subcmd}[/red]. Use: ip, proto, port, threat")
            return

        # Validate port number early
        port_num = None
        if subcmd == 'port':
            try:
                port_num = int(value)
                if port_num < 0 or port_num > 65535:
                    console.print("  [red]✗ Port must be 0-65535.[/red]")
                    return
            except ValueError:
                console.print(f"  [red]✗ Invalid port number: {value}[/red]")
                return

        if not self._db:
            console.print("  [red]Database not available.[/red]")
            return

        sid = self.current_active_session_id
        ctx = f" (session #{sid})" if sid else ""

        if subcmd == 'ip':
            console.print(f"  [bold]Searching for IP: {value}{ctx}[/bold]")
            results = self._db.search_by_ip(value, session_id=sid)
            print_search_results(results, f"IP={value}")
        elif subcmd in ('proto', 'protocol'):
            console.print(f"  [bold]Searching for protocol: {value}{ctx}[/bold]")
            results = self._db.search_by_protocol(value, session_id=sid)
            print_search_results(results, f"Protocol={value}")
        elif subcmd == 'port':
            console.print(f"  [bold]Searching for port: {port_num}{ctx}[/bold]")
            results = self._db.search_by_port(port_num, session_id=sid)
            print_search_results(results, f"Port={port_num}")
        elif subcmd == 'threat':
            self._search_threat(value)
    
    def complete_search(self, text, line, begidx, endidx):
        options = ['ip', 'proto', 'port', 'threat']
        return [o for o in options if o.startswith(text)]

    def _search_threat(self, ip):
        """Look up IP reputation via AbuseIPDB."""
        checker = ThreatIntelChecker(self._db)
        if not checker.is_configured():
            console.print("  [yellow]⚠ No API key set. Run: set api-key <YOUR_KEY>[/yellow]")
            console.print("  [dim]Get a free key at: https://www.abuseipdb.com/register[/dim]")
            return

        console.print(f"  [dim]Checking {ip} against AbuseIPDB...[/dim]")
        result = checker.check_ip(ip)

        if not result:
            console.print(f"  [red]✗ Could not look up {ip}[/red]")
            return

        score = result['abuse_score']
        country = result.get('country', '?')
        isp = result.get('isp', 'Unknown')

        # Color based on score
        if score >= 75:
            score_display = f"[bold red]{score}% 🔴 MALICIOUS[/bold red]"
        elif score >= 50:
            score_display = f"[red]{score}% ⚠️  SUSPICIOUS[/red]"
        elif score >= 25:
            score_display = f"[yellow]{score}% ⚡ LOW RISK[/yellow]"
        else:
            score_display = f"[green]{score}% ✅ CLEAN[/green]"

        console.print(f"\n  [bold]🔍 Threat Intel Report: {ip}[/bold]")
        console.print(f"    Abuse Score: {score_display}")
        console.print(f"    Country:     [cyan]{country}[/cyan]")
        console.print(f"    ISP:         [cyan]{isp}[/cyan]")
        console.print(f"    Cached:      [dim]{'yes (from DB)' if result.get('last_checked') else 'fresh lookup'}[/dim]")
        console.print()
    
    # ── SET COMMANDS ────────────────────────────────────────────
    
    def do_set(self, args):
        """Configure capture settings.
        
Usage:
  set interface <IF>   - Set capture interface
  set csv <FILE>       - Set CSV export file
  set count <N>        - Set packet count (0=unlimited)
  set display on|off   - Toggle live packet display
  set api-key <KEY>    - Set AbuseIPDB API key for threat intel"""
        # Use maxsplit=1 to preserve spaces in file paths (e.g. set csv /path/my file.csv)
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            console.print("  [dim]Usage: set interface|csv|count|display|api-key <value>[/dim]")
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
        elif key == 'api-key':
            checker = ThreatIntelChecker()
            checker.set_api_key(value)
            console.print(f"  [green]✓[/green] AbuseIPDB API key saved to [bold]~/.flowsentrix/config.json[/bold]")
            console.print(f"  [dim]  Threat intel lookups will be enabled on next capture.[/dim]")
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
  export csv [filename] - Export connections to CSV file (auto-names if omitted)"""
        parts = args.strip().split()
        if not parts:
            console.print("  [dim]Usage: export csv [filename][/dim]")
            return
        
        fmt = parts[0].lower()
        if fmt != 'csv':
            console.print(f"  [red]Unknown format: {parts[0]}[/red]. Use: csv")
            return

        if len(parts) >= 2:
            filename = parts[1]
        else:
            # Auto-generate filename with timestamp
            filename = f"flowsentrix_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        # Auto-append .csv if not present
        if not filename.lower().endswith('.csv'):
            filename += '.csv'

        if not self._db:
            console.print("  [red]Database not available.[/red]")
            return

        try:
            sid = self.current_active_session_id
            count = self._db.export_to_csv(filename, session_id=sid)
            ctx = f" from session #{sid}" if sid else ""
            console.print(f"  [green]✓[/green] Exported [bold]{count:,}[/bold] connections{ctx} to [bold]{filename}[/bold]")
        except Exception as e:
            console.print(f"  [red]✗ Export failed: {e}[/red]")
    
    def complete_export(self, text, line, begidx, endidx):
        return [o for o in ['csv'] if o.startswith(text)]
    
    # ── UTILITY COMMANDS ────────────────────────────────────────
    
    def do_clear(self, args):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def do_exit(self, args):
        """Exit FlowSentrix."""
        if self.capturing:
            console.print("  [yellow]Stopping capture...[/yellow]")
            self._capture_stop()
        console.print("  [cyan]Goodbye! 👋[/cyan]")
        return True
    
    def do_quit(self, args):
        """Exit FlowSentrix."""
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
        console.print("    [bold]show stats[/bold]              Stats for the loaded session [dim](or latest)[/dim]")
        console.print("    [bold]show stats all[/bold]          Cumulative stats from ALL sessions")
        console.print("    [bold]show connections[/bold] [dim][N][/dim]   Show top N connections/flows [dim](default: 10)[/dim]")
        console.print("    [bold]show interfaces[/bold]        Available network interfaces")
        console.print("    [bold]show config[/bold]            Current configuration")
        console.print("    [bold]show alerts[/bold] [dim][N][/dim]        Suricata IDS alerts [dim](latest session)[/dim]")
        console.print("    [bold]show alerts all[/bold]        Alerts from ALL sessions")
        console.print("    [bold]show threats[/bold]           Threat summary [dim](latest session)[/dim]")
        console.print("    [bold]show threats all[/bold]       Threat summary from ALL sessions")
        console.print()
        console.print("  [bold cyan]━━━ HISTORY ━━━[/bold cyan]")
        console.print("    [bold]session list[/bold]            List all past capture sessions")
        console.print("    [bold]session load[/bold] [dim]<ID>[/dim]      Load a session to view/search")
        console.print("    [bold]session delete[/bold] [dim]<ID>[/dim]    Delete a session & its data")
        console.print("    [bold]session clear[/bold]           Wipe all session history")
        console.print()
        console.print("  [bold cyan]━━━ SEARCH ━━━[/bold cyan]")
        console.print("    [bold]search ip[/bold] [dim]<IP>[/dim]         Find connections by IP address")
        console.print("    [bold]search proto[/bold] [dim]<PROTO>[/dim]   Find connections by protocol")
        console.print("    [bold]search port[/bold] [dim]<PORT>[/dim]     Find connections by port")
        console.print("    [bold]search threat[/bold] [dim]<IP>[/dim]    Check IP reputation [dim](AbuseIPDB)[/dim]")
        console.print()
        console.print("  [bold cyan]━━━ CONFIG ━━━[/bold cyan]")
        console.print("    [bold]set interface[/bold] [dim]<IF>[/dim]     Set capture interface")
        console.print("    [bold]set csv[/bold] [dim]<FILE>[/dim]         Enable CSV export")
        console.print("    [bold]set count[/bold] [dim]<N>[/dim]          Set packet count [dim](0=unlimited)[/dim]")
        console.print("    [bold]set display[/bold] [dim]on|off[/dim]     Toggle live packet display")
        console.print("    [bold]set api-key[/bold] [dim]<KEY>[/dim]      Set AbuseIPDB API key")
        console.print()
        console.print("  [bold cyan]━━━ EXPORT ━━━[/bold cyan]")
        console.print("    [bold]export csv[/bold] [dim][FILE][/dim]      Export connections to CSV [dim](auto-names if omitted)[/dim]")
        console.print()
        console.print("  [bold cyan]━━━ OTHER ━━━[/bold cyan]")
        console.print("    [bold]clear[/bold]                  Clear screen")
        console.print("    [bold]help[/bold] [dim][command][/dim]        Show help")
        console.print("    [bold]exit[/bold]                   Exit FlowSentrix")
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
