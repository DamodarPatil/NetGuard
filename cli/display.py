"""
NetGuard CLI Display
Color-coded packet and table formatting with Rich.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console(emoji=False)  # Disable emoji — :cd: in MACs 

# Protocol color map
PROTO_COLORS = {
    'TCP': 'blue',
    'UDP': 'green',
    'DNS': 'bright_green',
    'mDNS': 'bright_green',
    'MDNS': 'bright_green',
    'HTTP': 'bright_magenta',
    'HTTP-ALT': 'bright_magenta',
    'TLSv1.0': 'yellow',
    'TLSv1.2': 'yellow',
    'TLSv1.3': 'bold yellow',
    'SSLv3': 'yellow',
    'QUIC': 'bright_cyan',
    'ARP': 'white',
    'ICMP': 'cyan',
    'ICMPv6': 'cyan',
    'SSH': 'red',
    'FTP': 'red',
    'SMTP': 'magenta',
}

# Info patterns that get special colors
ALERT_PATTERNS = {
    'TCP Retransmission': 'bold red',
    'TCP Dup ACK': 'red',
    'TCP Out-Of-Order': 'bold red',
    'TCP Previous segment not captured': 'red',
    'TCP Keep-Alive': 'dim yellow',
    'TCP Keep-Alive ACK': 'dim yellow',
    'TCP ZeroWindow': 'bold red',
    'TCP Window Update': 'dim cyan',
    'Client Hello': 'bold green',
    'Server Hello': 'bold green',
    'Application Data': 'dim yellow',
}


def format_packet_line(data):
    """Format a single packet as a colored Rich Text line for live display."""
    proto = data.get('application_protocol', data.get('transport_protocol', '?'))
    color = PROTO_COLORS.get(proto, 'white')
    
    pkt_id = data.get('packet_id', '?')
    rel_time = data.get('relative_time', 0)
    src = data.get('display_src', data.get('src', '?'))
    dst = data.get('display_dst', data.get('dst', '?'))
    src_port = data.get('src_port', '')
    dst_port = data.get('dst_port', '')
    length = data.get('packet_length', 0)
    info = data.get('info', '')
    direction = data.get('direction', '')
    
    src_display = f"{src}:{src_port}" if src_port else src
    dst_display = f"{dst}:{dst_port}" if dst_port else dst
    
    # Truncate long addresses
    if len(src_display) > 24:
        src_display = src_display[:21] + "..."
    if len(dst_display) > 24:
        dst_display = dst_display[:21] + "..."
    
    # Build the line with colors
    line = Text()
    line.append(f"  {pkt_id:<5} ", style="dim")
    line.append(f"{rel_time:>8.3f}s ", style="dim")
    line.append(f"{proto:<8} ", style=f"bold {color}")
    
    # Direction arrow
    if direction == 'OUTGOING':
        line.append(f"{src_display:<24} ", style="green")
        line.append("→ ", style="bold green")
        line.append(f"{dst_display:<24} ", style="white")
    elif direction == 'INCOMING':
        line.append(f"{src_display:<24} ", style="white")
        line.append("→ ", style="bold blue")
        line.append(f"{dst_display:<24} ", style="blue")
    else:
        line.append(f"{src_display:<24} ", style="white")
        line.append("→ ", style="dim")
        line.append(f"{dst_display:<24} ", style="white")
    
    line.append(f"{length:>5} ", style="dim")
    
    # Color the info based on alert patterns
    info_style = "white"
    for pattern, style in ALERT_PATTERNS.items():
        if pattern in info:
            info_style = style
            break
    
    # Truncate info if too long
    if len(info) > 60:
        info = info[:57] + "..."
    line.append(info, style=info_style)
    
    return line


def print_packet_header():
    """Print the column header for packet display."""
    header = Text()
    header.append(f"  {'#':<5} ", style="bold dim")
    header.append(f"{'TIME':>8}  ", style="bold dim")
    header.append(f"{'PROTO':<8} ", style="bold dim")
    header.append(f"{'SOURCE':<24} ", style="bold dim")
    header.append(f"   ", style="dim")
    header.append(f"{'DESTINATION':<24} ", style="bold dim")
    header.append(f"{'LEN':>5} ", style="bold dim")
    header.append(f"INFO", style="bold dim")
    console.print(header)
    console.print("  " + "─" * 100, style="dim")


def print_stats_table(transport_counts, application_counts, direction_counts, 
                      total_packets, total_bytes, duration_str=""):
    """Print protocol statistics as a Rich table."""
    # Session overview panel
    overview = Table(show_header=False, box=None, padding=(0, 2))
    overview.add_column(style="bold green")
    overview.add_column(style="white")
    overview.add_row("Total Packets", f"{total_packets:,}")
    overview.add_row("Total Bytes", _format_bytes(total_bytes))
    if duration_str:
        overview.add_row("Duration", duration_str)
    for direction, count in sorted(direction_counts.items()):
        pct = (count / total_packets * 100) if total_packets > 0 else 0
        overview.add_row(f"  {direction}", f"{count:,} ({pct:.1f}%)")
    
    console.print(Panel(overview, title="[bold cyan]Session Overview[/]", border_style="cyan"))
    
    # Unified protocols table — each packet counted once
    if application_counts:
        proto_table = Table(title="Protocols", border_style="yellow")
        proto_table.add_column("Protocol", style="bold yellow", min_width=12)
        proto_table.add_column("Packets", justify="right", style="white")
        proto_table.add_column("%", justify="right", style="dim")
        proto_table.add_column("Distribution", min_width=30)
        
        sorted_protos = sorted(application_counts.items(), key=lambda x: x[1], reverse=True)
        for proto, count in sorted_protos[:20]:
            pct = (count / total_packets * 100) if total_packets > 0 else 0
            bar_len = int(pct / 2)
            bar = "█" * bar_len + "░" * (50 - bar_len)
            color = PROTO_COLORS.get(proto, 'white')
            proto_table.add_row(
                f"[{color}]{proto}[/]",
                f"{count:,}",
                f"{pct:.1f}%",
                f"[{color}]{bar}[/]"
            )
        console.print(proto_table)


# Severity → color mapping for behavioral tags
TAG_SEVERITY_COLORS = {
    'critical': 'bold red',
    'high': 'red',
    'medium': 'yellow',
    'low': 'dim',
}


def print_connections_table(connections):
    """Print connections/flows as a Rich table."""
    if not connections:
        console.print("  [dim]No connections in database.[/dim]")
        return

    # Check if any connection has tags
    has_tags = any(len(c) >= 13 and c[12] for c in connections)

    table = Table(title=f"Network Connections ({len(connections)} flows)", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Source", width=22)
    table.add_column("Destination", width=22)
    table.add_column("Protocol", width=10)
    table.add_column("Dir", width=4)
    table.add_column("Packets", justify="right", width=9)
    table.add_column("Bytes", justify="right", width=10)
    table.add_column("Duration", justify="right", width=8)
    table.add_column("State", width=8)
    if has_tags:
        table.add_column("Tags", width=18)

    for i, conn in enumerate(connections, 1):
        # Unpack — handle both 12-field (legacy) and 14-field (with tags) tuples
        src_ip, dst_ip, src_port, dst_port, protocol, direction, \
            start_time, end_time, duration, total_packets, total_bytes, state = conn[:12]
        tags = conn[12] if len(conn) > 12 else ''
        severity = conn[13] if len(conn) > 13 else ''

        color = PROTO_COLORS.get(protocol, 'white')

        # Format source and destination
        src_display = f"{src_ip}:{src_port}" if src_port else src_ip
        dst_display = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        if len(src_display) > 22:
            src_display = src_display[:19] + "..."
        if len(dst_display) > 22:
            dst_display = dst_display[:19] + "..."

        # Direction arrow
        dir_display = "→" if direction == 'OUTGOING' else "←" if direction == 'INCOMING' else "↔"

        # Format duration
        dur_str = _format_duration(duration) if duration else "-"

        # State color
        state_style = "green" if state == "ESTABLISHED" else "yellow" if state == "ACTIVE" else "red" if state in ("RST", "FIN") else "dim"

        row = [
            str(i),
            src_display,
            dst_display,
            f"[{color}]{protocol}[/]",
            dir_display,
            f"{total_packets:,}",
            _format_bytes(total_bytes),
            dur_str,
            f"[{state_style}]{state}[/]",
        ]

        if has_tags:
            if tags:
                tag_color = TAG_SEVERITY_COLORS.get(severity, 'dim')
                row.append(f"[{tag_color}]{tags}[/]")
            else:
                row.append("")

        table.add_row(*row)

    console.print(table)


def print_top_talkers(talkers):
    """Print top talkers as a Rich table."""
    table = Table(title="Top Talkers", border_style="green")
    table.add_column("#", style="dim", width=4)
    table.add_column("IP Address", style="bold", min_width=20)
    table.add_column("Connections", justify="right", style="dim")
    table.add_column("Packets", justify="right", style="white")
    table.add_column("Bytes", justify="right", style="cyan")
    
    for i, talker in enumerate(talkers, 1):
        style = "bold green" if i <= 3 else "white"
        if len(talker) == 4:
            ip, connections, packets, total_bytes = talker
            table.add_row(
                str(i), f"[{style}]{ip}[/]",
                f"{connections:,}", f"{packets:,}", _format_bytes(total_bytes)
            )
        elif len(talker) == 2:
            ip, count = talker
            table.add_row(str(i), f"[{style}]{ip}[/]", "-", f"{count:,}", "-")
    
    console.print(table)


def print_search_results(connections, search_type=""):
    """Print search results (connection-level)."""
    if not connections:
        console.print(f"  [dim]No connections found.[/dim]")
        return
    
    console.print(f"  [green]Found {len(connections)} connection(s)[/green]")
    print_connections_table(connections)


def print_tag_summary(summary):
    """Print behavioral tag summary table."""
    if not summary or summary.get('total_tagged', 0) == 0:
        console.print("  [dim]No behavioral tags detected yet.[/dim]")
        console.print("  [dim]Tags are generated during packet capture.[/dim]")
        return

    # Severity overview
    sev_table = Table(title="Behavioral Tags Summary", border_style="yellow")
    sev_table.add_column("Severity", style="bold", width=12)
    sev_table.add_column("Count", justify="right", width=8)
    
    for sev in ['critical', 'high', 'medium', 'low']:
        count = summary['severity_counts'].get(sev, 0)
        if count > 0:
            color = TAG_SEVERITY_COLORS.get(sev, 'white')
            sev_table.add_row(f"[{color}]{sev.upper()}[/]", f"{count:,}")

    sev_table.add_row("[bold]TOTAL[/]", f"[bold]{summary['total_tagged']:,}[/]")
    console.print(sev_table)

    # Tag breakdown
    if summary.get('tag_counts'):
        tag_table = Table(title="Tags Breakdown", border_style="cyan")
        tag_table.add_column("Tag", style="bold yellow", width=18)
        tag_table.add_column("Connections", justify="right", width=12)

        tag_names = {
            'beaconing': '⏱  beaconing',
            'data_exfil': '📤 data_exfil',
            'new_dest': '🆕 new_dest',
            'traffic_anomaly': '📈 traffic_anomaly',
        }

        for tag, count in sorted(summary['tag_counts'].items(), key=lambda x: x[1], reverse=True):
            display = tag_names.get(tag, tag)
            tag_table.add_row(display, f"{count:,}")

        console.print(tag_table)


def _format_bytes(bytes_value):
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def _format_duration(seconds):
    """Format duration in seconds to human-readable string."""
    if seconds is None or seconds == 0:
        return "-"
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    hours = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    return f"{hours}h {mins}m"
