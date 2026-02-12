"""
NetGuard CLI Display
Color-coded packet and table formatting with Rich.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

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


def print_recent_table(packets):
    """Print recent packets as a Rich table."""
    table = Table(title=f"Recent Packets ({len(packets)} shown)", border_style="cyan")
    table.add_column("#", style="dim", width=6)
    table.add_column("Time", style="dim", width=22)
    table.add_column("Protocol", width=10)
    table.add_column("Source", width=20)
    table.add_column("Destination", width=20)
    table.add_column("Len", justify="right", width=6)
    table.add_column("Info", max_width=50)
    
    for pkt in packets:
        timestamp, src, dst, protocol, size, info = pkt
        color = PROTO_COLORS.get(protocol, 'white')
        # Truncate info
        info_display = info[:50] + "..." if len(info) > 50 else info
        table.add_row(
            str(size),  # placeholder, DB returns different order
            timestamp[:22],
            f"[{color}]{protocol}[/]",
            src[:20],
            dst[:20],
            str(size),
            info_display
        )
    
    console.print(table)


def print_top_talkers(talkers):
    """Print top talkers as a Rich table."""
    table = Table(title="Top Talkers", border_style="green")
    table.add_column("#", style="dim", width=4)
    table.add_column("IP Address", style="bold", min_width=20)
    table.add_column("Packets", justify="right", style="white")
    
    for i, (ip, count) in enumerate(talkers, 1):
        style = "bold green" if i <= 3 else "white"
        table.add_row(str(i), f"[{style}]{ip}[/]", f"{count:,}")
    
    console.print(table)


def print_search_results(packets, search_type=""):
    """Print search results."""
    if not packets:
        console.print(f"  [dim]No packets found.[/dim]")
        return
    
    console.print(f"  [green]Found {len(packets)} packet(s)[/green]")
    
    table = Table(border_style="yellow", show_lines=False)
    table.add_column("Time", style="dim", width=22)
    table.add_column("Protocol", width=10)
    table.add_column("Source", width=22)
    table.add_column("Destination", width=22)
    table.add_column("Size", justify="right", width=6)
    table.add_column("Info", max_width=45)
    
    display_limit = min(len(packets), 100)
    for pkt in packets[:display_limit]:
        timestamp, src, dst, protocol, size, info = pkt
        color = PROTO_COLORS.get(protocol, 'white')
        info_display = info[:45] + "..." if len(info) > 45 else info
        table.add_row(
            timestamp[:22],
            f"[{color}]{protocol}[/]",
            src[:22],
            dst[:22],
            str(size),
            info_display
        )
    
    console.print(table)
    if len(packets) > display_limit:
        console.print(f"  [dim]... and {len(packets) - display_limit} more. Use 'export csv' to see all.[/dim]")


def _format_bytes(bytes_value):
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"
