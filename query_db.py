#!/usr/bin/env python3
"""
NetGuard Database Query Tool
Query and analyze captured network traffic from SQLite database.
"""
import sys
import argparse
from core.database import NetGuardDatabase
from datetime import datetime


def format_packet_row(packet):
    """Format packet data for display."""
    timestamp, src, dst, protocol, size, info = packet
    # Truncate long IPs for display
    src_display = src[:18] if len(src) <= 18 else src[:15] + "..."
    dst_display = dst[:18] if len(dst) <= 18 else dst[:15] + "..."
    
    return f"{timestamp} | {protocol:<6} | {src_display:<18} → {dst_display:<18} | {size:<6} | {info}"


def show_recent(db, limit=50):
    """Show most recent packets."""
    print(f"\n📊 Most Recent {limit} Packets")
    print("=" * 120)
    
    packets = db.get_recent_packets(limit)
    
    if not packets:
        print("No packets found in database.")
        return
    
    for packet in packets:
        print(format_packet_row(packet))
    
    print(f"\nShowing {len(packets)} of {db.get_packet_count()} total packets")


def show_stats(db):
    """Show protocol statistics."""
    print("\n📈 Protocol Statistics")
    print("=" * 70)
    
    stats = db.get_protocol_stats()
    
    if not stats:
        print("No statistics available.")
        return
    
    total_packets = sum(s[1] for s in stats)
    total_bytes = sum(s[2] for s in stats)
    
    print(f"Total Packets: {total_packets:,}")
    print(f"Total Bytes: {format_bytes(total_bytes)}")
    print(f"Database Size: {db.get_database_size()}")
    print("\nProtocol Breakdown:")
    print("-" * 70)
    
    for protocol, count, bytes_val in stats:
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        bar_length = int(percentage / 2)
        bar = "█" * bar_length + "░" * (50 - bar_length)
        print(f"  {protocol:<10} : {count:>8,} packets ({percentage:>5.1f}%) | {format_bytes(bytes_val):>10} {bar}")


def format_bytes(bytes_value):
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def search_ip(db, ip_address):
    """Search for packets by IP address."""
    print(f"\n🔍 Searching for IP: {ip_address}")
    print("=" * 120)
    
    packets = db.search_by_ip(ip_address)
    
    if not packets:
        print(f"No packets found for IP: {ip_address}")
        return
    
    print(f"Found {len(packets)} packet(s):\n")
    
    for packet in packets:
        print(format_packet_row(packet))


def search_protocol(db, protocol):
    """Search for packets by protocol."""
    print(f"\n🔍 Searching for Protocol: {protocol}")
    print("=" * 120)
    
    packets = db.search_by_protocol(protocol.upper())
    
    if not packets:
        print(f"No packets found for protocol: {protocol}")
        return
    
    print(f"Found {len(packets)} packet(s) (showing up to 1000):\n")
    
    for packet in packets[:100]:  # Limit display to 100
        print(format_packet_row(packet))
    
    if len(packets) > 100:
        print(f"\n... and {len(packets) - 100} more. Use --export to see all.")


def show_top_talkers(db, limit=10):
    """Show most active IP addresses."""
    print(f"\n🗣️  Top {limit} Most Active IPs")
    print("=" * 50)
    
    talkers = db.get_top_talkers(limit)
    
    if not talkers:
        print("No data available.")
        return
    
    for i, (ip, count) in enumerate(talkers, 1):
        print(f"  {i:2}. {ip:<18} : {count:>8,} packets")


def export_csv(db, output_file, limit=None):
    """Export database to CSV."""
    print(f"\n📤 Exporting to CSV: {output_file}")
    
    count = db.export_to_csv(output_file, limit)
    
    print(f"✅ Exported {count} packets to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard Database Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --recent 100                    Show last 100 packets
  %(prog)s --stats                         Show protocol statistics
  %(prog)s --ip 192.168.1.100              Search by IP address
  %(prog)s --protocol TCP                  Search by protocol
  %(prog)s --top-talkers 20                Show top 20 active IPs
  %(prog)s --export output.csv             Export all to CSV
  %(prog)s --export output.csv --limit 1000  Export last 1000 to CSV
        """
    )
    
    parser.add_argument('--db', default='data/netguard.db', 
                       help='Database path (default: data/netguard.db)')
    parser.add_argument('--recent', type=int, metavar='N',
                       help='Show N most recent packets')
    parser.add_argument('--stats', action='store_true',
                       help='Show protocol statistics')
    parser.add_argument('--ip', metavar='IP_ADDRESS',
                       help='Search packets by IP address')
    parser.add_argument('--protocol', metavar='PROTOCOL',
                       help='Search packets by protocol (TCP, UDP, DNS, etc.)')
    parser.add_argument('--top-talkers', type=int, metavar='N',
                       help='Show top N most active IP addresses')
    parser.add_argument('--export', metavar='CSV_FILE',
                       help='Export database to CSV file')
    parser.add_argument('--limit', type=int, metavar='N',
                       help='Limit export to N packets (used with --export)')
    
    args = parser.parse_args()
    
    # Initialize database
    db = NetGuardDatabase(args.db)
    
    # If no arguments, show stats by default
    if len(sys.argv) == 1:
        show_stats(db)
        print()
        show_recent(db, 20)
        return
    
    # Execute requested operations
    if args.stats:
        show_stats(db)
    
    if args.recent:
        show_recent(db, args.recent)
    
    if args.ip:
        search_ip(db, args.ip)
    
    if args.protocol:
        search_protocol(db, args.protocol)
    
    if args.top_talkers:
        show_top_talkers(db, args.top_talkers)
    
    if args.export:
        export_csv(db, args.export, args.limit)
    
    print()  # Final newline


if __name__ == "__main__":
    main()
