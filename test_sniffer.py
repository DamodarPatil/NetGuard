#!/usr/bin/env python3
"""
NetGuard - Quick Sniffer Test
Run with: sudo python3 test_sniffer.py
"""
from core.sniffer import PacketSniffer


def main():
    print("=" * 70)
    print("NetGuard - SQLite Database Integration (Phase 2)")
    print("=" * 70)
    print("\n💾 All packets now stored in SQLite database (data/netguard.db)")
    print("   Much faster and more efficient than CSV!")
    print()
    print("💡 Generate diverse traffic to see smart detection:")
    print("   ping 8.8.8.8                    # ICMP Echo Request/Reply")
    print("   curl http://example.com         # HTTP")
    print("   curl https://google.com         # HTTPS/QUIC")
    print()
    print("🔍 After capture, query your data:")
    print("   python3 query_db.py --stats          # Show statistics")
    print("   python3 query_db.py --recent 100     # Last 100 packets")
    print("   python3 query_db.py --ip 8.8.8.8      # Search by IP")
    print("   python3 query_db.py --protocol TCP   # Search by protocol")
    print()
    print("📚 See DATABASE_GUIDE.md for advanced queries")
    print("\n⚠️  Press Ctrl+C to stop and see session summary\n")
    
    # Initialize sniffer with database
    sniffer = PacketSniffer(
        interface=None,
        db_path="data/netguard.db"
    )
    
    # Capture 30 packets to see variety (use 0 for infinite)
    sniffer.start(count=1000)


if __name__ == "__main__":
    main()
