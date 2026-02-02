#!/usr/bin/env python3
"""
NetGuard - Quick Sniffer Test
Run with: sudo python3 test_sniffer.py
"""
from core.sniffer import PacketSniffer


def main():
    print("=" * 60)
    print("NetGuard - Packet Capture Test (Enhanced)")
    print("=" * 60)
    print("\n💡 Tip: Generate traffic in another terminal:")
    print("   ping 8.8.8.8       # ICMP packets")
    print("   curl google.com    # TCP/DNS packets")
    print("   or browse the web\n")
    
    # Capture 30 packets for testing
    sniffer = PacketSniffer(interface=None, packet_count=1000)
    sniffer.start()


if __name__ == "__main__":
    main()
