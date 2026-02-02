"""
NetGuard Packet Sniffer
Uses Scapy to capture network packets.
"""
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
from datetime import datetime


class PacketSniffer:
    """Lightweight packet capture engine."""
    
    def __init__(self, interface=None, packet_count=10):
        """
        Initialize the sniffer.
        
        Args:
            interface: Network interface to sniff (None = all interfaces)
            packet_count: Number of packets to capture (0 = infinite)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets_captured = 0
    
    def packet_callback(self, packet):
        """Process each captured packet."""
        self.packets_captured += 1
        
        # Extract timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Determine protocol and extract IPs
        if IP in packet:
            # IPv4 packet
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if TCP in packet:
                protocol = "TCP"
                port_info = f":{packet[TCP].dport}"
            elif UDP in packet:
                protocol = "UDP"
                port_info = f":{packet[UDP].dport}"
                # Check if it's DNS
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    protocol = "DNS"
                    port_info = ""
            elif ICMP in packet:
                protocol = "ICMP"
                port_info = " (ping)"
            else:
                protocol = packet[IP].proto  # Show protocol number
                port_info = ""
                
        elif IPv6 in packet:
            # IPv6 packet
            src_ip = packet[IPv6].src[:20] + "..."  # Truncate for display
            dst_ip = packet[IPv6].dst[:20] + "..."
            
            if TCP in packet:
                protocol = "TCP6"
                port_info = f":{packet[TCP].dport}"
            elif UDP in packet:
                protocol = "UDP6"
                port_info = f":{packet[UDP].dport}"
            else:
                protocol = "IPv6"
                port_info = ""
                
        elif ARP in packet:
            # ARP packet
            protocol = "ARP"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            port_info = " (who-has)"
            
        else:
            # Skip non-IP packets (reduces noise)
            return
        
        # Print status (not raw data - we're NetGuard, not Wireshark!)
        print(f"[{timestamp}] {protocol:6} | {src_ip:15} → {dst_ip:15}{port_info}")
        
        # TODO: Send to database and intelligence engine
    
    def start(self):
        """Start packet capture."""
        print(f"🛡️  NetGuard Sniffer Starting...")
        print(f"Interface: {self.interface or 'All'}")
        print(f"Capturing {self.packet_count if self.packet_count > 0 else '∞'} packets...\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                store=False  # Don't store in memory (efficient!)
            )
        except PermissionError:
            print("❌ Error: Root/sudo privileges required for packet capture!")
            print("Run with: sudo python3 test_sniffer.py")
        except Exception as e:
            print(f"❌ Capture error: {e}")
        
        print(f"\n✅ Capture complete! {self.packets_captured} packets processed.")


if __name__ == "__main__":
    # Quick test
    sniffer = PacketSniffer(packet_count=10)
    sniffer.start()
