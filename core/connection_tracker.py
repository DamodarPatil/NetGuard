"""
Connection/Flow Tracker for FlowSentrix.

Aggregates individual packets into connection-level summaries (flows).
This is how real enterprise network monitors (Zeek, ntopng, Arkime) work:
one row per connection instead of one row per packet.

A connection is identified by a 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)

Usage:
    tracker = ConnectionTracker()
    tracker.update(packet_data)   # called per packet
    flows = tracker.get_flows()   # get all flow summaries
    tracker.reset()               # clear for reprocessing
"""

from typing import Dict, List, Optional


# TCP flag → state mapping
TCP_STATE_MAP = {
    'SYN': 'SYN_SENT',
    'SYN,ACK': 'ESTABLISHED',
    'SYN, ACK': 'ESTABLISHED',
    'FIN': 'FIN',
    'FIN,ACK': 'FIN',
    'FIN, ACK': 'FIN',
    'RST': 'RST',
    'RST,ACK': 'RST',
    'RST, ACK': 'RST',
}


class ConnectionTracker:
    """Aggregates packets into connection/flow summaries in memory.

    Uses a dict keyed by 5-tuple for O(1) lookup per packet.
    Periodically flushed to the database by the capture engine.
    """

    def __init__(self):
        self.flows: Dict[tuple, dict] = {}  # key → flow_data

    def update(self, packet_data: dict) -> str:
        """Update or create a flow entry for this packet.

        Args:
            packet_data: Parsed packet dict from tshark (has src, dst,
                         src_port, dst_port, transport_protocol, etc.)

        Returns:
            The flow key string for reference.
        """
        src_ip = packet_data.get('src', '')
        dst_ip = packet_data.get('dst', '')
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        transport = packet_data.get('transport_protocol', '')
        application = packet_data.get('application_protocol', '')
        protocol = application or transport
        direction = packet_data.get('direction', '')
        pkt_len = packet_data.get('packet_length', 0)
        timestamp = packet_data.get('absolute_timestamp', '')
        tcp_flags = packet_data.get('tcp_flags', '')

        # Normalize the key: use sorted IPs so A→B and B→A are the same flow
        # But keep the original src/dst for the first packet (initiator)
        if src_port and dst_port:
            key = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
            reverse_key = self._make_key(dst_ip, src_ip, dst_port, src_port, protocol)
        else:
            # No ports (ICMP, ARP, etc.) — use IPs + protocol only
            key = self._make_key(src_ip, dst_ip, 0, 0, protocol)
            reverse_key = self._make_key(dst_ip, src_ip, 0, 0, protocol)

        # Check if this packet belongs to an existing flow (either direction)
        if key in self.flows:
            flow = self.flows[key]
        elif reverse_key in self.flows:
            flow = self.flows[reverse_key]
            key = reverse_key  # Use the existing key
        else:
            # New flow
            flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'transport': transport,
                'direction': direction,
                'start_time': timestamp,
                'end_time': timestamp,
                'duration': 0.0,
                'total_packets': 0,
                'total_bytes': 0,
                'state': 'ACTIVE',
            }
            self.flows[key] = flow

        # Update the flow
        flow['total_packets'] += 1
        flow['total_bytes'] += pkt_len
        flow['end_time'] = timestamp

        # Calculate duration
        try:
            from datetime import datetime
            start = datetime.fromisoformat(flow['start_time'])
            end = datetime.fromisoformat(flow['end_time'])
            flow['duration'] = (end - start).total_seconds()
        except Exception:
            pass

        # Update TCP state from flags
        if tcp_flags:
            new_state = TCP_STATE_MAP.get(tcp_flags.strip())
            if new_state:
                flow['state'] = new_state

        return str(key)

    def get_flows(self) -> List[dict]:
        """Return all flows as a list of dicts for DB insertion."""
        return list(self.flows.values())

    def get_flow_count(self) -> int:
        """Return number of active flows."""
        return len(self.flows)

    def reset(self):
        """Clear all flows (called before reprocessing)."""
        self.flows.clear()

    @staticmethod
    def _make_key(src_ip, dst_ip, src_port, dst_port, protocol) -> tuple:
        """Create a normalized flow key from the 5-tuple."""
        return (src_ip, dst_ip, int(src_port or 0), int(dst_port or 0), protocol)
