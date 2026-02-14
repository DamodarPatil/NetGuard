#!/bin/bash
# Launch Wireshark and NetGuard simultaneously for comparison testing.
# Usage: sudo ./compare.sh [interface]

IFACE="${1:-wlo1}"

echo "🚀 Starting Wireshark + NetGuard on '$IFACE'..."
echo "   Press Ctrl+C in NetGuard terminal to stop both."
echo ""

# Start Wireshark in background (capture starts immediately)
wireshark -i "$IFACE" -k &
WS_PID=$!

# Small delay to let Wireshark initialize
sleep 0.3

# Start NetGuard in foreground (Ctrl+C stops it)
python3 netguard.py <<EOF
set interface $IFACE
capture start
EOF

# Wireshark stays open so you can export CSV for comparison
echo ""
echo "✓ NetGuard stopped. Wireshark is still open — export CSV when ready."
