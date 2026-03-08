"""
FlowSentrix Intelligence Module
🧠 Behavioral tagging, anomaly detection, and threat intelligence.

Components:
  - SuricataEngine: Real-time IDS using Suricata subprocess
  - ThreatIntelChecker: IP reputation via AbuseIPDB API
"""

from intelligence.suricata import SuricataEngine
from intelligence.threat_intel import ThreatIntelChecker
