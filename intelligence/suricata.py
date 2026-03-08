"""
Suricata IDS Integration for FlowSentrix.

Manages Suricata as a subprocess for real-time threat detection.
Suricata runs as Process 3 alongside dumpcap (capture) and tshark (display),
capturing independently via AF_PACKET for zero-overhead analysis.

Architecture:
  suricata -i <iface> --af-packet -l <logdir>/
  → eve.json (real-time JSON alerts)
  → Python alert reader thread tails eve.json
  → alerts stored in DB + displayed in CLI
"""

import subprocess
import threading
import json
import os
import time
import signal


class SuricataEngine:
    """Real-time IDS engine using Suricata subprocess.
    
    Usage:
        engine = SuricataEngine(interface='wlo1', log_dir='data/suricata')
        engine.start()
        for alert in engine.tail_alerts():
            print(alert)  # real-time alerts
        engine.stop()
    """

    # Suricata severity mapping (1=highest severity in Suricata)
    SEVERITY_MAP = {
        1: 'CRITICAL',
        2: 'HIGH',
        3: 'MEDIUM',
        4: 'LOW',
    }

    SEVERITY_COLORS = {
        'CRITICAL': '\033[1;91m',  # Bold red
        'HIGH':     '\033[91m',     # Red
        'MEDIUM':   '\033[93m',     # Yellow
        'LOW':      '\033[36m',     # Cyan
    }

    def __init__(self, interface='any', log_dir='data/suricata'):
        self.interface = interface
        self.log_dir = log_dir
        self._process = None
        self._stop_event = threading.Event()
        self._alerts = []          # All alerts from this session
        self._alert_lock = threading.Lock()
        self._alert_callbacks = [] # Callbacks for live display

    def start(self):
        """Launch Suricata as an independent capture process.
        
        Suricata captures from the interface via AF_PACKET (same as dumpcap/tshark)
        and writes alerts to eve.json in the log directory.
        """
        if not self.is_available():
            return False

        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)

        # Remove stale eve.json so we only get fresh alerts
        eve_path = os.path.join(self.log_dir, 'eve.json')
        try:
            if os.path.exists(eve_path):
                os.remove(eve_path)
        except OSError:
            pass

        # Build suricata command
        # -i: capture interface
        # --af-packet: use AF_PACKET (fastest on Linux)
        # -l: log directory
        # -c: config file
        # --set outputs.0.eve-log.types.0.alert.payload=no — skip payload (faster)
        cmd = [
            'suricata',
            '-i', self.interface,
            '--af-packet',
            '-l', self.log_dir,
            '-c', '/etc/suricata/suricata.yaml',
            '--set', 'outputs.0.eve-log.types.0.alert.payload=no',
            '--set', 'outputs.0.eve-log.types.0.alert.payload-printable=no',
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._stop_event.clear()
            return True
        except (FileNotFoundError, PermissionError):
            return False

    def stop(self):
        """Stop Suricata gracefully."""
        self._stop_event.set()
        if self._process:
            try:
                self._process.send_signal(signal.SIGTERM)
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                    self._process.wait(timeout=3)
                except Exception:
                    pass
            self._process = None

    def on_alert(self, callback):
        """Register a callback for real-time alert notifications.
        
        Args:
            callback: function(alert_dict) called for each new alert
        """
        self._alert_callbacks.append(callback)

    def tail_alerts(self):
        """Tail eve.json and yield parsed alert dicts in real-time.
        
        This is a blocking generator — run it in a thread.
        Yields alert dicts with standardized fields.
        """
        eve_path = os.path.join(self.log_dir, 'eve.json')

        # Wait for eve.json to be created (Suricata takes a few seconds to start)
        wait_start = time.time()
        while not os.path.exists(eve_path) and not self._stop_event.is_set():
            if time.time() - wait_start > 30:  # Timeout after 30s
                return
            self._stop_event.wait(0.5)

        if self._stop_event.is_set():
            return

        # Tail the file
        with open(eve_path, 'r') as f:
            while not self._stop_event.is_set():
                line = f.readline()
                if not line:
                    # No new data — wait briefly
                    self._stop_event.wait(0.2)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Only process alert events (skip stats, flow, etc.)
                if event.get('event_type') != 'alert':
                    continue

                alert = self._parse_alert(event)
                if alert:
                    with self._alert_lock:
                        self._alerts.append(alert)
                    # Notify callbacks
                    for cb in self._alert_callbacks:
                        try:
                            cb(alert)
                        except Exception:
                            pass
                    yield alert

    def _parse_alert(self, event):
        """Parse a Suricata eve.json alert event into a standardized dict.
        
        Args:
            event: Raw JSON dict from eve.json
            
        Returns:
            Standardized alert dict or None
        """
        alert_data = event.get('alert', {})
        if not alert_data:
            return None

        severity_num = alert_data.get('severity', 3)
        severity = self.SEVERITY_MAP.get(severity_num, 'LOW')

        return {
            'timestamp': event.get('timestamp', ''),
            'severity': severity,
            'severity_num': severity_num,
            'signature': alert_data.get('signature', 'Unknown'),
            'signature_id': alert_data.get('signature_id', 0),
            'category': alert_data.get('category', ''),
            'src_ip': event.get('src_ip', ''),
            'dst_ip': event.get('dest_ip', ''),
            'src_port': event.get('src_port', 0),
            'dst_port': event.get('dest_port', 0),
            'proto': event.get('proto', ''),
            'action': alert_data.get('action', 'allowed'),
        }

    def get_alerts(self):
        """Get all alerts from this session."""
        with self._alert_lock:
            return list(self._alerts)

    def get_alert_count(self):
        """Get total alert count."""
        with self._alert_lock:
            return len(self._alerts)

    def get_severity_counts(self):
        """Get alert counts by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        with self._alert_lock:
            for alert in self._alerts:
                sev = alert.get('severity', 'LOW')
                counts[sev] = counts.get(sev, 0) + 1
        return counts

    def format_alert_line(self, alert):
        """Format an alert for CLI display.
        
        Returns:
            Colored string like: 🔴 ALERT [HIGH] ET SCAN Nmap (1.2.3.4 → 5.6.7.8:22)
        """
        sev = alert['severity']
        color = self.SEVERITY_COLORS.get(sev, '')
        reset = '\033[0m'

        icon = '🔴' if sev in ('CRITICAL', 'HIGH') else '🟡' if sev == 'MEDIUM' else '🔵'

        src = alert['src_ip']
        dst = alert['dst_ip']
        dst_port = alert.get('dst_port')
        if dst_port:
            dst = f"{dst}:{dst_port}"

        sig = alert['signature']
        # Truncate long signatures
        if len(sig) > 60:
            sig = sig[:57] + '...'

        return f"  {icon} {color}ALERT [{sev}]{reset} {sig} ({src} → {dst})"

    @staticmethod
    def is_available():
        """Check if Suricata is installed."""
        try:
            result = subprocess.run(
                ['suricata', '--build-info'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def has_rules():
        """Check if Suricata rules are installed."""
        rules_path = '/var/lib/suricata/rules/suricata.rules'
        return os.path.exists(rules_path) and os.path.getsize(rules_path) > 0
