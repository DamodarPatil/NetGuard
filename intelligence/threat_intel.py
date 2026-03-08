"""
Threat Intelligence module for FlowSentrix.

Provides IP reputation checking via AbuseIPDB API (free tier: 1K checks/day).
Results are cached in the database to avoid redundant API calls.

Usage:
    checker = ThreatIntelChecker(db)
    checker.set_api_key('your-key-here')
    result = checker.check_ip('1.2.3.4')
    # → {'abuse_score': 85, 'country': 'RU', 'isp': 'Evil Corp', ...}
"""

import threading
import time
import json
import os
from typing import Optional, Dict

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


def _get_user_home():
    """Get the real user's home directory, even under sudo."""
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user:
        import pwd
        return pwd.getpwnam(sudo_user).pw_dir
    return os.path.expanduser('~')

CONFIG_DIR = os.path.join(_get_user_home(), '.flowsentrix')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')

# AbuseIPDB API endpoint
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'


class ThreatIntelChecker:
    """Background IP reputation checker using AbuseIPDB.
    
    Features:
      - Checks IPs against AbuseIPDB (free: 1K checks/day)
      - Caches results in SQLite to avoid re-checking
      - Runs checks in background thread (non-blocking)
      - Graceful degradation: no API key = feature disabled
    """

    def __init__(self, db=None):
        self._db = db
        self._api_key = self._load_api_key()
        self._check_queue = []
        self._queue_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._checked_ips = set()  # Session cache to avoid duplicate checks

    def _load_api_key(self):
        """Load API key from config file."""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    return config.get('abuseipdb_api_key', '')
        except Exception:
            pass
        return ''

    def set_api_key(self, key):
        """Set and persist the AbuseIPDB API key."""
        self._api_key = key
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            config = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
            config['abuseipdb_api_key'] = key
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def is_configured(self):
        """Check if an API key is set."""
        return bool(self._api_key)

    def check_ip(self, ip: str) -> Optional[Dict]:
        """Check an IP against AbuseIPDB.
        
        Returns:
            Dict with abuse_score, country, isp etc. or None on failure.
        """
        if not self._api_key or not HAS_URLLIB:
            return None

        # Check DB cache first
        if self._db:
            cached = self._db.get_ip_reputation(ip)
            if cached:
                return cached

        try:
            url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url)
            req.add_header('Key', self._api_key)
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

            result = data.get('data', {})
            abuse_score = result.get('abuseConfidenceScore', 0)
            country = result.get('countryCode', '')
            isp = result.get('isp', '')

            # Cache in DB
            if self._db:
                self._db.cache_ip_reputation(ip, abuse_score, country, isp)

            return {
                'abuse_score': abuse_score,
                'country': country,
                'isp': isp,
                'is_malicious': abuse_score > 50,
            }
        except Exception:
            return None

    def queue_check(self, ip: str):
        """Queue an IP for background checking (non-blocking)."""
        # Skip private/local IPs
        if self._is_private(ip):
            return
        if ip in self._checked_ips:
            return
        self._checked_ips.add(ip)

        with self._queue_lock:
            self._check_queue.append(ip)

    def start_background(self):
        """Start background checking thread."""
        if not self._api_key:
            return
        self._stop_event.clear()
        t = threading.Thread(
            target=self._background_worker,
            name='FlowSentrix-ThreatIntel',
            daemon=True
        )
        t.start()

    def stop(self):
        """Stop background checking."""
        self._stop_event.set()

    def _background_worker(self):
        """Process queued IPs in the background, rate-limited."""
        while not self._stop_event.is_set():
            ip = None
            with self._queue_lock:
                if self._check_queue:
                    ip = self._check_queue.pop(0)

            if ip:
                self.check_ip(ip)
                # Rate limit: ~4 req/sec to stay well under free tier
                time.sleep(0.25)
            else:
                self._stop_event.wait(1.0)

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if an IP is private/local."""
        if not ip:
            return True
        return (ip.startswith('10.') or
                ip.startswith('192.168.') or
                ip.startswith('172.16.') or ip.startswith('172.17.') or
                ip.startswith('172.18.') or ip.startswith('172.19.') or
                ip.startswith('172.2') or ip.startswith('172.3') or
                ip.startswith('127.') or
                ip.startswith('169.254.') or
                ip == '0.0.0.0' or
                ip.startswith('::') or ip.startswith('fe80:') or
                ip.startswith('fc') or ip.startswith('fd'))
