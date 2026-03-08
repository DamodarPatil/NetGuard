"""
Behavioral Tagging Engine for FlowSentrix.

Provides 4 statistical/volume-based detectors that complement Suricata's
signature-based detection. These detect patterns Suricata CANNOT:

1. Beaconing     — periodic C2 callbacks (timing analysis)
2. Data Exfil    — large outbound transfers to external IPs
3. New Dest      — first-ever connection to unknown IP
4. Traffic Anomaly — deviation from per-IP rolling baseline

Two trust tiers for IP suppression:
  - TRUSTED: Fully exempt from behavioral alerting (Google, Meta, etc.)
  - SEMI-TRUSTED: Conditional suppression (NAT64, Cloudflare)
    - new_dest / traffic_anomaly: suppress only if < 10MB
    - data_exfil: always alert > 50MB, demote to MEDIUM
    - beaconing: always alert on non-standard ports (not 443/80)
    - Never suppress if unusual protocol

Usage:
    engine = BehaviorEngine(db)
    tags = engine.analyze(flows)   # {flow_key: [(tag, severity, reason), ...]}
"""

import statistics
from typing import Dict, List, Tuple, Optional
from datetime import datetime

# Import tuning config loader
from config import load_tuning_config, is_whitelisted, is_semi_trusted, get_detector_config


# Tag severity levels
SEVERITY_LOW = 'low'
SEVERITY_MEDIUM = 'medium'
SEVERITY_HIGH = 'high'
SEVERITY_CRITICAL = 'critical'

# ─── Default Thresholds (overridden by config/tuning.yaml if present) ───────
BEACON_MIN_CONNECTIONS = 5       # Min connections to same dst to check beaconing
BEACON_CV_THRESHOLD = 0.20       # Coefficient of variation < 0.20 = periodic

EXFIL_MEDIUM_BYTES = 50 * 1024 * 1024    # 50 MB
EXFIL_HIGH_BYTES = 200 * 1024 * 1024     # 200 MB

ANOMALY_MULTIPLIER = 5.0         # Flag if > 5× rolling average

# Private/local IP prefixes (skip for exfil detection)
_PRIVATE_PREFIXES = (
    '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '127.', '169.254.', '0.0.0.0',
    '::', 'fe80:', 'fc', 'fd', 'ff',
)


def _is_private(ip: str) -> bool:
    """Check if an IP is private/local/multicast."""
    if not ip:
        return True
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


class BehaviorEngine:
    """Statistical behavioral analysis engine.

    Analyzes connection flows to detect patterns that signature-based
    engines like Suricata cannot: beaconing, data exfiltration,
    new destinations, and traffic anomalies.

    Loads tuning configuration from config/tuning.yaml and applies
    IP allowlist suppression from config/ip_allowlist.txt.

    Supports two trust tiers:
      - TRUSTED (allowlist_networks): fully exempt
      - SEMI-TRUSTED (semi_trusted_networks): conditional suppression
    """

    def __init__(self, db=None):
        """Initialize the engine.

        Args:
            db: FlowSentrixDatabase instance (for known_destinations lookups)
        """
        self._db = db

        # Load tuning configuration (allowlists, thresholds, severity remap)
        self._config = load_tuning_config()
        self._tuning = self._config.get('tuning', {})
        self._allowlist = self._config.get('allowlist_networks', [])
        self._semi_trusted = self._config.get('semi_trusted_networks', [])
        self._severity_remap = self._config.get('severity_remap', {})

        # Per-detector configs (fall back to defaults if not in YAML)
        self._beacon_cfg = get_detector_config(self._tuning, 'beaconing')
        self._exfil_cfg = get_detector_config(self._tuning, 'data_exfil')
        self._new_dest_cfg = get_detector_config(self._tuning, 'new_dest')
        self._anomaly_cfg = get_detector_config(self._tuning, 'traffic_anomaly')

        # Semi-trusted tier config
        self._semi_cfg = self._tuning.get('semi_trusted', {})

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is FULLY TRUSTED (exempt from all behavioral alerting)."""
        return is_whitelisted(ip, self._allowlist)

    def _is_semi_trusted(self, ip: str) -> bool:
        """Check if an IP is SEMI-TRUSTED (conditional suppression only).

        Semi-trusted IPs (NAT64, Cloudflare) get reduced suppression
        because attackers can abuse these infrastructures.
        """
        return is_semi_trusted(ip, self._semi_trusted)

    def _is_unusual_protocol(self, flow: dict) -> bool:
        """Check if a flow uses an unusual protocol for semi-trusted destinations.

        Standard protocols (TCP, UDP, TLS, QUIC, HTTP, DNS) are expected.
        Anything else (GRE, ICMP tunneling, raw sockets) is suspicious.
        """
        standard = set(p.upper() for p in self._semi_cfg.get('standard_protocols', [
            'TCP', 'UDP', 'TLSv1.2', 'TLSv1.3', 'QUIC', 'HTTP', 'HTTPS', 'DNS'
        ]))
        proto = (flow.get('protocol', '') or '').upper()
        app_proto = (flow.get('application_protocol', '') or '').upper()

        # If either the transport or application protocol is non-standard, flag it
        if proto and proto not in standard:
            return True
        if app_proto and app_proto not in standard:
            return True
        return False

    def _in_learning_period(self) -> bool:
        """Check if we are still within the initial learning period.

        During the learning period, new_dest and traffic_anomaly alerts
        are suppressed or demoted because the baseline is immature.
        """
        global_cfg = self._tuning.get('global', {})
        learning_days = global_cfg.get('learning_period_days', 30)
        deployment_str = global_cfg.get('deployment_date', '')

        if not deployment_str:
            return True  # No deployment date = assume we're still learning

        try:
            deployment = datetime.fromisoformat(deployment_str)
            elapsed = (datetime.now() - deployment).days
            return elapsed < learning_days
        except (ValueError, TypeError):
            return True

    def analyze(self, flows: List[dict], ip_to_domain: Dict[str, str] = None) -> Dict[str, List[Tuple[str, str, str]]]:
        """Run all detectors on a batch of flows.

        Args:
            flows: List of flow dicts from ConnectionTracker.get_flows()
            ip_to_domain: Optional IP→domain mapping from DNS responses
                          (enables CDN-aware beaconing detection)

        Returns:
            Dict mapping flow index → [(tag, severity, reason), ...]
            Only flows with detected behaviors are included.
        """
        if not flows:
            return {}

        all_tags: Dict[int, List[Tuple[str, str, str]]] = {}

        # Run each detector
        detectors = [
            lambda f: self._detect_beaconing(f, ip_to_domain or {}),
            self._detect_data_exfil,
            self._detect_new_destination,
            self._detect_traffic_anomaly,
        ]
        for detector in detectors:
            results = detector(flows)
            for idx, tag, severity, reason in results:
                if idx not in all_tags:
                    all_tags[idx] = []
                all_tags[idx].append((tag, severity, reason))

        return all_tags

    def _detect_beaconing(self, flows: List[dict], ip_to_domain: Dict[str, str] = None) -> List[Tuple[int, str, str, str]]:
        """Detect periodic C2-style beaconing.

        Groups flows by (src_ip, destination) pair. The destination is resolved
        to a domain name via DNS lookups when available, so that CDN-rotated IPs
        are grouped together.

        Tuning applied:
            - Raised min_connections from 5 to 20 (configurable)
            - Suppress beaconing to FULLY TRUSTED IPs (Google, etc.)
            - SEMI-TRUSTED (NAT64, Cloudflare): always alert on non-standard
              ports (not 443/80) or unusual protocols. Suppress only on
              standard ports with standard protocols.
            - CV floor for trusted IPs (CV < 0.05 = keepalive)

        Returns:
            List of (flow_index, 'beaconing', severity, reason)
        """
        results = []
        if ip_to_domain is None:
            ip_to_domain = {}

        # Load tuned thresholds (fall back to defaults)
        min_conns = self._beacon_cfg.get('min_connections', BEACON_MIN_CONNECTIONS)
        cv_threshold = self._beacon_cfg.get('cv_threshold', BEACON_CV_THRESHOLD)
        cv_floor = self._beacon_cfg.get('cv_floor_for_trusted', 0.05)
        suppress_wl = self._beacon_cfg.get('suppress_whitelisted', False)
        always_suppress = set(self._beacon_cfg.get('always_suppress_destinations', []))

        # Semi-trusted beaconing config
        safe_ports = set(self._semi_cfg.get('beaconing_safe_ports', [443, 80]))

        # Group flows by src → destination (domain or IP)
        pairs: Dict[tuple, List[Tuple[int, dict]]] = {}
        for i, flow in enumerate(flows):
            src = flow.get('src_ip', '')
            dst_ip = flow.get('dst_ip', '')
            dst_key = ip_to_domain.get(dst_ip, dst_ip)
            key = (src, dst_key)
            if key not in pairs:
                pairs[key] = []
            pairs[key].append((i, flow))

        for (src, dst), group in pairs.items():
            if len(group) < min_conns:
                continue

            # Skip multicast/broadcast
            if dst.startswith('ff') or dst.startswith('224.') or dst.startswith('239.'):
                continue

            # ── Always-suppress destinations (systemd-resolved, loopback) ──
            raw_dst_ip = group[0][1].get('dst_ip', '')
            if raw_dst_ip in always_suppress or dst in always_suppress:
                continue

            # ── Trust tier check ──
            if suppress_wl and self._is_whitelisted(raw_dst_ip):
                # FULLY TRUSTED — suppress entirely
                continue

            if suppress_wl and self._is_semi_trusted(raw_dst_ip):
                # SEMI-TRUSTED — check port and protocol before suppressing
                # Collect destination ports used in this group
                group_ports = set()
                has_unusual_proto = False
                for _, flow in group:
                    port = flow.get('dst_port')
                    if port is not None:
                        group_ports.add(port)
                    if self._is_unusual_protocol(flow):
                        has_unusual_proto = True

                # Never suppress if unusual protocol
                if not has_unusual_proto:
                    # Only suppress if ALL connections are on standard ports
                    if group_ports and group_ports.issubset(safe_ports):
                        continue
                # Non-standard port or unusual protocol → fall through to alerting

            # Extract start times and sort
            times = []
            for idx, flow in group:
                try:
                    t = datetime.fromisoformat(flow.get('start_time', ''))
                    times.append((t, idx))
                except (ValueError, TypeError):
                    continue

            if len(times) < min_conns:
                continue

            times.sort(key=lambda x: x[0])

            # Deduplicate flows starting within 1 second of each other
            deduped = [times[0]]
            for j in range(1, len(times)):
                if (times[j][0] - deduped[-1][0]).total_seconds() > 1.0:
                    deduped.append(times[j])

            if len(deduped) < min_conns:
                continue

            # Compute inter-connection intervals (seconds)
            intervals = []
            for j in range(1, len(deduped)):
                delta = (deduped[j][0] - deduped[j - 1][0]).total_seconds()
                if delta > 0:
                    intervals.append(delta)

            if len(intervals) < min_conns - 1:
                continue

            # Coefficient of variation = stdev / mean
            mean = statistics.mean(intervals)
            if mean < 1.0:  # Too fast — likely just burst traffic
                continue

            stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev / mean if mean > 0 else float('inf')

            if cv < cv_threshold:
                # ── Tuning: CV floor for FULLY TRUSTED IPs only ──
                if cv < cv_floor and self._is_whitelisted(raw_dst_ip):
                    continue

                display_dst = dst
                reason = (
                    f"{len(deduped)} connections to {display_dst}, "
                    f"interval ~{mean:.1f}s (CV={cv:.3f})"
                )
                for idx, _ in group:
                    results.append((idx, 'beaconing', SEVERITY_HIGH, reason))

        return results

    def _detect_data_exfil(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect large outbound data transfers.

        Aggregates outbound bytes per destination IP across all flows,
        then flags if the total exceeds the threshold.

        Tuning applied:
            - Thresholds: 200MB (medium) / 500MB (high) for unknown destinations
            - FULLY TRUSTED: suppress entirely (Google Drive sync is legitimate)
            - SEMI-TRUSTED (NAT64, Cloudflare): always alert above 50MB,
              but demote severity to MEDIUM instead of HIGH. Never fully suppress.
            - Never suppress if unusual protocol to semi-trusted

        Returns:
            List of (flow_index, 'data_exfil', severity, reason)
        """
        results = []

        # Load tuned thresholds (fall back to defaults)
        medium_bytes = self._exfil_cfg.get('threshold_medium_bytes', EXFIL_MEDIUM_BYTES)
        high_bytes = self._exfil_cfg.get('threshold_high_bytes', EXFIL_HIGH_BYTES)
        suppress_wl = self._exfil_cfg.get('suppress_whitelisted', False)

        # Semi-trusted exfil config
        semi_exfil_threshold = self._semi_cfg.get('exfil_always_alert_bytes', 50 * 1024 * 1024)
        semi_exfil_severity = self._semi_cfg.get('exfil_demoted_severity', SEVERITY_MEDIUM)

        # Aggregate outbound bytes per destination
        dst_bytes: Dict[str, int] = {}
        dst_flows: Dict[str, List[int]] = {}
        dst_has_unusual_proto: Dict[str, bool] = {}

        for i, flow in enumerate(flows):
            if flow.get('direction', '') != 'OUTGOING':
                continue

            dst_ip = flow.get('dst_ip', '')
            if _is_private(dst_ip):
                continue

            # ── FULLY TRUSTED: suppress entirely ──
            if suppress_wl and self._is_whitelisted(dst_ip):
                continue

            # (Semi-trusted is NOT suppressed here — we aggregate and check below)

            dst_bytes[dst_ip] = dst_bytes.get(dst_ip, 0) + flow.get('total_bytes', 0)
            if dst_ip not in dst_flows:
                dst_flows[dst_ip] = []
                dst_has_unusual_proto[dst_ip] = False
            dst_flows[dst_ip].append(i)
            if self._is_unusual_protocol(flow):
                dst_has_unusual_proto[dst_ip] = True

        # Check aggregated totals
        for dst_ip, total_bytes in dst_bytes.items():
            is_semi = self._is_semi_trusted(dst_ip)

            if is_semi:
                # ── SEMI-TRUSTED: always alert above 50 MB ──
                # Demote severity to MEDIUM instead of suppressing
                if total_bytes >= semi_exfil_threshold:
                    mb = total_bytes / (1024 * 1024)
                    reason = f"{mb:.1f} MB uploaded to {dst_ip} (semi-trusted)"

                    # Use demoted severity unless unusual protocol (keep HIGH)
                    if dst_has_unusual_proto.get(dst_ip, False):
                        sev = SEVERITY_HIGH
                    else:
                        sev = semi_exfil_severity

                    for idx in dst_flows[dst_ip]:
                        results.append((idx, 'data_exfil', sev, reason))
            else:
                # ── Unknown destination: use normal thresholds ──
                if total_bytes >= high_bytes:
                    mb = total_bytes / (1024 * 1024)
                    reason = f"{mb:.1f} MB uploaded to {dst_ip}"
                    for idx in dst_flows[dst_ip]:
                        results.append((idx, 'data_exfil', SEVERITY_HIGH, reason))
                elif total_bytes >= medium_bytes:
                    mb = total_bytes / (1024 * 1024)
                    reason = f"{mb:.1f} MB uploaded to {dst_ip}"
                    for idx in dst_flows[dst_ip]:
                        results.append((idx, 'data_exfil', SEVERITY_MEDIUM, reason))

        return results

    def _detect_new_destination(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect connections to never-before-seen IPs.

        Tuning applied:
            - During learning period: demote to INFO
            - FULLY TRUSTED: always suppress
            - SEMI-TRUSTED (NAT64, Cloudflare): suppress only if transfer < 10MB.
              Never suppress if unusual protocol.
            - After learning: only alert on non-HTTPS ports

        Returns:
            List of (flow_index, 'new_dest', severity, reason)
        """
        results = []

        if not self._db:
            return results

        # ── During learning period, demote severity to INFO ──
        in_learning = self._in_learning_period()
        learning_severity = self._new_dest_cfg.get('learning_period_severity', 'low')

        suppress_wl = self._new_dest_cfg.get('suppress_whitelisted', False)
        https_only_suppress = self._new_dest_cfg.get('post_learning_https_only_suppress', False)

        # Semi-trusted config
        semi_max_bytes = self._semi_cfg.get('suppress_max_bytes', 10 * 1024 * 1024)

        # Collect unique destination IPs from flows
        dst_ips = set()
        for flow in flows:
            dst = flow.get('dst_ip', '')
            if dst and not _is_private(dst):
                dst_ips.add(dst)

        if not dst_ips:
            return results

        # Check which are known
        known = self._db.get_known_destinations(dst_ips)

        for i, flow in enumerate(flows):
            dst = flow.get('dst_ip', '')
            if dst and not _is_private(dst) and dst not in known:
                # ── FULLY TRUSTED: suppress always ──
                if suppress_wl and self._is_whitelisted(dst):
                    continue

                # ── SEMI-TRUSTED: suppress only if < 10 MB and standard protocol ──
                if suppress_wl and self._is_semi_trusted(dst):
                    flow_bytes = flow.get('total_bytes', 0)
                    if flow_bytes < semi_max_bytes and not self._is_unusual_protocol(flow):
                        continue
                    # Above 10 MB or unusual protocol → fall through to alerting

                # ── After learning, only alert on non-HTTPS ports ──
                if not in_learning and https_only_suppress:
                    dst_port = flow.get('dst_port')
                    if dst_port in (443, 80):
                        continue

                # Use demoted severity during learning period
                severity = learning_severity if in_learning else SEVERITY_LOW

                results.append((
                    i, 'new_dest', severity,
                    f"First connection to {dst}"
                ))

        return results

    def _detect_traffic_anomaly(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect traffic volume anomalies per destination IP.

        Tuning applied:
            - Minimum absolute threshold (10 MB)
            - Minimum baseline age (14 days)
            - FULLY TRUSTED: suppress unconditionally
            - SEMI-TRUSTED (NAT64, Cloudflare): suppress only if < 10 MB.
              Never suppress if unusual protocol.

        Returns:
            List of (flow_index, 'traffic_anomaly', severity, reason)
        """
        results = []

        if not self._db:
            return results

        # Load tuned thresholds (fall back to defaults)
        multiplier = self._anomaly_cfg.get('multiplier', ANOMALY_MULTIPLIER)
        min_abs_bytes = self._anomaly_cfg.get('min_absolute_bytes', 0)
        suppress_wl = self._anomaly_cfg.get('suppress_whitelisted', False)

        # Semi-trusted config
        semi_max_bytes = self._semi_cfg.get('suppress_max_bytes', 10 * 1024 * 1024)

        # Aggregate bytes per destination in this batch
        dst_bytes: Dict[str, int] = {}
        dst_flows: Dict[str, List[int]] = {}
        dst_has_unusual_proto: Dict[str, bool] = {}

        for i, flow in enumerate(flows):
            dst = flow.get('dst_ip', '')
            if not dst or _is_private(dst):
                continue

            # ── FULLY TRUSTED: suppress unconditionally ──
            if suppress_wl and self._is_whitelisted(dst):
                continue

            # (Semi-trusted is NOT suppressed here — check below after aggregation)

            dst_bytes[dst] = dst_bytes.get(dst, 0) + flow.get('total_bytes', 0)
            if dst not in dst_flows:
                dst_flows[dst] = []
                dst_has_unusual_proto[dst] = False
            dst_flows[dst].append(i)
            if self._is_unusual_protocol(flow):
                dst_has_unusual_proto[dst] = True

        if not dst_bytes:
            return results

        # Get rolling averages from DB
        averages = self._db.get_destination_averages(set(dst_bytes.keys()))

        for dst_ip, current_bytes in dst_bytes.items():
            # ── Minimum absolute bytes threshold ──
            if current_bytes < min_abs_bytes:
                continue

            # ── SEMI-TRUSTED: suppress only if < 10 MB and standard protocol ──
            if self._is_semi_trusted(dst_ip):
                if current_bytes < semi_max_bytes and not dst_has_unusual_proto.get(dst_ip, False):
                    continue
                # Above 10 MB or unusual protocol → fall through to alerting

            avg = averages.get(dst_ip)
            if avg is None or avg < 1024:  # Skip if no baseline or too small
                continue

            ratio = current_bytes / avg
            if ratio >= multiplier:
                mb_current = current_bytes / (1024 * 1024)
                mb_avg = avg / (1024 * 1024)
                reason = (
                    f"{dst_ip}: {mb_current:.1f} MB this session "
                    f"vs {mb_avg:.1f} MB average ({ratio:.1f}×)"
                )
                for idx in dst_flows.get(dst_ip, []):
                    results.append((idx, 'traffic_anomaly', SEVERITY_MEDIUM, reason))

        return results
