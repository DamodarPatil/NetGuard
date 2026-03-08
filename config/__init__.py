"""
FlowSentrix Configuration Loader.

Loads tuning YAML configs from the config/ directory and provides
utilities for IP allowlist matching (CIDR-based).

Supports two trust tiers:
  - TRUSTED: Fully exempt from behavioral alerting (Google, Meta, etc.)
  - SEMI-TRUSTED: Conditional suppression only (NAT64, Cloudflare)

Usage:
    from config import load_tuning_config, is_whitelisted, is_semi_trusted

    cfg = load_tuning_config()
    if is_whitelisted("2404:6800:4009::200e", cfg['allowlist_networks']):
        print("Google IP — fully trusted, skip all behavioral alerting")
    elif is_semi_trusted("2606:4700::1", cfg['semi_trusted_networks']):
        print("Cloudflare IP — semi-trusted, apply conditional rules")
"""

import os
import ipaddress
from typing import Dict, Any, List, Set

try:
    import yaml
except ImportError:
    yaml = None


# Base directory for config files (relative to project root)
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_CONFIG_DIR)


def _load_yaml(filename: str) -> dict:
    """Load a YAML file from the config directory.

    Args:
        filename: Name of the YAML file (e.g. 'tuning.yaml')

    Returns:
        Parsed dict, or empty dict if file not found or PyYAML missing.
    """
    if yaml is None:
        return {}

    path = os.path.join(_CONFIG_DIR, filename)
    if not os.path.exists(path):
        return {}

    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_allowlist_file():
    """Load CIDR entries from ip_allowlist.txt, separating trusted and semi-trusted.

    The file supports section headers:
      # [TRUSTED] — fully exempt from behavioral alerting
      # [SEMI-TRUSTED] — conditional suppression only

    Returns:
        Tuple of (trusted_networks, semi_trusted_networks)
    """
    path = os.path.join(_CONFIG_DIR, 'ip_allowlist.txt')
    trusted = []
    semi_trusted = []

    if not os.path.exists(path):
        return trusted, semi_trusted

    current_section = 'trusted'  # Default section

    try:
        with open(path, 'r') as f:
            for line in f:
                stripped = line.strip()

                # Skip empty lines
                if not stripped:
                    continue

                # Check for section headers
                upper = stripped.upper()
                if upper.startswith('# [TRUSTED]') or upper.startswith('#[TRUSTED]'):
                    current_section = 'trusted'
                    continue
                elif upper.startswith('# [SEMI-TRUSTED]') or upper.startswith('#[SEMI-TRUSTED]'):
                    current_section = 'semi_trusted'
                    continue

                # Skip pure comments
                if stripped.startswith('#'):
                    continue

                # Strip inline comments
                cidr = stripped.split('#')[0].strip()
                if not cidr:
                    continue

                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if current_section == 'semi_trusted':
                        semi_trusted.append(net)
                    else:
                        trusted.append(net)
                except ValueError:
                    continue  # Skip malformed entries
    except Exception:
        pass

    return trusted, semi_trusted


def _check_ip_in_networks(ip_str: str, networks: list) -> bool:
    """Check if an IP address falls within any network in the list.

    Args:
        ip_str: IP address string (IPv4 or IPv6)
        networks: List of ipaddress network objects

    Returns:
        True if the IP matches any range.
    """
    if not ip_str or not networks:
        return False

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for net in networks:
        try:
            if addr in net:
                return True
        except TypeError:
            # IPv4 address vs IPv6 network or vice versa — skip
            continue

    return False


def is_whitelisted(ip_str: str, networks: list) -> bool:
    """Check if an IP is in the FULLY TRUSTED allowlist.

    These IPs are exempt from all behavioral alerting.
    """
    return _check_ip_in_networks(ip_str, networks)


def is_semi_trusted(ip_str: str, networks: list) -> bool:
    """Check if an IP is in the SEMI-TRUSTED list.

    Semi-trusted IPs get conditional suppression — not blanket exemption.
    Rules for semi-trusted IPs:
      - new_dest / traffic_anomaly: suppress only if transfer < 10 MB
      - data_exfil: always alert above 50 MB, but demote to MEDIUM
      - beaconing: always alert on non-standard ports (not 443/80)
      - Never suppress if unusual protocol
    """
    return _check_ip_in_networks(ip_str, networks)


def load_tuning_config() -> Dict[str, Any]:
    """Load the complete tuning configuration.

    Returns:
        Dict with keys:
            'tuning': parsed tuning.yaml
            'severity_remap': parsed severity_remap.yaml
            'do_not_suppress': parsed do_not_suppress.yaml
            'allowlist_networks': list of FULLY TRUSTED network objects
            'semi_trusted_networks': list of SEMI-TRUSTED network objects
    """
    trusted, semi_trusted = _parse_allowlist_file()
    return {
        'tuning': _load_yaml('tuning.yaml'),
        'severity_remap': _load_yaml('severity_remap.yaml'),
        'do_not_suppress': _load_yaml('do_not_suppress.yaml'),
        'allowlist_networks': trusted,
        'semi_trusted_networks': semi_trusted,
    }


def get_detector_config(tuning: dict, detector_name: str) -> dict:
    """Get configuration for a specific detector from tuning config.

    Args:
        tuning: The 'tuning' dict from load_tuning_config()
        detector_name: One of 'beaconing', 'data_exfil', 'new_dest', 'traffic_anomaly'

    Returns:
        Detector-specific config dict, or empty dict if not found.
    """
    return tuning.get(detector_name, {})
