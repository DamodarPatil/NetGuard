#!/usr/bin/env python3
"""
FlowSentrix - Network Traffic Analyzer & Monitor
Interactive CLI Shell

Usage:
    sudo python3 flowsentrix.py
"""
import sys
import os

# ── Ensure venv packages are available even under sudo ──
# When running with `sudo python3 flowsentrix.py`, Python uses system site-packages
# instead of the venv. This adds the venv's site-packages to sys.path.
_project_dir = os.path.dirname(os.path.abspath(__file__))
_venv_site = os.path.join(_project_dir, "venv", "lib")
if os.path.isdir(_venv_site):
    # Find the python3.x directory inside venv/lib/
    for entry in os.listdir(_venv_site):
        sp = os.path.join(_venv_site, entry, "site-packages")
        if os.path.isdir(sp) and sp not in sys.path:
            sys.path.insert(0, sp)

# Add project root to path
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)

from cli.shell import FlowSentrixShell


def main():
    try:
        shell = FlowSentrixShell()
        shell.cmdloop()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
