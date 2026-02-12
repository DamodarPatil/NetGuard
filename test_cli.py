#!/usr/bin/env python3
"""
NetGuard CLI — Exhaustive Test Suite
Tests every command, subcommand, edge case, and error path.
"""
import sys
import os
import io
import traceback
from contextlib import redirect_stdout, redirect_stderr

# ── Venv path injection (same as netguard.py) ──
_project_dir = os.path.dirname(os.path.abspath(__file__))
_venv_site = os.path.join(_project_dir, "venv", "lib")
if os.path.isdir(_venv_site):
    for entry in os.listdir(_venv_site):
        sp = os.path.join(_venv_site, entry, "site-packages")
        if os.path.isdir(sp) and sp not in sys.path:
            sys.path.insert(0, sp)
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)

from cli.shell import NetGuardShell
from cli.display import console
import re

# ── Helpers ──
PASS = 0
FAIL = 0
BUGS = []

def strip_ansi(text):
    """Strip ANSI escape codes from Rich output for plain text comparison."""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def run_cmd(shell, cmd, expect_in=None, expect_not_in=None, label=None):
    """Run a shell command, capture output, and check expectations."""
    global PASS, FAIL, BUGS
    label = label or cmd
    
    buf = io.StringIO()
    old_file = console.file
    console.file = buf  # Redirect Rich console output
    
    old_stdout = sys.stdout
    sys.stdout = buf  # Redirect plain print output
    
    # cmd.Cmd uses self.stdout for help output (not sys.stdout)
    old_shell_stdout = shell.stdout
    shell.stdout = buf
    
    error = None
    try:
        shell.onecmd(cmd)
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    finally:
        console.file = old_file
        sys.stdout = old_stdout
        shell.stdout = old_shell_stdout
    
    output = strip_ansi(buf.getvalue())
    
    # Check for unexpected exceptions
    if error:
        FAIL += 1
        msg = f"CRASH on '{label}': {error}"
        BUGS.append(msg)
        print(f"  ✗ {label}")
        print(f"    EXCEPTION: {error}")
        return output
    
    # Check expected substrings present
    if expect_in:
        if isinstance(expect_in, str):
            expect_in = [expect_in]
        for substr in expect_in:
            if substr not in output:
                FAIL += 1
                msg = f"'{label}' — expected '{substr}' in output but not found"
                BUGS.append(msg)
                print(f"  ✗ {label}")
                print(f"    EXPECTED: '{substr}'")
                print(f"    OUTPUT: {output[:300]}")
                return output
    
    # Check unexpected substrings absent
    if expect_not_in:
        if isinstance(expect_not_in, str):
            expect_not_in = [expect_not_in]
        for substr in expect_not_in:
            if substr in output:
                FAIL += 1
                msg = f"'{label}' — unexpected '{substr}' found in output"
                BUGS.append(msg)
                print(f"  ✗ {label}")
                print(f"    UNEXPECTED: '{substr}'")
                return output
    
    PASS += 1
    print(f"  ✓ {label}")
    return output


def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


# ═══════════════════════════════════════════════════════════
#  INIT
# ═══════════════════════════════════════════════════════════
print("=" * 60)
print("  NetGuard CLI — Exhaustive Test Suite")
print("=" * 60)

shell = NetGuardShell()
print(f"\n  Shell initialized. Interface: {shell.interface}")
print(f"  DB packets: {shell._get_db_packet_count()}")


# ═══════════════════════════════════════════════════════════
#  1. HELP COMMANDS
# ═══════════════════════════════════════════════════════════
section("1. HELP COMMANDS")

run_cmd(shell, "help", expect_in=["CAPTURE", "DISPLAY", "SEARCH", "CONFIG", "EXPORT"])
# Note: help <cmd> uses cmd.Cmd's built-in which prints docstrings to stdout.
# Our run_cmd captures stdout too, so these should work:
run_cmd(shell, "help capture", expect_in=["capture start"])
run_cmd(shell, "help show", expect_in=["show stats"])
run_cmd(shell, "help search", expect_in=["search ip"])
run_cmd(shell, "help set", expect_in=["set interface"])
run_cmd(shell, "help export", expect_in=["export csv"])
run_cmd(shell, "help clear")
run_cmd(shell, "help exit")
run_cmd(shell, "help nonexistent", label="help nonexistent (unknown cmd)")


# ═══════════════════════════════════════════════════════════
#  2. SHOW COMMANDS — VALID
# ═══════════════════════════════════════════════════════════
section("2. SHOW COMMANDS — Valid")

run_cmd(shell, "show", expect_in="Usage")
run_cmd(shell, "show config", expect_in=["Interface", "Database"])
run_cmd(shell, "show interfaces", expect_in="Available Interfaces")
run_cmd(shell, "show stats")
run_cmd(shell, "show recent", label="show recent (default 20)")
run_cmd(shell, "show recent 5", label="show recent 5")
run_cmd(shell, "show recent 1", label="show recent 1")
run_cmd(shell, "show top-talkers", label="show top-talkers (default 10)")
run_cmd(shell, "show top-talkers 3", label="show top-talkers 3")
run_cmd(shell, "show talkers", label="show talkers (alias)")


# ═══════════════════════════════════════════════════════════
#  3. SHOW COMMANDS — INVALID / EDGE CASES
# ═══════════════════════════════════════════════════════════
section("3. SHOW COMMANDS — Invalid / Edge Cases")

run_cmd(shell, "show recent -1", expect_in="positive", label="show recent -1 (negative)")
run_cmd(shell, "show recent 0", expect_in="positive", label="show recent 0 (zero)")
run_cmd(shell, "show recent abc", expect_in="Invalid", label="show recent abc (non-numeric)")
run_cmd(shell, "show recent 99999", label="show recent 99999 (very large)")
run_cmd(shell, "show top-talkers -5", expect_in="positive", label="show top-talkers -5 (negative)")
run_cmd(shell, "show top-talkers 0", expect_in="positive", label="show top-talkers 0 (zero)")
run_cmd(shell, "show top-talkers abc", expect_in="Invalid", label="show top-talkers abc (non-numeric)")
run_cmd(shell, "show blah", expect_in="Unknown", label="show blah (unknown subcommand)")
run_cmd(shell, "show recent 5 extra_args", label="show recent 5 extra_args (extra args)")


# ═══════════════════════════════════════════════════════════
#  4. SEARCH COMMANDS — VALID
# ═══════════════════════════════════════════════════════════
section("4. SEARCH COMMANDS — Valid")

run_cmd(shell, "search", expect_in="Usage")
run_cmd(shell, "search ip 10.19.54.96", expect_in="Searching for IP")
run_cmd(shell, "search proto DNS", expect_in="Searching for protocol")
run_cmd(shell, "search proto TCP", expect_in="Searching for protocol")
run_cmd(shell, "search protocol TLS", expect_in="Searching for protocol", label="search protocol (alias)")
run_cmd(shell, "search port 443", expect_in="Searching for port")
run_cmd(shell, "search port 53", expect_in="Searching for port")


# ═══════════════════════════════════════════════════════════
#  5. SEARCH COMMANDS — INVALID / EDGE CASES
# ═══════════════════════════════════════════════════════════
section("5. SEARCH COMMANDS — Invalid / Edge Cases")

run_cmd(shell, "search ip", expect_in="Usage", label="search ip (no value)")
run_cmd(shell, "search port abc", expect_in="Invalid port", label="search port abc (non-numeric)")
run_cmd(shell, "search port -1", expect_in="0-65535", label="search port -1 (negative)")
run_cmd(shell, "search port 99999", expect_in="0-65535", label="search port 99999 (too large)")
run_cmd(shell, "search port 0", expect_in="Searching for port", label="search port 0 (zero — valid)")
run_cmd(shell, "search port 65535", expect_in="Searching for port", label="search port 65535 (max valid)")
run_cmd(shell, "search blah value", expect_in="Unknown", label="search blah (unknown subtype)")
run_cmd(shell, "search ip 999.999.999.999", expect_in="Searching for IP", label="search ip 999.999.999.999 (invalid IP format)")
run_cmd(shell, "search ip ''", label="search ip '' (empty-ish)")
run_cmd(shell, "search proto ''", label="search proto '' (empty-ish)")


# ═══════════════════════════════════════════════════════════
#  6. SET COMMANDS — VALID
# ═══════════════════════════════════════════════════════════
section("6. SET COMMANDS — Valid")

run_cmd(shell, "set", expect_in="Usage")
run_cmd(shell, "set interface wlo1", expect_in="Interface set to")
run_cmd(shell, "set csv /tmp/test.csv", expect_in="CSV export set to")
run_cmd(shell, "set csv /tmp/my test file.csv", expect_in="my test file.csv", label="set csv with spaces")
run_cmd(shell, "set count 100", expect_in="100")
run_cmd(shell, "set count 0", expect_in="unlimited")
run_cmd(shell, "set display on", expect_in="on")
run_cmd(shell, "set display off", expect_in="off")
run_cmd(shell, "set display true", expect_in="on", label="set display true (alias)")
run_cmd(shell, "set display false", expect_in="off", label="set display false (alias)")
run_cmd(shell, "set display yes", expect_in="on", label="set display yes (alias)")
run_cmd(shell, "set display no", expect_in="off", label="set display no (alias)")
run_cmd(shell, "set display 1", expect_in="on", label="set display 1 (alias)")
run_cmd(shell, "set display 0", expect_in="off", label="set display 0 (alias)")
run_cmd(shell, "set db data/netguard.db", expect_in="Database set to")


# ═══════════════════════════════════════════════════════════
#  7. SET COMMANDS — INVALID / EDGE CASES
# ═══════════════════════════════════════════════════════════
section("7. SET COMMANDS — Invalid / Edge Cases")

run_cmd(shell, "set interface fake0", expect_in="Unknown interface", label="set interface fake0 (nonexistent)")
run_cmd(shell, "set interface", expect_in="Usage", label="set interface (no value)")
run_cmd(shell, "set count -10", expect_in="must be >= 0", label="set count -10 (negative)")
run_cmd(shell, "set count abc", expect_in="Invalid", label="set count abc (non-numeric)")
run_cmd(shell, "set count 1.5", expect_in="Invalid", label="set count 1.5 (float)")
run_cmd(shell, "set display maybe", expect_in="Invalid value", label="set display maybe (invalid bool)")
run_cmd(shell, "set display", expect_in="Usage", label="set display (no value)")
run_cmd(shell, "set blah value", expect_in="Unknown setting", label="set blah (unknown setting)")
run_cmd(shell, "set count 999999999999", label="set count huge (very large)")


# ═══════════════════════════════════════════════════════════
#  8. EXPORT COMMANDS
# ═══════════════════════════════════════════════════════════
section("8. EXPORT COMMANDS")

run_cmd(shell, "export", expect_in="Usage")
run_cmd(shell, "export csv /tmp/netguard_test_export.csv", expect_in="Exported")
run_cmd(shell, "export csv", expect_in="Usage", label="export csv (no file)")
run_cmd(shell, "export json file.json", expect_in="Unknown format", label="export json (unsupported)")

# Verify export file
if os.path.exists("/tmp/netguard_test_export.csv"):
    import csv
    with open("/tmp/netguard_test_export.csv") as f:
        reader = csv.reader(f)
        header = next(reader)
        row_count = sum(1 for _ in reader)
    PASS += 1
    print(f"  ✓ Export file verified: {len(header)} columns, {row_count} rows")
    os.unlink("/tmp/netguard_test_export.csv")
else:
    FAIL += 1
    BUGS.append("Export file was not created")
    print(f"  ✗ Export file was NOT created")


# ═══════════════════════════════════════════════════════════
#  9. CAPTURE COMMANDS — WITHOUT CAPTURE RUNNING
# ═══════════════════════════════════════════════════════════
section("9. CAPTURE COMMANDS — No Active Capture")

run_cmd(shell, "capture", expect_in="Usage")
run_cmd(shell, "capture blah", expect_in="Unknown", label="capture blah (invalid subcommand)")


# ═══════════════════════════════════════════════════════════
#  10. OTHER / GENERAL COMMANDS
# ═══════════════════════════════════════════════════════════
section("10. OTHER / GENERAL COMMANDS")

run_cmd(shell, "clear", label="clear (no crash)")
run_cmd(shell, "", label="empty input (no crash)")
run_cmd(shell, "   ", label="whitespace-only input")
run_cmd(shell, "nonexistent_cmd", expect_in="Unknown command")
run_cmd(shell, "ls", expect_in="Unknown command", label="ls (shell passthrough)")
run_cmd(shell, "cat /etc/passwd", expect_in="Unknown command", label="cat /etc/passwd (security)")
run_cmd(shell, "!ls", label="! prefix (no crash)")


# ═══════════════════════════════════════════════════════════
#  11. SPECIAL CHARACTERS / INJECTION
# ═══════════════════════════════════════════════════════════
section("11. Special Characters / Injection")

run_cmd(shell, "search ip ; ls", label="search ip ; ls (command injection)")
run_cmd(shell, "search ip $(whoami)", label="search ip $(whoami) (subshell)")
run_cmd(shell, "search proto ' OR 1=1 --", label="search proto SQL injection attempt")
run_cmd(shell, "set csv /tmp/'; DROP TABLE packets; --", label="set csv SQL injection in path")
run_cmd(shell, "search port 443; ls", expect_in=["Invalid port"], label="search port with semicolon")
run_cmd(shell, 'search ip "test"', label='search ip with quotes')


# ═══════════════════════════════════════════════════════════
#  12. TAB COMPLETION
# ═══════════════════════════════════════════════════════════
section("12. TAB COMPLETION")

def test_completion(shell, method, text, line, expected_items, label):
    global PASS, FAIL, BUGS
    try:
        result = method(text, line, 0, len(line))
        if result is None:
            result = []
        for item in expected_items:
            if item not in result:
                FAIL += 1
                msg = f"Tab completion '{label}' — missing '{item}', got {result}"
                BUGS.append(msg)
                print(f"  ✗ {label} — missing '{item}', got {result}")
                return
        PASS += 1
        print(f"  ✓ {label} → {result}")
    except Exception as e:
        FAIL += 1
        msg = f"Tab completion '{label}' crashed: {e}"
        BUGS.append(msg)
        print(f"  ✗ {label} CRASHED: {e}")

test_completion(shell, shell.complete_capture, "", "capture ", ["start"], "capture <TAB>")
test_completion(shell, shell.complete_capture, "st", "capture st", ["start"], "capture st<TAB>")
test_completion(shell, shell.complete_capture, "sta", "capture sta", ["start"], "capture sta<TAB>")
test_completion(shell, shell.complete_show, "", "show ", ["stats", "recent", "top-talkers", "interfaces", "config"], "show <TAB>")
test_completion(shell, shell.complete_show, "s", "show s", ["stats"], "show s<TAB>")
test_completion(shell, shell.complete_search, "", "search ", ["ip", "proto", "port"], "search <TAB>")
test_completion(shell, shell.complete_set, "", "set ", ["interface", "csv", "count", "display", "db"], "set <TAB>")
test_completion(shell, shell.complete_set, "int", "set int", ["interface"], "set int<TAB>")
test_completion(shell, shell.complete_export, "", "export ", ["csv"], "export <TAB>")

# Tab complete interface names
test_completion(shell, shell.complete_set, "", "set interface ", ["wlo1"], "set interface <TAB>")
test_completion(shell, shell.complete_set, "w", "set interface w", ["wlo1"], "set interface w<TAB>")

# Tab complete display values
test_completion(shell, shell.complete_set, "", "set display ", ["on", "off"], "set display <TAB>")
test_completion(shell, shell.complete_set, "o", "set display o", ["on", "off"], "set display o<TAB>")

# Edge: completion with unknown prefix
test_completion(shell, shell.complete_capture, "xyz", "capture xyz", [], "capture xyz<TAB> (no match)")
test_completion(shell, shell.complete_set, "xyz", "set xyz", [], "set xyz<TAB> (no match)")


# ═══════════════════════════════════════════════════════════
#  13. DATABASE EDGE CASES
# ═══════════════════════════════════════════════════════════
section("13. DATABASE EDGE CASES")

# Temporarily set bad DB path
old_db = shell.db_path
shell.db_path = "/tmp/nonexistent_netguard_test.db"
shell._init_db()

run_cmd(shell, "show stats", label="show stats (empty new DB)")
run_cmd(shell, "show recent", label="show recent (empty new DB)")
run_cmd(shell, "search ip 1.1.1.1", label="search ip (empty new DB)")
run_cmd(shell, "export csv /tmp/netguard_empty_test.csv", label="export csv (empty new DB)")

# Restore
shell.db_path = old_db
shell._init_db()
if os.path.exists("/tmp/nonexistent_netguard_test.db"):
    os.unlink("/tmp/nonexistent_netguard_test.db")
if os.path.exists("/tmp/netguard_empty_test.csv"):
    os.unlink("/tmp/netguard_empty_test.csv")

# Test with None database
shell._db = None
run_cmd(shell, "show stats", expect_in=["no database available"], label="show stats (no DB connection)")
run_cmd(shell, "show recent", expect_in=["Database not available"], label="show recent (no DB connection)")
run_cmd(shell, "search ip 1.1.1.1", expect_in=["Database not available"], label="search ip (no DB connection)")
run_cmd(shell, "export csv /tmp/test.csv", expect_in=["Database not available"], label="export csv (no DB connection)")

# Restore DB
shell.db_path = old_db
shell._init_db()


# ═══════════════════════════════════════════════════════════
#  14. CAPTURE START VALIDATION
# ═══════════════════════════════════════════════════════════
section("14. CAPTURE START VALIDATION")

# Test capture without interface
original_iface = shell.interface
shell.interface = None
run_cmd(shell, "capture start", expect_in="No interface", label="capture start (no interface)")
shell.interface = original_iface

# Test double-start prevention (without actually starting)
shell.capturing = True
run_cmd(shell, "capture start", expect_in="already running", label="capture start (already running)")
shell.capturing = False


# ═══════════════════════════════════════════════════════════
#  15. EXIT / QUIT
# ═══════════════════════════════════════════════════════════
section("15. EXIT / QUIT")

# Test that exit returns True (signals cmd loop to stop)
buf = io.StringIO()
old_file = console.file
console.file = buf
old_stdout = sys.stdout
sys.stdout = buf
result = shell.onecmd("exit")
console.file = old_file
sys.stdout = old_stdout
if result is True:
    PASS += 1
    print("  ✓ exit returns True (stops cmd loop)")
else:
    FAIL += 1
    BUGS.append("exit does not return True — cmdloop won't stop")
    print(f"  ✗ exit returns {result} instead of True")

# Test quit alias
buf = io.StringIO()
console.file = buf
sys.stdout = buf
result = shell.onecmd("quit")
console.file = old_file
sys.stdout = old_stdout
if result is True:
    PASS += 1
    print("  ✓ quit returns True (alias works)")
else:
    FAIL += 1
    BUGS.append("quit does not return True")
    print(f"  ✗ quit returns {result}")


# ═══════════════════════════════════════════════════════════
#  RESULTS
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"  RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

if BUGS:
    print(f"\n  🐛 BUGS FOUND ({len(BUGS)}):")
    for i, bug in enumerate(BUGS, 1):
        print(f"    {i}. {bug}")
else:
    print("\n  ✅ NO BUGS FOUND!")

print()
