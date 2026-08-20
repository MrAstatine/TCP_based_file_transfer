"""Automatic inbound firewall rule setup for the receiver (Windows-only for now).

Why this exists
----------------
Windows Firewall silently drops unsolicited inbound TCP/ICMP traffic on
networks it classifies as "Public" (the default for unrecognized networks,
including most phone hotspots the first time you join them). That's why
`ping` *and* our TCP `connect()` both timed out with no error from the
receiver's own listening socket -- the packets never got past the OS
firewall to reach our `accept()` call at all.

Fixing this by hand means opening Windows Defender Firewall > Advanced
Settings > Inbound Rules > New Rule every time a new person wants to
receive a file, which defeats the point of a friendly P2P tool. This
module automates that: it checks whether an inbound rule already exists,
and if not, elevates *only the rule-creation command* (one UAC prompt)
rather than relaunching the whole app as admin. The receiver process
itself keeps running as a normal user, same as always.
"""

import os
import platform
import subprocess
import tempfile

FIREWALL_RULE_NAME = "P2P File Transfer (CNFT)"


def is_windows():
    return platform.system().lower() == "windows"


def _rule_exists():
    """Query (no admin required) whether our named rule is already present."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={FIREWALL_RULE_NAME}"],
            capture_output=True,
            text=True,
        )
        # netsh prints "No rules match the specified criteria." when absent.
        return result.returncode == 0 and "No rules match" not in result.stdout
    except (OSError, subprocess.CalledProcessError):
        return False


def _run_elevated_script(ps_lines):
    """Write ps_lines to a temp .ps1 file and run it elevated (one UAC prompt).

    Using a script file avoids the multi-layer quoting problems that arise
    when embedding netsh commands (which contain spaces and quotes) inside
    Start-Process -ArgumentList strings.
    """
    fd, script_path = tempfile.mkstemp(suffix=".ps1", prefix="p2p_fw_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(ps_lines) + "\n")

        # Pass each argument as a separate list element -- no shell quoting needed.
        # Start-Process -Verb RunAs is the UAC elevation hook; -Wait blocks until done.
        subprocess.run(
            [
                "powershell",
                "-Command",
                "Start-Process",
                "powershell",
                "-Verb", "RunAs",
                "-Wait",
                "-WindowStyle", "Hidden",
                "-ArgumentList", f'"-ExecutionPolicy Bypass -File `"{script_path}`""',
            ],
            check=True,
        )
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def ensure_inbound_rule(port):
    """Ensure an inbound TCP allow-rule exists for `port`.

    Safe to call on every receiver startup: it is a no-op after the first
    successful run on a given machine. Only triggers a UAC prompt the
    very first time, when the rule does not exist yet.
    """
    if not is_windows():
        print(
            "info: Automatic firewall setup only runs on Windows right now. "
            "On macOS/Linux, confirm inbound TCP on this port is allowed "
            "(e.g. check System Settings > Firewall, or your distro's "
            "ufw/iptables rules)."
        )
        return

    if _rule_exists():
        print(f"Firewall rule '{FIREWALL_RULE_NAME}' already present -- skipping setup.")
        return

    print("No firewall rule found for this port yet -- requesting one-time admin approval...")

    try:
        _run_elevated_script([
            f'netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
            f'dir=in action=allow protocol=TCP localport={port}'
        ])
    except subprocess.CalledProcessError:
        print("warning: Firewall rule could not be added automatically "
              "(the UAC prompt may have been declined).")
        print(
            f'    You can add it manually by running as admin:\n'
            f'    netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
            f'dir=in action=allow protocol=TCP localport={port}'
        )
        return

    if _rule_exists():
        print(f"Firewall rule added for inbound TCP port {port}.")
    else:
        print("warning: Rule still not detected. Please check Windows Firewall settings manually.")


def reset_and_create_rule(port):
    """Delete any stale rule with our name, then add a fresh one for `port`.

    Runs as a single elevated PowerShell call (one UAC prompt) so a rule
    left behind by a crashed prior session does not cause duplicates or a
    stale port number -- this always leaves exactly one correct rule.
    """
    if not is_windows():
        print("info: Automatic firewall setup only runs on Windows right now. "
              "On macOS/Linux, confirm inbound TCP on this port is allowed.")
        return

    print("Setting up a temporary firewall rule for this session...")

    try:
        _run_elevated_script([
            # Delete first (ignore error if rule does not exist yet)
            f'netsh advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}" 2>$null',
            # Then add a fresh rule for the current port
            f'netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
            f'dir=in action=allow protocol=TCP localport={port}',
        ])
    except subprocess.CalledProcessError:
        print("warning: Could not set up the firewall rule automatically "
              "(the UAC prompt may have been declined).")
        print(
            f'    You can add it manually by running as admin:\n'
            f'    netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
            f'dir=in action=allow protocol=TCP localport={port}'
        )
        return

    if _rule_exists():
        print(f"Temporary firewall rule active for TCP port {port}.")
    else:
        print("warning: Rule not detected after setup -- check Windows Firewall manually.")


def remove_inbound_rule():
    """Remove the inbound rule (requires admin, one UAC prompt).

    Called automatically at receiver shutdown via atexit / signal handler.
    """
    if not is_windows():
        return

    try:
        _run_elevated_script([
            f'netsh advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}"',
        ])
    except subprocess.CalledProcessError:
        pass  # Best-effort cleanup -- silently ignore if UAC was declined
