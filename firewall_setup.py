"""Automatic inbound firewall rule setup for the receiver (Windows-only for now).

Why this exists
----------------
Windows Firewall silently drops unsolicited inbound TCP/ICMP traffic on
networks it classifies as "Public" (the default for unrecognized networks,
including most phone hotspots the first time you join them). That's why
`ping` *and* our TCP `connect()` both timed out with no error from the
receiver's own listening socket — the packets never got past the OS
firewall to reach our `accept()` call at all.

Fixing this by hand means opening Windows Defender Firewall > Advanced
Settings > Inbound Rules > New Rule every time a new person wants to
receive a file, which defeats the point of a friendly P2P tool. This
module automates that: it checks whether an inbound rule already exists,
and if not, elevates *only the rule-creation command* (one UAC prompt)
rather than relaunching the whole app as admin. The receiver process
itself keeps running as a normal user, same as always.
"""

import platform
import subprocess

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


def ensure_inbound_rule(port):
    """Ensure an inbound TCP allow-rule exists for `port`.

    Safe to call on every receiver startup: it's a no-op after the first
    successful run on a given machine. Only triggers a UAC prompt the
    very first time, when the rule doesn't exist yet.
    """
    if not is_windows():
        print(
            "ℹ️  Automatic firewall setup only runs on Windows right now. "
            "On macOS/Linux, confirm inbound TCP on this port is allowed "
            "(e.g. check System Settings > Firewall, or your distro's "
            "ufw/iptables rules)."
        )
        return

    if _rule_exists():
        print(f"✅ Firewall rule '{FIREWALL_RULE_NAME}' already present — skipping setup.")
        return

    print("🔧 No firewall rule found for this port yet — requesting one-time admin approval...")
    print("   (A Windows 'Do you want to allow this app...' prompt should appear.)")

    netsh_args = (
        f'advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
        f'dir=in action=allow protocol=TCP localport={port}'
    )

    # Start-Process -Verb RunAs elevates ONLY this one netsh invocation.
    # -Wait blocks until the elevated process finishes before we continue.
    ps_command = f"Start-Process netsh -ArgumentList '{netsh_args}' -Verb RunAs -Wait"

    try:
        subprocess.run(["powershell", "-Command", ps_command], check=True)
    except subprocess.CalledProcessError:
        print("⚠️  Firewall rule could not be added automatically "
              "(the UAC prompt may have been declined).")
        print(f"    You can add it manually by running as admin:\n    netsh {netsh_args}")
        return

    if _rule_exists():
        print(f"✅ Firewall rule added for inbound TCP port {port}.")
    else:
        print("⚠️  Rule still not detected. Please check Windows Firewall settings manually.")


def reset_and_create_rule(port):
    """Delete any stale rule with our name, then add a fresh one for `port`.

    Runs as a single elevated PowerShell call (one UAC prompt) so a rule
    left behind by a crashed prior session doesn't cause duplicates or a
    stale port number — this always leaves exactly one correct rule.
    """
    if not is_windows():
        print("ℹ️  Automatic firewall setup only runs on Windows right now. "
              "On macOS/Linux, confirm inbound TCP on this port is allowed.")
        return

    netsh_delete = f'advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}"'
    netsh_add = (
        f'advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
        f'dir=in action=allow protocol=TCP localport={port}'
    )
    # Chain delete+add inside one elevated PowerShell process -> one UAC prompt.
    ps_command = (
        f"Start-Process powershell -Verb RunAs -Wait -ArgumentList "
        f"'-Command \"netsh {netsh_delete}; netsh {netsh_add}\"'"
    )

    print("🔧 Setting up a temporary firewall rule for this session...")
    print("   (A Windows 'Do you want to allow this app...' prompt should appear.)")

    try:
        subprocess.run(["powershell", "-Command", ps_command], check=True)
    except subprocess.CalledProcessError:
        print("⚠️  Could not set up the firewall rule automatically "
              "(the UAC prompt may have been declined).")
        print(f"    You can add it manually by running as admin:\n    netsh {netsh_add}")
        return

    if _rule_exists():
        print(f"✅ Temporary firewall rule active for TCP port {port}.")
    else:
        print("⚠️  Rule not detected after setup — check Windows Firewall manually.")


def remove_inbound_rule():
    """Optional cleanup: remove the rule (requires admin, one UAC prompt).

    Not called automatically — leaving the rule in place is what makes
    subsequent runs prompt-free. Expose this as a manual/CLI option if you
    want a way to revoke access later, e.g. after a one-off transfer.
    """
    if not is_windows():
        return

    ps_command = (
        f'Start-Process netsh -ArgumentList \'advfirewall firewall delete rule '
        f'name="{FIREWALL_RULE_NAME}"\' -Verb RunAs -Wait'
    )
    subprocess.run(["powershell", "-Command", ps_command], check=False)
