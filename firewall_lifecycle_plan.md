# Plan: Ephemeral Windows Firewall Rule for P2P Receiver

## Objective
Automatically open inbound TCP access for the receiver's port on startup,
and automatically remove that access on shutdown — with zero manual
firewall configuration required from the user, and without running the
whole application as Administrator.

## Design decision (and why)
Elevate **only the two `netsh` commands** (rule add, rule delete) via a
one-off elevated subprocess, NOT the entire Python process.

Rationale: `filename` in `work_rec.py`'s chunk handler comes from
network-supplied metadata (`recv_transfer_metadata`) and is not path-
sanitized. If the whole receiver ran as Administrator, any bug in that
path-handling logic would write files with admin privileges instead of
a normal user's. Keeping the main app unprivileged limits the damage
any single bug can do — the firewall changes are the *only* thing that
needs elevation, so they're the only thing that gets it.

## File 1: `firewall_setup.py` (already exists — extend it)

Current state: has `ensure_inbound_rule(port)` (idempotent add, skips if
rule exists) and `remove_inbound_rule()` (delete, not currently called
automatically).

Changes:
1. Add a new function `reset_and_create_rule(port)` that does delete-then-add
   in a **single** elevated PowerShell invocation (one UAC prompt instead of
   two), so any leftover rule from a crashed prior session is cleared and a
   fresh one is created with the current port:

   ```python
   def reset_and_create_rule(port):
       """Delete any stale rule with our name, then add a fresh one for `port`.
       Runs as a single elevated call (one UAC prompt) to keep prior-crash
       leftovers from causing duplicate/stale rules."""
       if not is_windows():
           print("ℹ️  Automatic firewall setup only runs on Windows right now.")
           return

       netsh_delete = f'advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}"'
       netsh_add = (
           f'advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
           f'dir=in action=allow protocol=TCP localport={port}'
       )
       # Chain both netsh calls inside one elevated PowerShell process.
       ps_command = (
           f"Start-Process powershell -Verb RunAs -Wait -ArgumentList "
           f"'-Command \"netsh {netsh_delete}; netsh {netsh_add}\"'"
       )
       try:
           subprocess.run(["powershell", "-Command", ps_command], check=True)
       except subprocess.CalledProcessError:
           print("⚠️  Could not set up firewall rule automatically "
                 "(UAC prompt may have been declined).")
           return

       if _rule_exists():
           print(f"✅ Temporary firewall rule active for TCP port {port}.")
       else:
           print("⚠️  Rule not detected after setup — check Windows Firewall manually.")
   ```

2. Keep `remove_inbound_rule()` exactly as-is — it's reused for cleanup at
   shutdown.

## File 2: `work_rec.py` — wire up lifecycle hooks

In the `if __name__ == "__main__":` block:

1. Import at top of file:
   ```python
   import atexit
   import signal
   from firewall_setup import reset_and_create_rule, remove_inbound_rule
   ```

2. Immediately after `port` is parsed (after the `try/except ValueError`
   block that reads `port_str`), before `start_server(...)` is called:
   ```python
   reset_and_create_rule(port)
   atexit.register(remove_inbound_rule)

   def _cleanup_on_signal(signum, frame):
       remove_inbound_rule()
       sys.exit(0)

   signal.signal(signal.SIGINT, _cleanup_on_signal)
   signal.signal(signal.SIGTERM, _cleanup_on_signal)
   ```

   Note: `SIGINT` (Ctrl+C) would actually already trigger `atexit` on its
   own since it just raises `KeyboardInterrupt` and unwinds normally — the
   explicit handler here is mainly to guarantee cleanup runs for `SIGTERM`
   (e.g. Task Manager "End Task" without `/F`), which bypasses `atexit`.

## Known limitation (be upfront about this)
A hard kill (`taskkill /F`, power loss, OS crash) bypasses both `atexit`
and signal handlers — no code can run after the process is forcibly
terminated. `reset_and_create_rule()`'s delete-then-add at the *next*
startup is what self-heals from this: any orphaned rule from an
ungraceful exit gets cleared before a fresh one is created, so leftover
rules don't accumulate indefinitely, they just persist until the next
run rather than being deleted immediately.

## Testing checklist
- [ ] Fresh machine, no existing rule: start receiver, confirm exactly one
      UAC prompt, confirm rule appears in Windows Defender Firewall >
      Advanced Settings > Inbound Rules.
- [ ] Stop receiver normally (choose "n" at "Receive another file?"):
      confirm rule disappears from Inbound Rules.
- [ ] Stop receiver via Ctrl+C mid-wait: confirm rule disappears.
- [ ] Kill receiver via Task Manager "End Task": confirm rule is left
      behind, then start receiver again and confirm it's cleaned up
      automatically (delete-then-add) before the new rule is created.
- [ ] Decline the UAC prompt: confirm the app prints a clear manual
      fallback command and continues without crashing (receiver should
      still start and listen; the transfer just won't be reachable until
      the rule is added some other way).
