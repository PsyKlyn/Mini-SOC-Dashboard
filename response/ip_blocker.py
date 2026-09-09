# ---------- IP BLOCKER (simulated firewall blocklist) ----------
# Aggressive behaviour (e.g. port scanning) puts the source IP on the
# blocklist for a few minutes. A real SOC would push this to a firewall.

import database


def block(ip, reason="Port scan detected", minutes=5):
    """Blocklist an IP for N minutes (action recorded as 'blocklisted')."""
    database.block_ip(ip, reason, action="blocklisted", minutes=minutes)


def unblock(ip):
    database.unblock_ip(ip)


def is_blocked(ip):
    return database.is_blocked(ip)
