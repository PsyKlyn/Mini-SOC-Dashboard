# ---------- RATE LIMITER (application-level, simulated) ----------
# Brute-force attackers get a temporary rate limit: further login
# attempts are refused until the window expires.

import database


def apply(ip, reason="Too many failed logins", minutes=3):
    """Rate-limit an IP for N minutes (action recorded as 'rate_limited')."""
    database.block_ip(ip, reason, action="rate_limited", minutes=minutes)


def is_rate_limited(ip):
    return database.is_blocked(ip)


def clear(ip):
    database.unblock_ip(ip)
