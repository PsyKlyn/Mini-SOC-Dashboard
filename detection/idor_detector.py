# ---------- BROKEN ACCESS CONTROL detection (A01 / IDOR) ----------
# A logged-in user requests another user's profile via /profile?id=N.

import re

import config
import database


def check(details, source_ip):
    """details looks like: requested_id=2 session_id=1"""
    m = re.search(r"requested_id=(\S+)", details or "")
    s = re.search(r"session_id=(\S+)", details or "")
    if not m or not s:
        return None
    requested = m.group(1)
    session_id = s.group(1)
    try:
        if int(requested) == int(session_id):
            return None  # own profile - normal
    except ValueError:
        return None
    if database.recent_alert_exists("BROKEN ACCESS CONTROL", source_ip,
                                    config.IDOR_DEDUPE_MIN):
        return None
    return {
        "alert_type": "BROKEN ACCESS CONTROL",
        "severity": "High",
        "source_ip": source_ip,
        "username": "",
        "endpoint": "/profile",
        "description": "User with session id {} requested profile of user "
                       "id {} (unauthorized access).".format(session_id, requested),
    }
