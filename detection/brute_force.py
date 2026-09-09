# ---------- BRUTE FORCE detection (A07) ----------
# Repeated failed logins from the same IP inside a short window.

import config
import database


def check(source_ip, username=""):
    """Return an alert dict if this IP crossed the failed-login threshold."""
    count = database.count_recent_failed(source_ip, config.BRUTE_WINDOW_MIN)
    if count < config.BRUTE_THRESHOLD:
        return None
    # Avoid one alert per request: skip if we already alerted for this burst
    if database.recent_alert_exists("BRUTE FORCE", source_ip,
                                    config.BRUTE_WINDOW_MIN):
        return None
    return {
        "alert_type": "BRUTE FORCE",
        "severity": "High",
        "source_ip": source_ip,
        "username": username,
        "endpoint": "/login",
        "description": "{} failed login attempts from this IP within "
                       "{} minute(s).".format(count, config.BRUTE_WINDOW_MIN),
    }
