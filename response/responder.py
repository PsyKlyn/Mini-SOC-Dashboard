# ---------- RESPONDER ----------
# Turns a detected alert into an automated defensive action and keeps
# the alert + the human-readable security log in sync.

import database
from collector import log_collector
from response import ip_blocker, rate_limiter

# Alert type -> (response status, action callable)
POLICIES = {
    "BRUTE FORCE": ("rate_limited",
                    lambda ip, alert: rate_limiter.apply(
                        ip, reason="Brute force: " + (alert["description"] or "")[:100])),
    "PORT SCAN": ("blocklisted",
                  lambda ip, alert: ip_blocker.block(
                      ip, reason="Port scan: " + (alert["description"] or "")[:100])),
    "SQL INJECTION": ("suspicious_logged", None),
    "BROKEN ACCESS CONTROL": ("suspicious_logged", None),
}


def respond_to_alert(alert_id):
    """Apply the policy for one alert; returns the response status used."""
    alert = database.get_alert(alert_id)
    if not alert:
        return None
    status, action = POLICIES.get(alert["alert_type"], ("suspicious_logged", None))
    ip = alert["source_ip"] or "0.0.0.0"
    if action:
        try:
            action(ip, alert)
        except Exception:
            status = "error"
    database.update_alert_response(alert_id, status)
    log_collector.append_log(
        "RESPONSE",
        "{} from {} -> {} [{}]".format(
            alert["alert_type"], ip, status, alert["description"]))
    return status
