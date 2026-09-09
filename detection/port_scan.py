# ---------- PORT SCAN detection ----------
# One IP connects to several honeypot ports within a short window.

import config
import database


def check(source_ip):
    """Count distinct honeypot ports touched by this IP recently."""
    ports = database.recent_probe_ports(source_ip,
                                        config.PORT_WINDOW_SECONDS)
    if len(ports) < config.PORT_MIN_PORTS:
        return None
    if database.recent_alert_exists("PORT SCAN", source_ip, 2):
        return None
    severity = "High" if len(ports) >= config.PORT_HIGH_PORTS else "Medium"
    return {
        "alert_type": "PORT SCAN",
        "severity": severity,
        "source_ip": source_ip,
        "username": "",
        "endpoint": "network",
        "description": "Source contacted {} different honeypot port(s): "
                       "{}".format(len(ports), ", ".join(ports)),
    }
