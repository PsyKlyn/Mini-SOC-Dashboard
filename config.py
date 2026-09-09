# ---------- Mini SOC configuration ----------
# All detection thresholds live here so they are easy to tune.

# Brute force (A07)
BRUTE_THRESHOLD = 5        # failed logins needed before alerting
BRUTE_WINDOW_MIN = 2       # ...within this many minutes

# SQL injection (A05) - pattern list lives in detection/sqli_detector.py

# Broken access control (A01)
IDOR_DEDUPE_MIN = 1        # don't spam duplicate alerts within 1 minute

# Port scan (honeypot listens on these extra ports)
HONEYPOT_PORTS = [9101, 9102, 9103, 9104, 9105]
PORT_MIN_PORTS = 3         # distinct ports from one IP => MEDIUM alert
PORT_HIGH_PORTS = 5        # distinct ports => HIGH alert
PORT_WINDOW_SECONDS = 60   # counting window

# Engine
ENGINE_INTERVAL = 2        # seconds between detection sweeps
