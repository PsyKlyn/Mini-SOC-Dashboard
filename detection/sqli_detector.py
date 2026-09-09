# ---------- SQL INJECTION detection (A05) ----------
import database
# Looks for suspicious SQL keywords / syntax inside request text.

SQLI_PATTERNS = [
    "union select", "union all select", "union select null",
    "or 1=1", "or '1'='1", "or \"1\"=\"1",
    "1'='1", "1\"=\"1",
    "'--", "')--", "'#",
    "/*", "*/",
    "sleep(", "benchmark(", "waitfor delay",
    "sqlite_master", "sqlite_version()", "version()",
    "information_schema",
    "' or '", "\" or \"",
    "select * from", "select password", "select username",
    "group by", "order by 1",
]


def find_pattern(text):
    """Return the first SQLi pattern found in text (lowercased match)."""
    low = (text or "").lower()
    for pattern in SQLI_PATTERNS:
        if pattern in low:
            return pattern
    return None


def check_query(query_text, source_ip, endpoint="/search"):
    """Check the search query value for SQLi indicators."""
    pattern = find_pattern(query_text)
    if not pattern:
        return None
    if database.recent_alert_exists("SQL INJECTION", source_ip, 1):
        return None  # same attacker flooding payloads: don't spam duplicates
    return {
        "alert_type": "SQL INJECTION",
        "severity": "High",
        "source_ip": source_ip,
        "username": "",
        "endpoint": endpoint,
        "description": "Suspicious SQL pattern '{}' in request value "
                       "{}".format(pattern, query_text[:120]),
    }


def check_username(username, source_ip):
    """Login endpoint can also receive SQLi payloads in the username field."""
    return check_query(username, source_ip, endpoint="/login")
