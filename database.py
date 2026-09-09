import sqlite3
from datetime import datetime

DATABASE = "cyberlab.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            role TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            location TEXT DEFAULT '',
            website TEXT DEFAULT '',
            member_since TEXT DEFAULT ''
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)

    # ---- SOC tables (event logging + detection + response) ----

    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            event_type TEXT,
            endpoint TEXT,
            username TEXT,
            details TEXT,
            detection_status TEXT DEFAULT 'logged',
            response_status TEXT DEFAULT 'none'
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            username TEXT,
            endpoint TEXT,
            description TEXT,
            detection_status TEXT DEFAULT 'detected',
            response_status TEXT DEFAULT 'pending'
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            action TEXT,
            timestamp TEXT,
            expires_at TEXT
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            username TEXT
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    db.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(detection_status)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_failed_ip ON failed_logins(source_ip, timestamp)")

    # migration: add profile columns to an existing users table
    existing = [r["name"] for r in db.execute("PRAGMA table_info(users)")]
    for col, decl in {
            "full_name": "TEXT DEFAULT ''", "role": "TEXT DEFAULT ''",
            "bio": "TEXT DEFAULT ''", "location": "TEXT DEFAULT ''",
            "website": "TEXT DEFAULT ''",
            "member_since": "TEXT DEFAULT ''"}.items():
        if col not in existing:
            db.execute("ALTER TABLE users ADD COLUMN {} {}".format(col, decl))

    db.commit()
    db.close()


def seed_data():
    db = get_db()

    demo_users = [
        ("admin", "admin123", "admin@cyberlab.local",
         "Riley Chen", "SOC Administrator",
         "Runs the CyberLab SOC: monitors alerts, tunes detections and "
         "manages the blocklist.",
         "Remote - IST", "https://cyberlab.local/admin",
         "2025-06-01"),
        ("alex", "alex123", "alex@cyberlab.local",
         "Alex Morgan", "SOC Analyst I",
         "Security analyst exploring the CyberLab honeypot. Curious about "
         "attack detection, IDORs and blue-team tooling.",
         "Bengaluru, India", "https://cyberlab.local/alex",
         "2026-02-14"),
    ]
    for (u, p, e, full, role, bio, loc, web, since) in demo_users:
        row = db.execute("SELECT id FROM users WHERE username = ?",
                         (u,)).fetchone()
        if row:
            # enrich existing demo users only where the field is still empty
            db.execute(
                "UPDATE users SET full_name = COALESCE(NULLIF(full_name, ''), ?),"
                " role = COALESCE(NULLIF(role, ''), ?),"
                " bio = COALESCE(NULLIF(bio, ''), ?),"
                " location = COALESCE(NULLIF(location, ''), ?),"
                " website = COALESCE(NULLIF(website, ''), ?),"
                " member_since = COALESCE(NULLIF(member_since, ''), ?)"
                " WHERE username = ?",
                (full, role, bio, loc, web, since, u))
        else:
            db.execute(
                "INSERT INTO users (username, password, email, full_name, role,"
                " bio, location, website, member_since)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (u, p, e, full, role, bio, loc, web, since))

    products = [
        ("Network Scanner", "Tool for network analysis."),
        ("Security Book", "Introduction to cybersecurity."),
        ("Penetration Testing Kit", "Tools used in security testing.")
    ]

    has_products = db.execute(
        "SELECT COUNT(*) AS c FROM products").fetchone()["c"] > 0
    if not has_products:
        db.executemany("""
            INSERT INTO products (name, description)
            VALUES (?, ?)
        """, products)

    db.commit()
    db.close()


# ================= SOC helper functions =================
# Each helper opens its own connection and closes it, so they are safe
# to call from anywhere in the app (routes, detection engine, ...).

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- events ----------

def add_event(source_ip, event_type, endpoint="", username="", details="",
              detection_status="logged", response_status="none"):
    """Record one event (login, search, profile access, port probe...)."""
    db = get_db()
    db.execute(
        "INSERT INTO events (timestamp, source_ip, event_type, endpoint, "
        "username, details, detection_status, response_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now(), source_ip, event_type, endpoint, username, details,
         detection_status, response_status))
    db.commit()
    db.close()


def get_pending_events(limit=200):
    """Events the detection engine has not analysed yet (oldest first)."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM events WHERE detection_status = 'logged' "
        "ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


def mark_event_processed(event_id):
    db = get_db()
    db.execute("UPDATE events SET detection_status = 'processed' "
               "WHERE id = ?", (event_id,))
    db.commit()
    db.close()


def count_events():
    db = get_db()
    row = db.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    db.close()
    return row["c"] if row else 0


def get_recent_events(limit=50):
    db = get_db()
    rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",
                      (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ---------- alerts ----------

def add_alert(alert_type, severity, source_ip, description,
              username="", endpoint=""):
    """Create a security alert; returns the new alert id."""
    db = get_db()
    cursor = db.execute(
        "INSERT INTO alerts (timestamp, alert_type, severity, source_ip, "
        "username, endpoint, description, response_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
        (now(), alert_type, severity, source_ip, username, endpoint,
         description))
    db.commit()
    alert_id = cursor.lastrowid
    db.close()
    return alert_id


def get_alert(alert_id):
    db = get_db()
    row = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    db.close()
    return dict(row) if row else None


def recent_alert_exists(alert_type, source_ip, minutes):
    """True if this IP already triggered this alert type recently
    (used to avoid flooding the dashboard with duplicate alerts)."""
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM alerts WHERE alert_type = ? AND source_ip = ? "
        "AND timestamp >= datetime('now', 'localtime', ?) LIMIT 1",
        (alert_type, source_ip, "-{} minutes".format(minutes))).fetchone()
    db.close()
    return row is not None


def update_alert_response(alert_id, status):
    db = get_db()
    db.execute("UPDATE alerts SET response_status = ? WHERE id = ?",
               (status, alert_id))
    db.commit()
    db.close()


def count_alerts():
    db = get_db()
    row = db.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
    db.close()
    return row["c"] if row else 0


def count_open_alerts():
    """Alerts that still need attention (no automated response yet)."""
    db = get_db()
    row = db.execute("SELECT COUNT(*) AS c FROM alerts "
                     "WHERE response_status IN ('pending', 'none')").fetchone()
    db.close()
    return row["c"] if row else 0


def get_recent_alerts(limit=50):
    db = get_db()
    rows = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                      (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_responses(limit=50):
    """Alerts that triggered an automated defensive response."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM alerts WHERE response_status NOT IN ('pending', 'none') "
        "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ---------- failed logins / brute force ----------

def log_failed_login(source_ip, username):
    """Store a single failed login (used by brute-force detection)."""
    db = get_db()
    db.execute("INSERT INTO failed_logins (timestamp, source_ip, username) "
               "VALUES (?, ?, ?)", (now(), source_ip, username))
    db.commit()
    db.close()


def count_recent_failed(source_ip, minutes=2):
    """How many failed logins came from this IP in the last N minutes."""
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS c FROM failed_logins "
        "WHERE source_ip = ? AND timestamp >= datetime('now', 'localtime', ?)",
        (source_ip, "-{} minutes".format(minutes))).fetchone()
    db.close()
    return row["c"] if row else 0


# ---------- blocked IPs / honeypot probes ----------

def block_ip(ip, reason, action="blocklisted", minutes=5):
    """Application-level temporary block (simulated, reversible)."""
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO blocked_ips "
        "(ip, reason, action, timestamp, expires_at) "
        "VALUES (?, ?, ?, ?, datetime('now', 'localtime', ?))",
        (ip, reason, action, now(), "+{} minutes".format(minutes)))
    db.commit()
    db.close()


def unblock_ip(ip):
    db = get_db()
    db.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    db.commit()
    db.close()


def is_blocked(ip):
    """True if the IP is on the blocklist and not yet expired."""
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM blocked_ips WHERE ip = ? AND expires_at > datetime('now', 'localtime')",
        (ip,)).fetchone()
    db.close()
    return row is not None


def get_blocked_ips():
    db = get_db()
    rows = db.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def recent_probe_ports(source_ip, window_seconds=60):
    """Distinct honeypot ports this IP touched inside the window."""
    import config
    placeholders = ",".join("?" for _ in config.HONEYPOT_PORTS)
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT endpoint FROM events "
        "WHERE source_ip = ? AND event_type = 'port_probe' "
        "AND endpoint IN ({}) AND timestamp >= datetime('now', 'localtime', ?)"
        .format(placeholders),
        (source_ip,) + tuple(str(p) for p in config.HONEYPOT_PORTS) +
        ("-{} seconds".format(window_seconds),)).fetchall()
    db.close()
    return [r["endpoint"] for r in rows]


# ---------- settings (secure-mode toggle) ----------

def get_setting(key, default=None):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?",
                     (key,)).fetchone()
    db.close()
    return row["value"] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
               (key, value))
    db.commit()
    db.close()


# ---------- demo seed (fictional data for the exhibition) ----------

def seed_soc_demo():
    """OPTIONAL helper - NOT called automatically.
    Fills the SOC dashboard with a short fictional attack story if you ever
    want a pre-populated demo. All IPs are fictional (RFC 5737)."""
    db = get_db()
    empty = db.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"] == 0
    if not empty:
        db.close()
        return
    demo = [
        # (minutes ago, source_ip, event_type, endpoint, username, details)
        (25, "203.0.113.77", "login_failed", "/login", "admin",
         "Invalid username or password"),
        (24, "203.0.113.77", "login_failed", "/login", "admin",
         "Invalid username or password"),
        (23, "203.0.113.77", "login_failed", "/login", "admin",
         "Invalid username or password"),
        (20, "203.0.113.77", "search", "/search", "",
         "q=' OR '1'='1' --"),
        (18, "198.51.100.9", "port_probe", "9101",
         "SYN probe sent to honeypot port 9101"),
        (18, "198.51.100.9", "port_probe", "9103",
         "SYN probe sent to honeypot port 9103"),
        (18, "198.51.100.9", "port_probe", "9105",
         "SYN probe sent to honeypot port 9105"),
    ]
    for row in demo:
        minutes_ago, ip, etype, endpoint, username, details = (row + ("",))[:6]
        db.execute(
            "INSERT INTO events (timestamp, source_ip, event_type, endpoint, "
            "username, details, detection_status, response_status) "
            "VALUES (datetime('now', 'localtime', ?), ?, ?, ?, ?, ?, 'processed', 'none')",
            ("-{} minutes".format(minutes_ago), ip, etype, endpoint,
             username, details))
    db.execute(
        "INSERT INTO alerts (timestamp, alert_type, severity, source_ip, "
        "username, endpoint, description, response_status) "
        "VALUES (datetime('now', 'localtime', '-23 minutes'), 'BRUTE FORCE', 'High', "
        "'203.0.113.77', 'admin', '/login', "
        "'3 failed login attempts from this IP within 2 minute(s).', "
        "'rate_limited')")
    db.execute(
        "INSERT INTO alerts (timestamp, alert_type, severity, source_ip, "
        "username, endpoint, description, response_status) "
        "VALUES (datetime('now', 'localtime', '-20 minutes'), 'SQL INJECTION', 'High', "
        "'203.0.113.77', '', '/search', "
        "'Suspicious SQL pattern ''or 1=1'' in request value q='' OR ''1''=''1'' --', "
        "'suspicious_logged')")
    db.execute(
        "INSERT INTO alerts (timestamp, alert_type, severity, source_ip, "
        "username, endpoint, description, response_status) "
        "VALUES (datetime('now', 'localtime', '-18 minutes'), 'PORT SCAN', 'Medium', "
        "'198.51.100.9', '', 'network', "
        "'Source contacted 3 different honeypot port(s): 9101, 9103, 9105', "
        "'blocklisted')")
    db.execute(
        "INSERT INTO blocked_ips (ip, reason, action, timestamp, expires_at) "
        "VALUES ('198.51.100.9', 'Port scan: Source contacted 3 different "
        "honeypot port(s)', 'blocklisted', datetime('now', 'localtime', '-18 minutes'), "
        "datetime('now', 'localtime', '12 minutes'))")
    db.commit()
    db.close()


if __name__ == "__main__":
    init_db()
    seed_data()
    print("Database created successfully and sample data added.")
