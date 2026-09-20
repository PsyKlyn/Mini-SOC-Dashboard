from flask import (Flask, abort, flash, jsonify, redirect,
                   render_template, request, session, url_for)

import database
from datetime import datetime
from database import (add_event, get_db, init_db, log_failed_login,
                      seed_data)
from detection import sqli_detector
from detection.engine import ENGINE
from response import ip_blocker
from collector import network_monitor

app = Flask(__name__)
app.secret_key = "cyberlab-secret-key"


@app.context_processor
def inject_soc_notifications():

    try:
        db = get_db()

        # New/unprocessed events
        event_count = db.execute("""
            SELECT COUNT(*) AS c
            FROM events
            WHERE detection_status = 'logged'
        """).fetchone()["c"]

        # Alerts waiting for attention
        alert_count = db.execute("""
            SELECT COUNT(*) AS c
            FROM alerts
            WHERE LOWER(TRIM(response_status)) = 'suspicious_logged'
        """).fetchone()["c"]

        # Alerts where an automated/manual response has already happened
        response_count = db.execute("""
            SELECT COUNT(*) AS c
            FROM alerts
            WHERE LOWER(TRIM(response_status)) = 'blocklisted'
        """).fetchone()["c"]

        # Overview captures EVERYTHING
        overview_count = (
            event_count
            + alert_count
            + response_count
        )

        db.close()

        return {
            "notification_overview": overview_count,
            "notification_events": event_count,
            "notification_alerts": alert_count,
            "notification_responses": response_count
        }

    except Exception as e:
        print("Notification count error:", e)

        return {
            "notification_overview": 0,
            "notification_events": 0,
            "notification_alerts": 0,
            "notification_responses": 0
        }

@app.route("/api/soc/notifications")
def soc_notifications():

    try:
        db = get_db()

        events = db.execute("""
            SELECT COUNT(*) AS c
            FROM events
            WHERE detection_status = 'logged'
        """).fetchone()["c"]

        alerts = db.execute("""
            SELECT COUNT(*) AS c
            FROM alerts
            WHERE LOWER(TRIM(response_status)) = 'suspicious_logged'
        """).fetchone()["c"]

        responses = db.execute("""
            SELECT COUNT(*) AS c
            FROM alerts
            WHERE LOWER(TRIM(response_status)) = 'blocklisted'
        """).fetchone()["c"]

        db.close()

        return {
            "overview": events + alerts + responses,
            "events": events,
            "alerts": alerts,
            "responses": responses
        }

    except Exception as e:
        print("Notification API error:", e)

        return {
            "overview": 0,
            "events": 0,
            "alerts": 0,
            "responses": 0
        }


def fmt_clock12(value):
    """'YYYY-MM-DD HH:MM:SS' (24h) -> 'YYYY-MM-DD hh:mm:ss AM/PM' (12h).
    Keeps the date part untouched; used for display only, so stored
    timestamps stay lexicographically sortable for SQLite."""
    if not value:
        return value
    try:
        dt = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %I:%M:%S %p")


app.jinja_env.filters["clock12"] = fmt_clock12
failed_attempts = {}


#  SOC: shared helpers 

def get_client_ip():
    """Return the visitor's IP address so events can be logged per source."""
    return request.remote_addr or "0.0.0.0"


def secure_mode_enabled():
    """Read the global 'mode' setting (secure vs insecure)."""
    return database.get_setting("mode", "insecure") == "secure"


@app.context_processor
def inject_soc_globals():
    """Make the current mode available to every template."""
    secure = secure_mode_enabled()
    return {
        "secure_mode": secure,
        "mode_badge": "Secure mode" if secure else "Insecure mode (vulnerable)",
        "mode_class": "secure" if secure else "insecure",
    }


#  public pages (deliberately vulnerable)
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        client_ip = get_client_ip()

        # SOC: refuse requests from IPs the SOC has rate-limited/blocked
        if ip_blocker.is_blocked(client_ip):
            add_event(client_ip, "login_blocked", "/login", username,
                      "Login refused: IP is on the SOC blocklist")
            return render_template("login.html",
                                   error_message="Too many failed attempts - "
                                                 "this IP was blocked by the SOC "
                                                 "(rate limited). Try again later.",
                                   code=429), 429

        db = get_db()

        if secure_mode_enabled():
            #  SECURE branch: parameterized query (SQLi does not work) 
            sql = "SELECT * FROM users WHERE username = ? AND password = ?"
            user = db.execute(sql, (username, password)).fetchone()
        else:
            #  INSECURE branch: raw f-string (SQL injection demo) 
            sql = f"""
                SELECT * FROM users
                WHERE username = '{username}'
                AND password = '{password}'
            """
            user = db.execute(sql).fetchone()

        db.close()

        if user:
            session["user_id"] = user["id"]
            add_event(client_ip, "login_success", "/login", username,
                      "User logged in successfully")
            return redirect("/profile")

        failed_attempts[username] = failed_attempts.get(username, 0) + 1

        # SOC: log the failed login (also stored in failed_logins table
        # so the brute-force detector can count attempts per IP)
        log_failed_login(client_ip, username)
        add_event(client_ip, "login_failed", "/login", username,
                  "Invalid username or password")

        flash("Invalid username or password.")
        return redirect("/login")

    return render_template("login.html")




def profile_initials(user):
    """Two-letter avatar initials from full_name (or username)."""
    full = (user.get("full_name") or "").strip()
    if full:
        parts = full.split()
        initials = (parts[0][0] + (parts[-1][0] if len(parts) > 1 else ""))
    else:
        initials = (user.get("username") or "?")[:2]
    return initials.upper() or "?"


def member_days(member_since):
    """Days since the account was created (0 if the date is missing)."""
    try:
        joined = datetime.strptime(member_since, "%Y-%m-%d")
        return max(0, (datetime.now() - joined).days)
    except (ValueError, TypeError):
        return 0


@app.route("/profile")
def profile():
    # SOC: log every profile access (requested id + logged-in id) so
    # IDOR attempts can be detected later
    requested_id = request.args.get("id", "")
    session_id = session.get("user_id")
    add_event(get_client_ip(), "profile_access", "/profile", "",
              "requested_id={} session_id={}".format(requested_id, session_id))

    # Not logged in yet: send the visitor to the login page instead of
    # showing "User not found." / an access-denied page. The IDOR demo
    # below intentionally still applies to logged-in users.
    if not session.get("user_id"):
        add_event(get_client_ip(), "profile_denied", "/profile", "",
                  "Not authenticated - redirected to login")
        flash("Please log in first to view a profile.")
        return redirect("/login")

    if secure_mode_enabled():
        #  SECURE branch: must be logged in; id is forced from session 
        user_id = session["user_id"]
        requested_id = user_id  # ?id= is ignored: users only see themselves
    else:
        # INSECURE branch: ?id= lets anyone read any profile (IDOR) 
        user_id = requested_id or session.get("user_id")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        db.close()
        flash("User not found.")
        return redirect("/profile")

    # Per-user profile stats + activity, derived from the SOC event log
    events = db.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 500").fetchall()
    db.close()
    user = dict(user)
    uid = user["id"]
    uname = user["username"]

    login_count = 0
    last_login = None
    profile_opens = 0
    search_count = 0
    activity = []
    for ev in events:
        ev = dict(ev)
        etype = ev["event_type"]
        if etype == "login_success" and ev["username"] == uname:
            login_count += 1
            last_login = last_login or ev["timestamp"]
        if etype == "search":
            search_count += 1
        if etype == "profile_access":
            # details look like: requested_id=X session_id=Y
            sid = None
            try:
                sid = int(ev["details"].rsplit("session_id=", 1)[1])
            except (ValueError, IndexError):
                pass
            if sid == uid:
                profile_opens += 1
        # this user's audit trail: their logins or pages opened by them
        is_mine = ev["username"] == uname or (
            etype == "profile_access" and
            ev["details"].rsplit("session_id=", 1)[-1].strip() == str(uid))
        if is_mine and len(activity) < 8:
            activity.append(ev)

    return render_template(
        "profile.html", user=user, viewing_self=(session.get("user_id") == uid),
        stats={
            "login_count": login_count,
            "last_login": last_login,
            "profile_opens": profile_opens,
            "search_count": search_count,
        },
        activity=activity,
        initials=profile_initials(user),
        member_days=member_days(user.get("member_since", "")))


@app.route("/search")
def search():
    query = request.args.get("q", "")

    # SOC: log the search BEFORE running the query, so even a payload
    # that breaks the SQL statement is still recorded
    if query:
        add_event(get_client_ip(), "search", "/search", "", "q=" + query)

    db = get_db()

    if secure_mode_enabled():
        # SECURE branch: parameterized LIKE with escaped wildcards 
        escaped = (query.replace("\\", "\\\\").replace("%", "\\%")
                       .replace("_", "\\_"))
        sql = "SELECT * FROM products WHERE name LIKE ? ESCAPE '\\'"
        results = db.execute(sql, ("%" + escaped + "%",)).fetchall()
    else:
        #  INSECURE branch: raw f-string LIKE (SQL injection demo) 
        sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        results = db.execute(sql).fetchall()

    db.close()
    return render_template("search.html", results=results, query=query)


@app.route("/admin")
def admin():

    client_ip = get_client_ip()
  
    # ACCESS CONTROL

    if secure_mode_enabled():

        if session.get("user_id") != 2:

            add_event(
                client_ip,
                "admin_denied",
                "/admin",
                "Non-admin tried to open the admin panel"
            )

            return render_template(
                "admin.html",
                denied=True,
                reason="Admins only - log in as admin."
            ), 403

        add_event(
            client_ip,
            "admin_access",
            "/admin",
            "admin",
            "Admin panel opened (authorized)"
        )

    else:

        add_event(
            client_ip,
            "admin_access",
            "/admin",
            "Admin panel opened (no access control!)"
        )

 
    # USER SEARCH / FILTER

    search_query = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "").strip()

    db = get_db()


    sql = """
        SELECT
            id,
            username,
            email,
            full_name,
            role,
            bio,
            location,
            website,
            member_since
        FROM users
        WHERE 1=1
    """

    params = []


    if search_query:

        sql += """
            AND (
                username LIKE ?
                OR email LIKE ?
                OR full_name LIKE ?
                OR role LIKE ?
            )
        """

        search_pattern = "%" + search_query + "%"

        params.extend([
            search_pattern,
            search_pattern,
            search_pattern,
            search_pattern
        ])


    if role_filter:

        sql += """
            AND role = ?
        """

        params.append(role_filter)


    sql += """
        ORDER BY id ASC
    """


    rows = db.execute(
        sql,
        tuple(params)
    ).fetchall()


    
    # BUILD USER LIST
    

    users = []

    for row in rows:

        user = dict(row)


        # Find latest successful login

        last_login = db.execute("""
            SELECT timestamp
            FROM events
            WHERE event_type = 'login_success'
              AND username = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (
            user["username"],
        )).fetchone()


        if last_login:

            user["last_login"] = last_login["timestamp"]

        else:

            user["last_login"] = None


        users.append(user)


    
    # STATISTICS

    total_users = db.execute("""
        SELECT COUNT(*) AS count
        FROM users
    """).fetchone()["count"]


    # There is currently no active/inactive field
    # in the database.

    active_users = total_users


    # There is currently no MFA field
    # in the database.

    mfa_enabled = 0


    
    # ROLES
  
    roles = db.execute("""
        SELECT DISTINCT role
        FROM users
        WHERE role IS NOT NULL
          AND role != ''
        ORDER BY role
    """).fetchall()


    db.close()


   
    # RENDER ADMIN PAGE
    
    return render_template(
        "admin.html",

        users=users,

        total_users=total_users,
        active_users=active_users,
        mfa_enabled=mfa_enabled,

        roles=roles,

        search_query=search_query,
        role_filter=role_filter
    )

#  ADMIN - ADD USER

@app.route("/admin/users/add", methods=["POST"])
def admin_add_user():

    client_ip = get_client_ip()

    
    # Access control
    if secure_mode_enabled():

        if session.get("user_id") != 2:

            add_event(
                client_ip,
                "admin_users_denied",
                "/admin/users/add",
                "Non-admin tried to create a user"
            )

            return "Access denied", 403


    
    # Get form data
  

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    email = request.form.get("email", "").strip()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "").strip()
    location = request.form.get("location", "").strip()
    website = request.form.get("website", "").strip()
    bio = request.form.get("bio", "").strip()


    # Validation

    if not username:
        flash("Username is required.")
        return redirect(url_for("admin") + "#user-management")

    if not password:
        flash("Password is required.")
        return redirect(url_for("admin") + "#user-management")

    if not email:
        flash("Email is required.")
        return redirect(url_for("admin") + "#user-management")

    if not full_name:
        flash("Full name is required.")
        return redirect(url_for("admin") + "#user-management")

    if not role:
        flash("Role is required.")
        return redirect(url_for("admin") + "#user-management")

   
    # Database
    
    db = get_db()


    existing = db.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()


    if existing:

        db.close()

        flash(
            "Username '{}' already exists.".format(username)
        )

        return redirect(
            url_for("admin") + "#user-management"
        )

 
    # Create user
  
    member_since = datetime.now().strftime("%Y-%m-%d")


    db.execute(
        """
        INSERT INTO users (
            username,
            password,
            email,
            full_name,
            role,
            bio,
            location,
            website,
            member_since
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            password,
            email,
            full_name,
            role,
            bio,
            location,
            website,
            member_since
        )
    )


    db.commit()
    db.close()


    # SOC event
    
    add_event(
        client_ip,
        "admin_user_created",
        "/admin/users/add",
        username,
        "Created user '{}' with role '{}'".format(
            username,
            role
        )
    )


    flash(
        "User '{}' was created successfully.".format(
            username
        )
    )


    # IMPORTANT:
    # Return to the SAME admin page.
    return redirect(
        url_for("admin") + "#user-management"
    )

@app.route("/logout")
def logout():
    add_event(get_client_ip(), "logout", "/logout")
    session.clear()
    return redirect("/")


#  SOC dashboard 

@app.route("/soc")
def soc_dashboard():
    summary = {
        "events": database.count_events(),
        "alerts": database.count_alerts(),
        "open_alerts": database.count_open_alerts(),
        "blocked": len(database.get_blocked_ips()),
        "recent_alerts": database.get_recent_alerts(8),
        "recent_events": database.get_recent_events(10),
        "responses": database.get_responses(8),
    }
    return render_template("soc_dashboard.html", **summary)


@app.route("/soc/api/summary")
def soc_api_summary():
    """JSON feed polled by the dashboard every few seconds."""
    return jsonify({
        "mode": "secure" if secure_mode_enabled() else "insecure",
        "events": database.count_events(),
        "alerts": database.count_alerts(),
        "open_alerts": database.count_open_alerts(),
        "blocked": len(database.get_blocked_ips()),
        "recent_alerts": [dict(a, timestamp=fmt_clock12(a["timestamp"]))
                               for a in database.get_recent_alerts(6)],
    })


@app.route("/soc/alerts")
def soc_alerts():
    return render_template("soc_alerts.html",
                           alerts=database.get_recent_alerts(100))


@app.route("/soc/events")
def soc_events():
    return render_template("soc_events.html",
                           events=database.get_recent_events(100))


@app.route("/soc/responses")
def soc_responses():
    return render_template("soc_responses.html",
                           responses=database.get_responses(100),
                           blocked=database.get_blocked_ips())


@app.route("/soc/alert/<int:alert_id>")
def soc_alert_details(alert_id):
    alert = database.get_alert(alert_id)
    if not alert:
        abort(404)
    related = database.get_recent_events(100)
    related = [e for e in related if e["source_ip"] == alert["source_ip"]][:15]
    return render_template("attack_details.html", alert=alert,
                           related=related,
                           blocked=ip_blocker.is_blocked(alert["source_ip"]))


@app.route("/soc/simulate-scan", methods=["POST"])
def soc_simulate_scan():
    ip = request.form.get("ip", "").strip() or "203.0.113.77"
    count = network_monitor.simulate_scan(ip)
    # Run one detection sweep right away so the alert appears instantly
    processed, alerts_created = ENGINE.run_once()
    flash("Simulated scan from {} hit {} honeypot port(s) - "
          "{} new alert(s).".format(ip, count, alerts_created))
    return redirect(url_for("soc_dashboard"))


@app.route("/soc/unblock/<path:ip>", methods=["POST"])
def soc_unblock(ip):
    ip_blocker.unblock(ip)
    flash("IP {} removed from the blocklist.".format(ip))
    return redirect(url_for("soc_responses"))


@app.route("/mode", methods=["POST"])
def toggle_mode():
    """Switch the whole app between insecure (vulnerable) and secure mode."""
    value = request.form.get("mode", "insecure")
    database.set_setting("mode", "secure" if value == "secure" else "insecure")
    add_event(get_client_ip(), "mode_change", "/mode", "",
              "Application switched to {}".format(value))
    flash("Application is now in {} mode.".format(value))
    return redirect(request.referrer or url_for("soc_dashboard"))


if __name__ == "__main__":
    init_db()
    # make sure demo users/products exist on a brand-new database
    db = get_db()
    has_users = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] > 0
    db.close()
    if not has_users:
        seed_data()
    # demo seeding removed on request: the SOC starts empty and is populated
    # live by real attacks during the exhibition (SQLi, brute force, scans)
    network_monitor.start_honeypots()
    ENGINE.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
