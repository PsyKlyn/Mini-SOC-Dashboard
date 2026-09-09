// Live SOC dashboard: polls the summary API every 3 seconds and refreshes
// the page in place. All values are inserted with textContent so
// attacker-controlled data can never execute as HTML.

function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
}

// Severity strings map onto fixed CSS classes (sev-critical, sev-high, ...).
function sevClass(value) {
    var known = { critical: 1, high: 1, medium: 1, low: 1, info: 1 };
    var key = String(value || "info").toLowerCase();
    return known[key] ? key : "info";
}

function td(text) {
    var cell = document.createElement("td");
    cell.textContent = text;
    return cell;
}

// Rebuild the "Recent alerts" table body in place. The header and the
// surrounding table come from the template, so nothing is duplicated.
function renderRecentAlerts(rows) {
    var body = document.getElementById("recent-alerts-body");
    if (!body) return;
    body.innerHTML = "";

    rows.forEach(function (alert) {
        var tr = document.createElement("tr");

        tr.appendChild(td(alert.timestamp));

        var link = document.createElement("a");
        link.href = "/soc/alert/" + alert.id;
        link.textContent = alert.alert_type;
        var typeCell = document.createElement("td");
        typeCell.appendChild(link);
        tr.appendChild(typeCell);

        var badge = document.createElement("span");
        badge.className = "sev sev-" + sevClass(alert.severity);
        badge.textContent = alert.severity;
        var sevCell = document.createElement("td");
        sevCell.appendChild(badge);
        tr.appendChild(sevCell);

        tr.appendChild(td(alert.source_ip));
        tr.appendChild(td(alert.response_status));

        body.appendChild(tr);
    });
}

function refresh() {
    fetch("/soc/api/summary")
        .then(function (response) { return response.json(); })
        .then(function (data) {
            setText("stat-events", data.events);
            setText("stat-alerts", data.alerts);
            setText("stat-open", data.open_alerts);
            setText("stat-blocked", data.blocked);

            var pill = document.getElementById("mode-pill");
            if (pill) {
                pill.textContent = data.mode === "secure" ? "Secure mode" : "Insecure mode (vulnerable)";
                pill.className = "mode-pill " + data.mode;
            }

            renderRecentAlerts(data.recent_alerts || []);
        })
        .catch(function () { /* offline / server restarting: ignore */ });
}

refresh();
setInterval(refresh, 3000);
