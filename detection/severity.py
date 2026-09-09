# ---------- Severity helpers ----------

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

SEVERITY_COLOR = {
    "Info": "gray", "Low": "blue", "Medium": "yellow",
    "High": "orange", "Critical": "red",
}


def rank(severity):
    return SEVERITY_ORDER.get(severity, 0)


def highest(alerts):
    """Return the highest severity among a list of alert dicts."""
    if not alerts:
        return "Info"
    return max((a["severity"] for a in alerts), key=rank)
