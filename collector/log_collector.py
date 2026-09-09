# ---------- LOG COLLECTOR ----------
# Appends human-readable lines to logs/security.log. Every SOC action
# (events, detections, responses) is mirrored here so visitors can see
# the story of an attack in plain text.

import os

import database

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "logs", "security.log")


def append_log(level, message):
    """Write one '[TIME] [LEVEL] message' line to the security log."""
    directory = os.path.dirname(LOG_FILE)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(LOG_FILE, "a", encoding="utf-8") as handle:
        handle.write("{} [{}] {}\n".format(database.now(), level.upper(), message))


def recent_lines(n=40):
    """Return the last N log lines (newest last)."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as handle:
        lines = handle.readlines()
    return lines[-n:]
