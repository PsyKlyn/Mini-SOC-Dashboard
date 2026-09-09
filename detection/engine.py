# ---------- DETECTION ENGINE ----------
# Background thread that sweeps logged events and asks the right
# detector for each one. Detected attacks become alerts and are passed
# to the responder, which chooses an automated defensive action.

import threading
import time

import config
import database
import detection.brute_force as brute_force
import detection.idor_detector as idor_detector
import detection.port_scan as port_scan
import detection.sqli_detector as sqli_detector
from collector import log_collector
from response import responder


class DetectionEngine(object):

    def __init__(self, interval=config.ENGINE_INTERVAL):
        self.interval = interval
        self._stop = threading.Event()

    # ---------- routing ----------

    def _route(self, event):
        """Pick the right detector for one event, or None."""
        event_type = event["event_type"]
        ip = event["source_ip"] or "0.0.0.0"
        if event_type == "login_failed":
            return brute_force.check(ip, event.get("username") or "")
        if event_type == "search":
            details = event.get("details") or ""
            query = details.partition("=")[2] if details.startswith("q=") else details
            return sqli_detector.check_query(query, ip)
        if event_type == "profile_access":
            return idor_detector.check(event.get("details"), ip)
        if event_type == "port_probe":
            return port_scan.check(ip)
        return None

    # ---------- one sweep ----------

    def run_once(self):
        """Process all currently pending events. Returns (processed, alerts)."""
        processed = 0
        alerts_created = 0
        for event in database.get_pending_events(limit=200):
            alert = None
            try:
                alert = self._route(event)
            except Exception:
                alert = None  # never let one bad event kill the sweep
            database.mark_event_processed(event["id"])
            processed += 1
            if alert:
                alert_id = database.add_alert(
                    alert_type=alert["alert_type"],
                    severity=alert["severity"],
                    source_ip=alert["source_ip"],
                    description=alert["description"],
                    username=alert.get("username", ""),
                    endpoint=alert.get("endpoint", ""))
                responder.respond_to_alert(alert_id)
                alerts_created += 1
        return processed, alerts_created

    # ---------- background thread ----------

    def start(self):
        log_collector.append_log("INFO", "Detection engine started "
                                         "(every {}s)".format(self.interval))
        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()
        return thread

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()


ENGINE = DetectionEngine()
