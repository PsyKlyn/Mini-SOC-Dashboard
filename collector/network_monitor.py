# NETWORK MONITOR (honeypot) 

import socket
import threading
import time

import config
import database
from collector import log_collector

_probe_threads = []


def _handle_connection(port, conn, addr):
    ip = addr[0]
    database.add_event(ip, "port_probe", endpoint=str(port),
                       details="TCP connection to honeypot port {}".format(port))
    log_collector.append_log(
        "INFO", "Honeypot port {} contacted by {}".format(port, ip))
    try:
        conn.close()
    except OSError:
        pass


def _listen(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(8)
    except OSError:
        return
    while True:
        try:
            conn, addr = server.accept()
        except OSError:
            break
        threading.Thread(target=_handle_connection,
                         args=(port, conn, addr), daemon=True).start()


def start_honeypots():
    """Bind a listener thread on every honeypot port (called on app start)."""
    if _probe_threads:
        return _probe_threads
    for port in config.HONEYPOT_PORTS:
        thread = threading.Thread(target=_listen, args=(port,), daemon=True)
        thread.start()
        _probe_threads.append(thread)
    log_collector.append_log(
        "INFO", "Honeypot listeners started on ports " +
                ", ".join(str(p) for p in config.HONEYPOT_PORTS))
    return _probe_threads


def simulate_scan(ip="203.0.113.77"):
    """Simulate a (fictional) attacker probing all honeypot ports."""
    for port in config.HONEYPOT_PORTS:
        database.add_event(ip, "port_probe", endpoint=str(port),
                           details="SYN probe sent to honeypot port {}".format(port))
        time.sleep(0.05)
    log_collector.append_log(
        "INFO", "Simulated scan started from {} over {} port(s)".format(
            ip, len(config.HONEYPOT_PORTS)))
    return len(config.HONEYPOT_PORTS)
