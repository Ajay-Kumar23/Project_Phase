"""
dashboard_server.py
--------------------
A tiny, dependency-free HTTP server that exposes the containment engine's
live state (service graph, latest risk scores, alerts, applied policies)
as JSON at http://localhost:8000/status.

The React/HTML dashboard polls this endpoint every couple of seconds to
show what's happening inside the engine in real time.

No Flask needed — uses Python's built-in http.server so there's nothing
extra to install.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {
    "graph": {"nodes": [], "edges": []},
    "active_incidents": {},   # {compromised_service: risk_scores_dict} for EVERY currently-active incident
    "alerts": [],       # list of {time, message}
    "policies": [],      # list of {time, name, compromised, blocked}
    "last_updated": None,
}
_lock = threading.Lock()


def update_graph(networkx_graph):
    with _lock:
        nodes = [{"id": n} for n in networkx_graph.nodes()]
        edges = [
            {"source": u, "target": v, "count": data.get("count", 1)}
            for u, v, data in networkx_graph.edges(data=True)
        ]
        STATE["graph"] = {"nodes": nodes, "edges": edges}
        STATE["last_updated"] = time.strftime("%H:%M:%S")


def update_risk_scores(compromised_service: str, risk_scores: dict):
    """Adds/updates this service's incident WITHOUT erasing other active incidents."""
    with _lock:
        STATE["active_incidents"][compromised_service] = risk_scores
        STATE["last_updated"] = time.strftime("%H:%M:%S")


def clear_incident(compromised_service: str):
    """Call this when a policy is rolled back — removes just this one incident."""
    with _lock:
        STATE["active_incidents"].pop(compromised_service, None)
        STATE["last_updated"] = time.strftime("%H:%M:%S")


def add_alert(message: str):
    with _lock:
        STATE["alerts"].insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "message": message,
        })
        STATE["alerts"] = STATE["alerts"][:20]  # keep last 20
        STATE["last_updated"] = time.strftime("%H:%M:%S")


def add_policy(name: str, compromised: str, blocked: list):
    with _lock:
        STATE["policies"].insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "name": name,
            "compromised": compromised,
            "blocked": blocked,
        })
        STATE["policies"] = STATE["policies"][:20]
        STATE["last_updated"] = time.strftime("%H:%M:%S")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/status":
            self.send_response(404)
            self.end_headers()
            return

        with _lock:
            body = json.dumps(STATE).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")  # allow dashboard.html to fetch this
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # silence default request logging so it doesn't clutter main.py's output


def start_server(port: int = 8000):
    server = HTTPServer(("0.0.0.0", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Dashboard API serving live state at http://localhost:{port}/status")
    return server
