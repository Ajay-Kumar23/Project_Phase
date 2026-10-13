"""
vulnerable_service.py
----------------------
A deliberately vulnerable microservice for demonstration purposes.

This exposes a "ping" diagnostic endpoint that takes a host parameter and
runs a real shell ping command against it — WITHOUT sanitizing the input.
This is a genuine, real OS command injection vulnerability (CWE-78),
functionally identical in class to DVWA's Command Injection module, but
with zero database dependency, making it far lighter to run.

DO NOT deploy this pattern in any real application. This file exists
ONLY to be intentionally exploited in a controlled lab/demo environment.

Example legitimate use:
    GET /ping?host=127.0.0.1

Example exploitation (what an attacker would send):
    GET /ping?host=127.0.0.1;whoami
    GET /ping?host=127.0.0.1;wget checkoutservice:5050 --timeout=3
"""

from flask import Flask, request
import subprocess
import threading
import time
import urllib.request

app = Flask(__name__)


HEARTBEAT_SECONDS = 10


def register_with_mesh():
    """
    Make a real outbound call to checkoutservice, repeated forever every
    HEARTBEAT_SECONDS, so that Cilium Hubble records this service as a
    participant in the service graph.

    IMPORTANT: hubble observe --follow (used by graph_builder.py / main.py)
    is a LIVE stream — it never replays flows that happened before the
    stream started, and graph_builder's in-memory graph is rebuilt from
    scratch every time main.py restarts. A one-shot registration burst at
    pod startup is therefore not reliable: if that burst finishes before
    main.py's hubble thread is listening, this service never appears in
    the graph until something generates a fresh flow by hand.

    Making this a permanent heartbeat (instead of stopping after ~60s)
    guarantees that no matter when main.py is (re)started, a fresh flow
    to checkoutservice occurs within HEARTBEAT_SECONDS, so containment
    for this service becomes reliable instead of a manual timing race.
    """
    time.sleep(5)
    while True:
        try:
            urllib.request.urlopen(
                "http://checkoutservice:5050", timeout=3
            )
        except Exception:
            pass  # expected: checkoutservice speaks gRPC not HTTP
                  # but the connection attempt itself is enough for
                  # Hubble to record the inter-pod flow
        time.sleep(HEARTBEAT_SECONDS)


@app.route("/register")
def register():
    """
    On-demand version of the heartbeat in register_with_mesh(): forces one
    immediate outbound call to checkoutservice right now, so you can
    deterministically get this pod into the live Hubble/graph_builder
    graph instead of waiting up to HEARTBEAT_SECONDS for the background
    thread's next tick. Use this right before firing the exploit if you
    want to be 100% sure the node is already in main.py's graph:

        curl http://localhost:8080/register
    """
    try:
        urllib.request.urlopen("http://checkoutservice:5050", timeout=3)
        detail = "connection succeeded"
    except Exception as e:
        # Expected: checkoutservice speaks gRPC, not HTTP, so this will
        # usually raise (e.g. ConnectionResetError). That's fine — the
        # TCP flow itself is what Hubble records; the app-level response
        # doesn't matter.
        detail = f"connection attempt made (exception is expected: {e})"
    return {"status": "ok", "detail": detail}, 200


@app.route("/health")
def health():
    return {"status": "ok", "service": "vulnerable-service"}, 200


@app.route("/")
def home():
    return (
        "<h2>Vulnerable Diagnostic Service (demo only)</h2>"
        "<p>Try: <code>/ping?host=127.0.0.1</code></p>"
        "<p>This endpoint is intentionally vulnerable to OS command injection.</p>"
    )


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE ON PURPOSE: host is passed straight into a shell command
    # with no sanitization or allowlisting. This is a textbook OS command
    # injection (CWE-78), used here only for a controlled security demo.
    command = f"ping -c 1 {host}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    return f"<pre>{output}</pre>"


if __name__ == "__main__":
    threading.Thread(target=register_with_mesh, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
