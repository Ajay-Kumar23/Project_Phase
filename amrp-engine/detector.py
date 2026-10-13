"""
detector.py
-----------
Connects to live Tetragon process events (via `tetra getevents -o json`)
and flags suspicious activity inside application pods.

This is your "Detection Layer" — it doesn't decide what to do about a
threat, it just raises an alert. main.py (Week 3 final step) will connect
this alert to the risk scorer and policy generator.

Run (needs kubectl access to the cluster):
    python3 detector.py
Stop with Ctrl+C.
"""

import subprocess
import json
from datetime import datetime

# Binaries that are suspicious if they suddenly appear inside an
# application pod (not kube-system) — classic signs of a shell/reverse
# shell/reconnaissance after a compromise. Extend this list as needed.
SUSPICIOUS_BINARIES = {
    "/bin/sh", "/bin/bash", "/bin/dash",
    "/usr/bin/nc", "/bin/nc", "/usr/bin/ncat",
    "/usr/bin/wget", "/usr/bin/curl",
    "/usr/bin/nmap",
    "/usr/bin/python3", "/usr/bin/python",
    "/usr/bin/socat",
    "/usr/bin/ssh",
}

# Namespaces we don't care about (system/infra noise)
IGNORED_NAMESPACES = {"kube-system", "kube-node-lease", "kube-public"}


def extract_pod_service_name(pod_name: str) -> str:
    """Same stripping logic as graph_builder.py, so names line up."""
    if not pod_name:
        return "unknown"
    parts = pod_name.split("-")
    if len(parts) > 2:
        return "-".join(parts[:-2])
    return pod_name


def check_event(event_json: dict):
    exec_event = event_json.get("process_exec")
    if not exec_event:
        return  # we only care about process_exec (new process started)

    process = exec_event.get("process", {})
    binary = process.get("binary", "")
    args = process.get("arguments", "")
    pod = process.get("pod", {})
    pod_name = pod.get("name")
    namespace = pod.get("namespace", "")

    if not pod_name or namespace in IGNORED_NAMESPACES:
        return  # ignore infra/system noise

    if binary in SUSPICIOUS_BINARIES:
        # Avoid a feedback loop: main.py's own kill_process() remediation
        # runs "sh -c kill -9 <pid>" inside the pod, which would otherwise
        # be flagged as a NEW suspicious event by this same detector.
        if "kill -9" in args or "kill -SIGKILL" in args:
            return None

        service_name = extract_pod_service_name(pod_name)
        pid = process.get("pid")
        uid = process.get("uid")
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n🚨 [{timestamp}] SUSPICIOUS PROCESS DETECTED")
        print(f"    Service:   {service_name}")
        print(f"    Pod:       {pod_name}  (namespace: {namespace})")
        print(f"    Binary:    {binary}")
        print(f"    Arguments: {args}")
        print(f"    PID:       {pid}   UID: {uid}")
        print(f"    --> This service should be treated as COMPROMISED: {service_name}\n")

        return {
            "service": service_name,
            "pod": pod_name,
            "namespace": namespace,
            "binary": binary,
            "arguments": args,
            "pid": pid,
            "uid": uid,
        }

    return None


def main():
    print("Starting Tetragon event stream... (Ctrl+C to stop)")
    print(f"Watching for suspicious binaries: {sorted(SUSPICIOUS_BINARIES)}\n")

    process = subprocess.Popen(
        ["kubectl", "exec", "-n", "kube-system", "ds/tetragon",
         "-c", "tetragon", "--", "tetra", "getevents", "-o", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # Show anything unexpected (errors, warnings) instead of hiding it
                print(f"[non-json output] {line}")
                continue
            try:
                event_json = json.loads(line)
            except json.JSONDecodeError:
                continue

            check_event(event_json)

    except KeyboardInterrupt:
        print("\nStopping detector.")
        process.terminate()


if __name__ == "__main__":
    main()
