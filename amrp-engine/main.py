"""
main.py
-------
Orchestrates the full AMRP pipeline, live, automatically:

  1. graph_builder     -> continuously builds the live service graph (Hubble)
  2. detector           -> continuously watches for suspicious process
                            activity across every node (Tetragon)
  3. risk_scorer         -> the moment a compromise is detected, scores
                            risk for every other service using the live graph
  4. policy_generator    -> generates AND applies a minimal
                            CiliumNetworkPolicy automatically — no manual
                            kubectl commands needed anymore

This is the file you run live during your demo.

Run:
    python3 main.py
Stop with Ctrl+C.
"""

import threading
import subprocess
import time
import json
import yaml

import graph_builder
import detector
import risk_scorer
import policy_generator
import dashboard_server

# How long (in seconds) a containment policy stays active before the engine
# automatically re-evaluates and lifts it, restoring normal connectivity.
# This models "risk decay" — the assumption that a threat's urgency
# decreases over time once contained, and a human/automated process should
# periodically confirm whether isolation is still needed.
ROLLBACK_AFTER_SECONDS = 60

# List every Tetragon pod in your cluster so detection covers ALL nodes,
# not just one. Update these names if they differ on your cluster
# (check with: kubectl get pods -n kube-system -o wide | grep tetragon)
TETRAGON_PODS = [
    "tetragon-7czd2",   # amrp-worker
    "tetragon-s56w9",   # amrp-worker2
    "tetragon-vgp7j",   # amrp-control-plane
]

already_contained = set()
lock = threading.Lock()


def run_graph_builder():
    """Background thread: keep the live service graph updated from Hubble."""
    process = subprocess.Popen(
        ["hubble", "observe", "-o", "json", "--follow"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    flow_count = 0
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        if not line.startswith("{"):
            # Surface anything unexpected (connection errors, version
            # mismatches, etc.) instead of silently discarding it — this
            # was previously hiding real startup failures.
            print(f"[hubble non-json output] {line}")
            continue
        try:
            flow_json = json.loads(line)
        except json.JSONDecodeError:
            continue
        graph_builder.process_flow(flow_json)
        flow_count += 1
        dashboard_server.update_graph(graph_builder.service_graph)  # update on every flow, not every 10th


def kill_process(pod: str, namespace: str, pid, binary: str) -> bool:
    """
    Best-effort attempt to terminate the actual malicious process inside
    the pod, using the PID Tetragon reported. This does NOT guarantee the
    attacker/vulnerability is gone (they may have already achieved
    persistence, or the process may have already exited) — it only removes
    the specific flagged process, as an additional response alongside
    network containment.

    Many minimal/distroless container images do not have a `kill` binary
    available, in which case this fails gracefully and is logged as such.
    """
    if not pid:
        return False

    result = subprocess.run(
        ["kubectl", "exec", "-n", namespace, pod, "--",
         "/bin/sh", "-c", f"kill -9 {pid}"],
        capture_output=True, text=True
    )
    success = result.returncode == 0
    print(f"    Process kill attempt (PID {pid}, {binary}): "
          f"{'SUCCEEDED' if success else 'FAILED — ' + result.stderr.strip()[:120]}")
    return success


def rollback(compromised_service: str, policy_name: str):
    """
    Automatically lifts a containment policy after ROLLBACK_AFTER_SECONDS,
    modeling risk decay: the assumption is that the operator/system has had
    time to investigate, and connectivity should be restored unless the
    threat is still active.
    """
    time.sleep(ROLLBACK_AFTER_SECONDS)

    print(f"\n{'='*60}")
    print(f">>> RISK DECAY: re-evaluating containment for {compromised_service}")
    print(f"{'='*60}")

    result = subprocess.run(
        ["kubectl", "delete", "ciliumnetworkpolicy", policy_name],
        capture_output=True, text=True
    )
    print(result.stdout.strip())
    if result.returncode != 0:
        print("ERROR removing policy (it may have already been deleted):", result.stderr.strip())
    else:
        print(f">>> Containment policy for {compromised_service} automatically LIFTED after "
              f"{ROLLBACK_AFTER_SECONDS}s — connectivity restored.")
        dashboard_server.add_alert(
            f"Risk decay: containment lifted for {compromised_service}, connectivity restored"
        )
        dashboard_server.add_policy(
            f"rollback-{policy_name}", compromised_service, ["(policy removed — all traffic restored)"]
        )
        dashboard_server.clear_incident(compromised_service)

    with lock:
        already_contained.discard(compromised_service)  # allow re-detection if it happens again

    print(f"{'='*60}\n")


def contain(incident: dict):
    """Given a compromise incident (service + process details), attempt to
    kill the offending process, score risk, and automatically apply
    network containment."""
    compromised_service = incident["service"]

    print(f"\n{'='*60}")
    print(f">>> CONTAINMENT TRIGGERED for: {compromised_service}")
    print(f"{'='*60}")

    dashboard_server.add_alert(
        f"Suspicious process detected in {compromised_service}: "
        f"{incident['binary']} {incident['arguments']} (PID {incident['pid']})"
    )

    # Active response: attempt to kill the actual flagged process, in
    # addition to network containment. This is a best-effort action — see
    # kill_process() docstring for its real-world limitations.
    killed = kill_process(incident["pod"], incident["namespace"], incident["pid"], incident["binary"])
    dashboard_server.add_alert(
        f"Process termination {'succeeded' if killed else 'attempted (failed — no kill utility in container)'} "
        f"for PID {incident['pid']} in {compromised_service}"
    )

    graph_builder.print_graph_summary()
    dashboard_server.update_graph(graph_builder.service_graph)

    # The compromised service might not be in the graph yet if the attack
    # happened very soon after startup, before Hubble reported any traffic
    # for it. Rather than giving up immediately, wait briefly and retry —
    # this fixes a real, recurring timing race observed during testing.
    max_wait_seconds = 15
    waited = 0
    while compromised_service not in graph_builder.service_graph and waited < max_wait_seconds:
        time.sleep(1)
        waited += 1

    if compromised_service not in graph_builder.service_graph:
        print(f"    '{compromised_service}' still not in the live graph after waiting "
              f"{max_wait_seconds}s (no traffic observed for it yet) — skipping containment for now.\n")
        return

    if waited > 0:
        print(f"    (waited {waited}s for '{compromised_service}' to appear in the live graph)")
        graph_builder.print_graph_summary()
        dashboard_server.update_graph(graph_builder.service_graph)

    scores = risk_scorer.score_risk(graph_builder.service_graph, compromised_service)
    risk_scorer.print_risk_report(scores, compromised_service)
    dashboard_server.update_risk_scores(compromised_service, scores)

    policy, targets = policy_generator.generate_policy(compromised_service, scores)
    policy_generator.print_policy(policy, targets, compromised_service)

    if not targets:
        print(f"    No HIGH risk neighbors found for '{compromised_service}' "
              f"— nothing to isolate yet.\n")
        return

    with open("generated_policy.yaml", "w") as f:
        yaml.dump(policy, f, sort_keys=False, default_flow_style=False)

    result = subprocess.run(
        ["kubectl", "apply", "-f", "generated_policy.yaml"],
        capture_output=True, text=True
    )
    print(result.stdout.strip())
    if result.returncode != 0:
        print("ERROR applying policy:", result.stderr)
    else:
        print(f">>> Containment policy APPLIED automatically for {compromised_service}")
        dashboard_server.add_alert(f"Policy applied: isolated {compromised_service} from {', '.join(targets)}")
        dashboard_server.add_policy(f"isolate-{compromised_service}", compromised_service, targets)

        # Schedule automatic rollback (risk decay) in the background so the
        # main pipeline isn't blocked waiting for it.
        policy_name = f"isolate-{compromised_service}"
        threading.Thread(
            target=rollback, args=(compromised_service, policy_name), daemon=True
        ).start()
        print(f"    (Auto-rollback scheduled in {ROLLBACK_AFTER_SECONDS}s unless re-triggered)")
    print(f"{'='*60}\n")


def run_detector(tetragon_pod: str):
    """Background thread: watch one Tetragon pod's events; trigger containment on detection."""
    process = subprocess.Popen(
        ["kubectl", "exec", "-n", "kube-system", tetragon_pod,
         "-c", "tetragon", "--", "tetra", "getevents", "-o", "json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    for line in process.stdout:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event_json = json.loads(line)
        except json.JSONDecodeError:
            continue

        incident = detector.check_event(event_json)
        if incident:
            compromised = incident["service"]
            with lock:
                if compromised in already_contained:
                    continue
                already_contained.add(compromised)
            contain(incident)


def main():
    print("=" * 60)
    print("  AMRP — Adaptive Microservice Runtime Protection")
    print("  LIVE containment engine running. Ctrl+C to stop.")
    print("=" * 60)
    print(f"\nWatching {len(TETRAGON_PODS)} node(s) for compromise, "
          f"building live service graph...\n")

    dashboard_server.start_server(port=8000)

    threads = [threading.Thread(target=run_graph_builder, daemon=True)]
    for pod in TETRAGON_PODS:
        threads.append(threading.Thread(target=run_detector, args=(pod,), daemon=True))

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down AMRP engine. Final graph state:")
        graph_builder.print_graph_summary()


if __name__ == "__main__":
    main()
