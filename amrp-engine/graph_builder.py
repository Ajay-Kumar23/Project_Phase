"""
graph_builder.py
-----------------
Connects to live Hubble flow data (via `hubble observe -o json --follow`)
and builds a real-time service dependency graph using networkx.

Nodes = services (namespace/app label, derived from pod_name)
Edges = observed traffic between services, weighted by flow count.

Run:
    python3 graph_builder.py
Stop with Ctrl+C.
"""

import subprocess
import json
import re
import networkx as nx
from datetime import datetime

# Live graph object — this is what your risk-scoring engine (Week 3) will read from.
service_graph = nx.DiGraph()


def extract_service_name(pod_name: str) -> str:
    """
    Turn a pod name like 'frontend-56455998f9-k4j9s' into a stable
    service name like 'frontend' by stripping the ReplicaSet/pod hash suffixes.
    """
    if not pod_name:
        return "unknown"
    # Strip the last two dash-separated hash segments (ReplicaSet hash + pod hash)
    parts = pod_name.split("-")
    if len(parts) > 2:
        return "-".join(parts[:-2])
    return pod_name


def process_flow(flow_json: dict):
    flow = flow_json.get("flow")
    if not flow:
        return

    src = flow.get("source", {})
    dst = flow.get("destination", {})

    src_pod = src.get("pod_name")
    dst_pod = dst.get("pod_name")

    # Skip flows where we can't identify a real service on both ends
    # (e.g. health checks, host-to-host, DNS to coredns can be kept or filtered as needed)
    if not src_pod or not dst_pod:
        return

    src_service = extract_service_name(src_pod)
    dst_service = extract_service_name(dst_pod)

    if src_service == dst_service:
        return  # ignore self-loops

    verdict = flow.get("verdict", "UNKNOWN")

    # Add/update the edge with a running traffic count
    if service_graph.has_edge(src_service, dst_service):
        service_graph[src_service][dst_service]["count"] += 1
    else:
        service_graph.add_edge(src_service, dst_service, count=1)

    service_graph.nodes[src_service]["namespace"] = src.get("namespace", "default")
    service_graph.nodes[dst_service]["namespace"] = dst.get("namespace", "default")

    if verdict == "DROPPED":
        print(f"[{datetime.now().strftime('%H:%M:%S')}] DROPPED  {src_service} -> {dst_service}")


def print_graph_summary():
    print("\n--- Current Service Graph ---")
    for u, v, data in service_graph.edges(data=True):
        print(f"  {u:25s} -> {v:25s}  (flows seen: {data['count']})")
    print(f"Nodes: {service_graph.number_of_nodes()}  Edges: {service_graph.number_of_edges()}\n")


def main():
    print("Starting Hubble flow stream... (Ctrl+C to stop)\n")
    process = subprocess.Popen(
        ["hubble", "observe", "-o", "json", "--follow"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    flow_count = 0
    try:
        for line in process.stdout:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                flow_json = json.loads(line)
            except json.JSONDecodeError:
                continue

            process_flow(flow_json)
            flow_count += 1

            # Print a live summary every 25 flows so you can see the graph grow
            if flow_count % 25 == 0:
                print_graph_summary()

    except KeyboardInterrupt:
        print("\nStopping... final graph state:")
        print_graph_summary()
        process.terminate()


if __name__ == "__main__":
    main()
