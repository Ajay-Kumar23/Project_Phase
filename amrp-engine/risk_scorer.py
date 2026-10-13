"""
risk_scorer.py
--------------
Takes a service graph (built by graph_builder.py) and the name of a
compromised service (flagged by detector.py), and calculates a risk
score for every other service based on graph distance (hop count).

This is the core of your novel contribution — turning "X is compromised"
into "here is exactly how much risk every other service in the
application is under."

Risk levels:
    CRITICAL  -> the compromised service itself
    HIGH      -> 1 hop away (direct neighbor, either direction)
    MEDIUM    -> 2 hops away
    LOW       -> 3+ hops away, or unreachable

Run standalone for a demo using a sample graph:
    python3 risk_scorer.py
"""

import networkx as nx


def score_risk(graph: nx.DiGraph, compromised_service: str) -> dict:
    """
    Returns a dict: {service_name: risk_level} for every node in the graph,
    based on shortest-path distance (in either direction) from the
    compromised service.
    """
    if compromised_service not in graph:
        raise ValueError(f"'{compromised_service}' not found in the service graph")

    # Treat the graph as undirected for distance purposes — an attacker
    # can potentially move along a connection regardless of which way
    # the traffic was originally initiated.
    undirected = graph.to_undirected()

    # BFS shortest path lengths from the compromised node to every
    # other reachable node.
    distances = nx.single_source_shortest_path_length(undirected, compromised_service)

    risk_scores = {}
    for node in graph.nodes():
        distance = distances.get(node)  # None if unreachable

        if node == compromised_service:
            risk_scores[node] = "CRITICAL"
        elif distance == 1:
            risk_scores[node] = "HIGH"
        elif distance == 2:
            risk_scores[node] = "MEDIUM"
        elif distance is not None and distance >= 3:
            risk_scores[node] = "LOW"
        else:
            risk_scores[node] = "LOW"  # unreachable = not a lateral movement path, low risk

    return risk_scores


def print_risk_report(risk_scores: dict, compromised_service: str):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_services = sorted(risk_scores.items(), key=lambda x: order[x[1]])

    print(f"\n=== Risk Report (source: {compromised_service}) ===")
    for service, risk in sorted_services:
        marker = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[risk]
        print(f"  {marker} {risk:8s}  {service}")
    print()


if __name__ == "__main__":
    # Sample graph reconstructed from your actual graph_builder.py output,
    # so you can test this file standalone before wiring it into main.py.
    demo_graph = nx.DiGraph()
    edges = [
        ("loadgenerator", "frontend"),
        ("frontend", "loadgenerator"),
        ("frontend", "adservice"),
        ("frontend", "coredns"),
        ("frontend", "productcatalogservice"),
        ("frontend", "currencyservice"),
        ("frontend", "cartservice"),
        ("frontend", "recommendationservice"),
        ("frontend", "shippingservice"),
        ("coredns", "frontend"),
        ("adservice", "frontend"),
        ("productcatalogservice", "frontend"),
        ("productcatalogservice", "recommendationservice"),
        ("currencyservice", "frontend"),
        ("cartservice", "redis-cart"),
        ("cartservice", "frontend"),
        ("redis-cart", "cartservice"),
        ("recommendationservice", "productcatalogservice"),
        ("recommendationservice", "frontend"),
        ("shippingservice", "frontend"),
        ("emailservice", "checkoutservice"),
        ("checkoutservice", "emailservice"),
    ]
    demo_graph.add_edges_from(edges)

    compromised = "emailservice"
    scores = score_risk(demo_graph, compromised)
    print_risk_report(scores, compromised)
