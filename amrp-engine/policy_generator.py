"""
policy_generator.py
--------------------
Takes the risk report from risk_scorer.py and generates a minimal,
targeted CiliumNetworkPolicy YAML that isolates the compromised service
from its HIGH-risk neighbors only — leaving everything else (MEDIUM/LOW
risk services) completely untouched.

This is the artifact that proves your project's core claim: minimal
isolation, maximum availability. It doesn't lock down the whole app —
it cuts exactly the risky connections and nothing more.

Run standalone for a demo:
    python3 policy_generator.py
"""

import yaml
from datetime import datetime


def generate_policy(compromised_service: str, risk_scores: dict, namespace: str = "default") -> dict:
    """
    Builds a CiliumNetworkPolicy that:
      - Selects the compromised service as the endpoint the policy applies to
      - Allows all egress by default
      - Explicitly denies egress from the compromised service to every
        HIGH risk neighbor (i.e. cuts its ability to reach services it
        could spread to next)

    Returns a Python dict representing the policy — ready to dump as YAML
    or apply directly via the Kubernetes API (Week 3 final step, main.py).
    """
    high_risk_targets = [
        service for service, risk in risk_scores.items()
        if risk == "HIGH"
    ]

    policy_name = f"isolate-{compromised_service}"

    policy = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
        },
        "spec": {
            "endpointSelector": {
                "matchLabels": {
                    "app": compromised_service
                }
            },
            "egress": [
                {
                    "toEndpoints": [{}]
                }
            ],
            "egressDeny": [
                {
                    "toEndpoints": [
                        {
                            "matchLabels": {"app": target}
                        }
                    ]
                }
                for target in high_risk_targets
            ]
        }
    }

    return policy, high_risk_targets


def print_policy(policy: dict, high_risk_targets: list, compromised_service: str):
    print(f"\n=== Generated Containment Policy ===")
    print(f"Compromised service: {compromised_service}")
    print(f"Blocking egress to HIGH risk neighbors: {high_risk_targets}")
    print(f"All other services (MEDIUM/LOW risk) remain fully reachable.\n")
    print(yaml.dump(policy, sort_keys=False, default_flow_style=False))


if __name__ == "__main__":
    from risk_scorer import score_risk
    import networkx as nx

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

    policy, targets = generate_policy(compromised, scores)
    print_policy(policy, targets, compromised)

    with open("generated_policy.yaml", "w") as f:
        yaml.dump(policy, f, sort_keys=False, default_flow_style=False)
    print("Saved to generated_policy.yaml — you can apply it with:")
    print("  kubectl apply -f generated_policy.yaml\n")
