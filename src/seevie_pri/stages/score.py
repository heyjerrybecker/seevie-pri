from __future__ import annotations

import networkx as nx

from seevie_pri.context import CVEMatch, ScoredMatch, TriageContext


def score(ctx: TriageContext) -> TriageContext:
    name_to_nodes: dict[str, list[str]] = {}
    for node_id in ctx.graph.nodes:
        comp = ctx.graph.nodes[node_id].get("component")
        if comp:
            name_to_nodes.setdefault(comp.name, []).append(node_id)

    scored = []
    for m in ctx.matches:
        vuln_nodes = name_to_nodes.get(m.affected_component.name, [])
        topo = score_topology(ctx.graph, vuln_nodes, ctx.root_node)
        compat = score_version_compatibility(m)
        combined = topo * (1 - compat)

        scored.append(ScoredMatch(
            match=m,
            topology_score=round(topo, 4),
            compatibility_score=round(compat, 4),
            combined_score=round(combined, 4),
        ))

    ctx.scores = scored
    return ctx


def score_topology(
    graph: nx.DiGraph, vuln_nodes: list[str], root: str
) -> float:
    if not vuln_nodes or len(graph) < 2:
        return 0.0

    betweenness = nx.betweenness_centrality(graph)
    scores = []

    for vn in vuln_nodes:
        reachable = len(nx.ancestors(graph, vn))
        try:
            depth = nx.shortest_path_length(graph, root, vn)
        except nx.NetworkXNoPath:
            depth = len(graph)

        fan_in = graph.in_degree(vn)
        n = len(graph)

        bc = betweenness.get(vn, 0)
        reach_norm = reachable / max(n - 1, 1)
        depth_norm = 1 - (depth / max(n - 1, 1))
        fan_norm = fan_in / max(n - 1, 1)

        s = 0.25 * bc + 0.25 * reach_norm + 0.25 * depth_norm + 0.25 * fan_norm
        scores.append(s)

    return max(scores)


def score_version_compatibility(match: CVEMatch) -> float:
    if match.fixed_version is None:
        return 0.0
    if match.affected_component.direct:
        return 0.8
    return 0.3
