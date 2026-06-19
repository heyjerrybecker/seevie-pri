from __future__ import annotations

import logging
import re

import httpx
import networkx as nx

from seevie_pri.context import CVEMatch, ScoredMatch, TriageContext
from seevie_pri.version import parse_version

logger = logging.getLogger(__name__)

DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/{system}/packages/{name}/versions/{version}:dependencies"

ECOSYSTEM_TO_SYSTEM = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "golang": "go",
}


def score(ctx: TriageContext) -> TriageContext:
    name_to_nodes: dict[str, list[str]] = {}
    for node_id in ctx.graph.nodes:
        comp = ctx.graph.nodes[node_id].get("component")
        if comp:
            name_to_nodes.setdefault(comp.name, []).append(node_id)

    constraints = _fetch_constraints(ctx)

    scored = []
    for m in ctx.matches:
        vuln_nodes = name_to_nodes.get(m.affected_component.name, [])
        topo = score_topology(ctx.graph, vuln_nodes, ctx.root_node)

        if constraints:
            compat = score_version_compatibility_with_constraints(
                ctx.graph, vuln_nodes, ctx.root_node,
                m.affected_component.name, m.fixed_version, constraints,
            )
        else:
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


def _fetch_constraints(ctx: TriageContext) -> dict[tuple[str, str], str]:
    root_comp = ctx.graph.nodes.get(ctx.root_node, {}).get("component")
    if not root_comp or not root_comp.purl:
        return {}

    system = ECOSYSTEM_TO_SYSTEM.get(root_comp.ecosystem, "")
    if not system:
        return {}

    name = root_comp.name
    version = root_comp.version
    if not version:
        return {}

    try:
        url = DEPS_DEV_URL.format(system=system, name=name, version=version)
        resp = httpx.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        logger.debug("deps.dev lookup failed for %s@%s, using heuristic", name, version)
        return {}

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    constraints: dict[tuple[str, str], str] = {}

    for edge in edges:
        from_idx = edge.get("fromNode", 0)
        to_idx = edge.get("toNode", 0)
        req = edge.get("requirement", "")
        if not req or from_idx >= len(nodes) or to_idx >= len(nodes):
            continue
        from_name = nodes[from_idx]["versionKey"]["name"]
        to_name = nodes[to_idx]["versionKey"]["name"]
        constraints[(from_name, to_name)] = req

    return constraints


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


def score_version_compatibility_with_constraints(
    graph: nx.DiGraph,
    vuln_nodes: list[str],
    root: str,
    vuln_name: str,
    fixed_version: str | None,
    constraints: dict[tuple[str, str], str],
) -> float:
    if not fixed_version or not vuln_nodes:
        return 0.0

    patch = parse_version(fixed_version)
    compatible_paths = 0
    total_paths = 0

    for vn in vuln_nodes:
        try:
            paths = list(nx.all_simple_paths(graph, root, vn))
        except nx.NodeNotFound:
            continue
        if not paths:
            continue

        for path in paths:
            total_paths += 1
            path_ok = True

            for j in range(len(path) - 1):
                src_node = path[j]
                tgt_node = path[j + 1]

                tgt_comp = graph.nodes[tgt_node].get("component")
                if not tgt_comp or tgt_comp.name != vuln_name:
                    continue

                src_comp = graph.nodes[src_node].get("component")
                if not src_comp:
                    continue

                req = constraints.get((src_comp.name, tgt_comp.name), "")
                if not req:
                    continue

                if not _version_satisfies(patch, req):
                    path_ok = False
                    break

            if path_ok:
                compatible_paths += 1

    if total_paths == 0:
        return 0.0

    return compatible_paths / total_paths


def _version_satisfies(version: tuple, requirement: str) -> bool:
    req_version = parse_version(requirement)
    if req_version == (0, 0, 0):
        if requirement.startswith("^"):
            base = parse_version(requirement[1:])
            if base == (0, 0, 0):
                return True
            return version >= base and version[0] == base[0]
        if requirement.startswith("~"):
            base = parse_version(requirement[1:])
            if base == (0, 0, 0):
                return True
            return version >= base and version[0] == base[0] and version[1] == base[1]
        if requirement.startswith(">="):
            base = parse_version(requirement[2:])
            return version >= base
        return True

    return version >= req_version
