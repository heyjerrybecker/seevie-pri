from __future__ import annotations

import json

import networkx as nx

from seevie_pri.context import Component, TriageContext
from seevie_pri.purl import parse_purl


def parse(ctx: TriageContext) -> TriageContext:
    raw = ctx.sbom_path.read_bytes()
    fmt = detect_format(raw)

    if fmt == "cyclonedx-json":
        components, graph, root = _parse_cyclonedx_json(raw)
    elif fmt == "cyclonedx-xml":
        components, graph, root = _parse_cyclonedx_xml(raw)
    elif fmt == "spdx-json":
        raise NotImplementedError("SPDX support coming in a future release")
    else:
        raise ValueError(f"Unrecognized SBOM format: {fmt}")

    ctx.components = components
    ctx.graph = graph
    ctx.root_node = root
    return ctx


def detect_format(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore").lstrip()

    if text.startswith("{"):
        data = json.loads(text)
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx-json"
        if "spdxVersion" in data:
            return "spdx-json"

    if "<bom" in text and "cyclonedx" in text.lower():
        return "cyclonedx-xml"

    raise ValueError("Unrecognized SBOM format")


def _parse_cyclonedx_json(raw: bytes) -> tuple[list[Component], nx.DiGraph, str]:
    data = json.loads(raw)
    components = []
    graph = nx.DiGraph()
    ref_to_comp: dict[str, Component] = {}

    meta_comp = data.get("metadata", {}).get("component", {})
    root_ref = meta_comp.get("bom-ref", "root")
    root = _json_to_component(meta_comp)
    root.direct = True
    components.append(root)
    graph.add_node(root_ref, component=root)
    ref_to_comp[root_ref] = root

    for comp_data in data.get("components", []):
        comp = _json_to_component(comp_data)
        bom_ref = comp_data.get("bom-ref", comp.name)
        components.append(comp)
        graph.add_node(bom_ref, component=comp)
        ref_to_comp[bom_ref] = comp

    for dep in data.get("dependencies", []):
        parent_ref = dep["ref"]
        for child_ref in dep.get("dependsOn", []):
            if parent_ref in graph and child_ref in graph:
                graph.add_edge(parent_ref, child_ref)

    for child_ref in graph.successors(root_ref):
        if child_ref in ref_to_comp:
            ref_to_comp[child_ref].direct = True

    return components, graph, root_ref


def _parse_cyclonedx_xml(raw: bytes) -> tuple[list[Component], nx.DiGraph, str]:
    raise NotImplementedError("CycloneDX XML parsing — implemented in Task 4")


def _json_to_component(data: dict) -> Component:
    purl_str = data.get("purl")
    version = data.get("version", "")

    if purl_str:
        ecosystem, name, _ = parse_purl(purl_str)
    else:
        group = data.get("group", "")
        comp_name = data.get("name", "")
        name = f"{group}:{comp_name}" if group else comp_name
        ecosystem = ""

    return Component(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl_str,
        direct=False,
    )
