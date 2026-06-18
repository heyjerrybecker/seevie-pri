from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

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
        components, graph, root = _parse_spdx_json(raw)
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
    text = raw.decode("utf-8")
    # Strip default namespace for simpler XPath
    text = re.sub(r'\s+xmlns="[^"]*"', "", text, count=1)
    root_elem = ET.fromstring(text)

    components = []
    graph = nx.DiGraph()
    ref_to_comp: dict[str, Component] = {}

    meta_comp = root_elem.find(".//metadata/component")
    root_ref = meta_comp.get("bom-ref", "root") if meta_comp is not None else "root"
    if meta_comp is not None:
        root = _xml_to_component(meta_comp)
        root.direct = True
        components.append(root)
        graph.add_node(root_ref, component=root)
        ref_to_comp[root_ref] = root

    for comp_elem in root_elem.findall(".//components/component"):
        comp = _xml_to_component(comp_elem)
        bom_ref = comp_elem.get("bom-ref", comp.name)
        components.append(comp)
        graph.add_node(bom_ref, component=comp)
        ref_to_comp[bom_ref] = comp

    for dep in root_elem.findall(".//dependencies/dependency"):
        parent_ref = dep.get("ref")
        for child in dep.findall("dependency"):
            child_ref = child.get("ref")
            if parent_ref in graph and child_ref in graph:
                graph.add_edge(parent_ref, child_ref)

    for child_ref in graph.successors(root_ref):
        if child_ref in ref_to_comp:
            ref_to_comp[child_ref].direct = True

    return components, graph, root_ref


def _xml_to_component(elem) -> Component:
    purl_elem = elem.find("purl")
    purl_str = purl_elem.text if purl_elem is not None else None
    version_elem = elem.find("version")
    version = version_elem.text if version_elem is not None else ""

    if purl_str:
        ecosystem, name, _ = parse_purl(purl_str)
    else:
        group_elem = elem.find("group")
        name_elem = elem.find("name")
        group = group_elem.text if group_elem is not None else ""
        comp_name = name_elem.text if name_elem is not None else ""
        name = f"{group}:{comp_name}" if group else comp_name
        ecosystem = ""

    return Component(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl_str,
        direct=False,
    )


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


def _parse_spdx_json(raw: bytes) -> tuple[list[Component], nx.DiGraph, str]:
    data = json.loads(raw)
    components = []
    graph = nx.DiGraph()
    ref_to_comp: dict[str, Component] = {}

    for pkg in data.get("packages", []):
        spdx_id = pkg["SPDXID"]
        comp = _spdx_pkg_to_component(pkg)
        components.append(comp)
        graph.add_node(spdx_id, component=comp)
        ref_to_comp[spdx_id] = comp

    root_ref = ""
    for rel in data.get("relationships", []):
        rel_type = rel["relationshipType"]
        if rel_type == "DESCRIBES" and rel["spdxElementId"] == "SPDXRef-DOCUMENT":
            root_ref = rel["relatedSpdxElement"]
        elif rel_type == "DEPENDS_ON":
            parent = rel["spdxElementId"]
            child = rel["relatedSpdxElement"]
            if parent in graph and child in graph:
                graph.add_edge(parent, child)

    if not root_ref and components:
        root_ref = data["packages"][0]["SPDXID"]

    if root_ref in ref_to_comp:
        ref_to_comp[root_ref].direct = True

    for child_ref in graph.successors(root_ref):
        if child_ref in ref_to_comp:
            ref_to_comp[child_ref].direct = True

    return components, graph, root_ref


def _spdx_pkg_to_component(pkg: dict) -> Component:
    purl_str = None
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            purl_str = ref["referenceLocator"]
            break

    version = pkg.get("versionInfo", "")

    if purl_str:
        ecosystem, name, _ = parse_purl(purl_str)
    else:
        name = pkg.get("name", "")
        ecosystem = ""

    return Component(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl_str,
        direct=False,
    )
