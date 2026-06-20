from __future__ import annotations

import sqlite3
from pathlib import Path

import networkx as nx

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from seevie_pri.db import (
    fetch_epss_scores,
    get_findings,
    get_findings_for_sbom,
    get_summary,
    list_sboms,
    clear_findings,
    store_findings,
    update_business_value,
)
from seevie_pri.context import TriageContext
from seevie_pri.pipeline import run
from seevie_pri.stages.match import match
from seevie_pri.stages.parse import parse
from seevie_pri.stages.rank import rank
from seevie_pri.stages.score import score

templates_dir = Path(__file__).parent / "templates"


def _compute_architecture_insights(sboms):
    if len(sboms) < 2:
        return None

    comp_services = {}  # comp_name -> set of service names
    service_comp_counts = {}  # service_name -> set of comp_names

    for sbom in sboms:
        sbom_path = Path(sbom["sbom_path"])
        if not sbom_path.exists():
            continue
        try:
            ctx = TriageContext(sbom_path=sbom_path)
            ctx = parse(ctx)
        except Exception:
            continue

        service_comps = set()
        for node_id in ctx.graph.nodes:
            comp = ctx.graph.nodes[node_id].get("component")
            if comp:
                comp_services.setdefault(comp.name, set()).add(sbom["name"])
                service_comps.add(comp.name)
        service_comp_counts[sbom["name"]] = service_comps

    total_services = len(sboms)
    total_unique_deps = len(comp_services)

    # Shared deps (in 2+ services)
    shared = {name: svcs for name, svcs in comp_services.items() if len(svcs) >= 2}
    shared_sorted = sorted(shared.items(), key=lambda x: len(x[1]), reverse=True)

    # Most shared
    most_shared = None
    if shared_sorted:
        name, svcs = shared_sorted[0]
        short_name = name.split(":")[-1] if ":" in name else name
        most_shared = {
            "name": short_name,
            "full_name": name,
            "count": len(svcs),
            "pct": round(len(svcs) / total_services * 100),
        }

    # Most structurally critical (highest betweenness across all graphs)
    merged = nx.DiGraph()
    for sbom in sboms:
        sbom_path = Path(sbom["sbom_path"])
        if not sbom_path.exists():
            continue
        try:
            ctx = TriageContext(sbom_path=sbom_path)
            ctx = parse(ctx)
        except Exception:
            continue
        for node_id in ctx.graph.nodes:
            comp = ctx.graph.nodes[node_id].get("component")
            if comp:
                merged.add_node(comp.name)
        for u, v in ctx.graph.edges:
            u_comp = ctx.graph.nodes[u].get("component")
            v_comp = ctx.graph.nodes[v].get("component")
            if u_comp and v_comp:
                merged.add_edge(u_comp.name, v_comp.name)

    most_central = None
    if len(merged) > 2:
        bc = nx.betweenness_centrality(merged)
        top = max(bc, key=bc.get)
        short_name = top.split(":")[-1] if ":" in top else top
        most_central = {"name": short_name, "full_name": top, "score": round(bc[top], 4)}

    # Least connected service
    least_connected = None
    if service_comp_counts:
        least = min(
            service_comp_counts.items(),
            key=lambda x: sum(1 for c in x[1] if c in shared),
        )
        least_connected = {
            "name": least[0],
            "shared": sum(1 for c in least[1] if c in shared),
        }

    concentration_pct = round(len(shared) / max(total_unique_deps, 1) * 100)

    shared_deps = [
        {"name": name.split(":")[-1] if ":" in name else name, "full_name": name,
         "services": sorted(svcs), "count": len(svcs)}
        for name, svcs in shared_sorted[:15]
    ]

    return {
        "total_services": total_services,
        "most_shared": most_shared,
        "most_central": most_central,
        "least_connected": least_connected,
        "shared_count": len(shared),
        "concentration_pct": concentration_pct,
        "shared_deps": shared_deps,
    }


def create_dashboard_router(conn: sqlite3.Connection) -> APIRouter:
    router = APIRouter(prefix="/dashboard")
    templates = Jinja2Templates(directory=str(templates_dir))

    @router.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        summary = get_summary(conn)
        return templates.TemplateResponse(request, "overview.html", {
            "active_page": "overview",
            "summary": summary,
        })

    @router.get("/services", response_class=HTMLResponse)
    def services(request: Request):
        sboms = list_sboms(conn)
        return templates.TemplateResponse(request, "services.html", {
            "active_page": "services",
            "sboms": sboms,
        })

    @router.get("/architecture", response_class=HTMLResponse)
    def architecture(request: Request):
        sboms = list_sboms(conn)
        insights = _compute_architecture_insights(sboms)
        return templates.TemplateResponse(request, "architecture.html", {
            "active_page": "architecture",
            "insights": insights,
        })

    @router.get("/architecture/graph")
    def architecture_graph():
        sboms = list_sboms(conn)
        all_nodes = []
        all_edges = []
        comp_services = {}  # comp_name -> set of service names
        findings_list = get_findings(conn)
        vuln_components = {f["component"] for f in findings_list}

        for sbom in sboms:
            sbom_path = Path(sbom["sbom_path"])
            if not sbom_path.exists():
                continue
            ctx = TriageContext(sbom_path=sbom_path)
            try:
                ctx = parse(ctx)
            except Exception:
                continue

            prefix = sbom["name"]

            # Add service node (diamond shape)
            all_nodes.append({
                "id": f"svc:{prefix}",
                "label": prefix,
                "title": f"{prefix} ({sbom['ecosystem']})",
                "shape": "diamond",
                "color": "#ffa502",
                "size": 20,
                "font": {"color": "#fff", "size": 13, "bold": True},
                "borderWidth": 2,
            })

            for node_id in ctx.graph.nodes:
                comp = ctx.graph.nodes[node_id].get("component")
                if not comp:
                    continue
                comp_services.setdefault(comp.name, set()).add(prefix)

                node_key = f"{prefix}:{node_id}"
                is_vuln = comp.name in vuln_components
                downstream = len(nx.descendants(ctx.graph, node_id))
                upstream = len(nx.ancestors(ctx.graph, node_id))

                all_nodes.append({
                    "id": node_key,
                    "label": comp.name.split(":")[-1] if ":" in comp.name else comp.name,
                    "title": f"{comp.name}@{comp.version} (in: {prefix})",
                    "shape": "dot",
                    "color": "#e94560" if is_vuln else "#2a5a6a",
                    "size": 8,
                    "font": {"color": "#e0e0e0", "size": 9},
                    "borderWidth": 1,
                    "fullName": comp.name,
                    "version": comp.version,
                    "service": prefix,
                    "downstream": downstream,
                    "upstream": upstream,
                    "isDirect": comp.direct,
                    "isVuln": is_vuln,
                })

                if comp.direct:
                    all_edges.append({
                        "from": f"svc:{prefix}",
                        "to": node_key,
                        "arrows": "to",
                        "color": {"color": "#1e1e3a"},
                        "width": 1,
                    })

            for u, v in ctx.graph.edges:
                all_edges.append({
                    "from": f"{prefix}:{u}",
                    "to": f"{prefix}:{v}",
                    "arrows": "to",
                    "color": {"color": "#1e1e3a"},
                    "width": 1,
                })

        # Second pass: update shared dep colors/sizes based on service count
        for node in all_nodes:
            if node.get("shape") == "diamond":
                continue
            # Extract comp name from title
            comp_name = node["title"].split("@")[0] if "@" in node.get("title", "") else ""
            svc_count = len(comp_services.get(comp_name, set()))
            if node["color"] != "#e94560":  # don't override vulnerable
                if svc_count >= 3:
                    node["color"] = "#ffa502"
                    node["size"] = 14
                elif svc_count >= 2:
                    node["color"] = "#45b7d1"
                    node["size"] = 11

        return {"nodes": all_nodes, "edges": all_edges}

    @router.get("/services/{sbom_id}", response_class=HTMLResponse)
    def service_detail(request: Request, sbom_id: str):
        sboms = list_sboms(conn)
        sbom = next((s for s in sboms if s["id"] == sbom_id), None)
        findings = get_findings_for_sbom(conn, sbom_id)
        return templates.TemplateResponse(request, "service_detail.html", {
            "active_page": "services",
            "sbom": sbom,
            "findings": findings,
        })

    @router.get("/services/{sbom_id}/graph")
    def service_graph(sbom_id: str):
        sboms = list_sboms(conn)
        sbom = next((s for s in sboms if s["id"] == sbom_id), None)
        if not sbom:
            return {"nodes": [], "edges": []}

        sbom_path = Path(sbom["sbom_path"])
        if not sbom_path.exists():
            return {"nodes": [], "edges": []}

        ctx = TriageContext(sbom_path=sbom_path)
        ctx = parse(ctx)

        findings_list = get_findings_for_sbom(conn, sbom_id)
        vuln_components = {f["component"] for f in findings_list}
        finding_counts = {}
        for f in findings_list:
            finding_counts[f["component"]] = finding_counts.get(f["component"], 0) + 1

        nodes = []
        for node_id in ctx.graph.nodes:
            comp = ctx.graph.nodes[node_id].get("component")
            if not comp:
                continue
            is_vuln = comp.name in vuln_components
            nodes.append({
                "id": node_id,
                "label": comp.name.split(":")[-1] if ":" in comp.name else comp.name,
                "title": f"{comp.name}@{comp.version}",
                "color": "#e94560" if is_vuln else "#4ecdc4" if comp.direct else "#2a5a6a",
                "size": 15 + (finding_counts.get(comp.name, 0) * 5) if is_vuln else 10,
                "font": {"color": "#e0e0e0"},
                "borderWidth": 2 if is_vuln else 1,
                "borderWidthSelected": 3,
            })

        edges = []
        for u, v in ctx.graph.edges:
            edges.append({
                "from": u,
                "to": v,
                "arrows": "to",
                "color": {"color": "#1e1e3a", "highlight": "#4ecdc4"},
            })

        return {"nodes": nodes, "edges": edges}

    @router.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request, severity: str | None = None,
                      min_score: float | None = None):
        findings = get_findings(conn, severity=severity, min_score=min_score)
        return templates.TemplateResponse(request, "findings.html", {
            "active_page": "findings",
            "findings": findings,
            "current_severity": severity or "",
            "current_min_score": min_score or 0,
        })

    @router.get("/upload", response_class=HTMLResponse)
    def upload_page(request: Request):
        return templates.TemplateResponse(request, "upload.html", {
            "active_page": "upload",
        })

    @router.get("/_findings_table", response_class=HTMLResponse)
    def findings_table_partial(request: Request, severity: str | None = None,
                               min_score: float | None = None):
        findings = get_findings(conn, severity=severity, min_score=min_score)
        rows = ""
        for f in findings:
            sev = f["severity"].lower()
            br = f.get("blast_radius", 1)
            br_bg = "#e9456030" if br >= 3 else "#ffa50230" if br >= 2 else "#1e1e3a"
            rows += (
                f'<tr><td style="font-family:\'JetBrains Mono\',monospace;font-size:12px;">{f["cve_id"]}</td>'
                f'<td><span class="badge {sev}">{f["severity"]}</span></td>'
                f'<td style="text-align:center;"><span style="background:{br_bg};padding:3px 10px;border-radius:10px;font-family:\'JetBrains Mono\',monospace;font-size:12px;font-weight:600;">{br} svc{"s" if br != 1 else ""}</span></td>'
                f'<td>{f["component"]}</td>'
                f'<td>{f["sbom_name"]}</td>'
                f'<td>{f["combined_score"]:.2f}</td>'
                f'<td>{f["fixed_version"] or "—"}</td>'
                f'<td>{f["action"]}</td></tr>'
            )
        return HTMLResponse(rows if rows else '<tr><td colspan="8" style="text-align:center;color:#888;padding:24px;">No findings match the current filters.</td></tr>')

    @router.post("/_rescan", response_class=HTMLResponse)
    def rescan_partial():
        sboms = list_sboms(conn)
        if not sboms:
            return HTMLResponse('<span style="color:#888;">No SBOMs indexed.</span>')

        clear_findings(conn)
        total = 0
        high = 0
        all_cve_ids = []

        scan_results = []
        for sbom in sboms:
            sbom_path = Path(sbom["sbom_path"])
            if not sbom_path.exists():
                continue
            ctx = TriageContext(sbom_path=sbom_path, options={"no_nvd": True})
            stages = [parse, match, score, rank]
            try:
                ctx = run(ctx, stages)
            except Exception:
                continue
            scan_results.append((sbom, ctx))
            all_cve_ids.extend(f.scored.match.cve_id for f in ctx.rankings)

        epss_scores = fetch_epss_scores(list(set(all_cve_ids)))

        for sbom, ctx in scan_results:
            bv = sbom.get("business_value", 1_000_000)
            store_findings(conn, sbom["id"], ctx.rankings,
                           epss_scores=epss_scores, business_value=bv)
            total += len(ctx.rankings)
            high += sum(1 for f in ctx.rankings
                        if f.scored.match.severity in ("HIGH", "CRITICAL"))

        exposure = sum(
            f.get("financial_risk", 0) for f in get_findings(conn)
        )
        exp_str = f"${exposure:,.0f}" if exposure else "$0"

        return HTMLResponse(
            f'<span>Scanned {len(sboms)} service(s). {total} finding(s), '
            f'{high} high/critical. {exp_str} total exposure.</span>'
        )

    @router.post("/_update_business_value")
    async def update_bv(request: Request):
        data = await request.json()
        update_business_value(conn, data["sbom_id"], data["business_value"])
        return {"status": "updated"}

    return router
