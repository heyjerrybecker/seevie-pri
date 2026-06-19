from __future__ import annotations

import sqlite3
from pathlib import Path

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
