from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile

from seevie_pri.context import TriageContext
from seevie_pri.db import (
    init_db,
    store_sbom,
    store_components,
    list_sboms,
    store_findings,
    get_findings,
    get_findings_for_sbom,
    clear_findings,
)
from seevie_pri.pipeline import run
from seevie_pri.stages.match import match
from seevie_pri.stages.parse import parse
from seevie_pri.stages.rank import rank
from seevie_pri.stages.score import score


def create_app(db_path: Path | None = None) -> FastAPI:
    app = FastAPI(title="SeeviePri", description="Vulnerability triage engine")

    if db_path is None:
        from seevie_pri.db import DEFAULT_DB_PATH
        db_path = DEFAULT_DB_PATH

    conn = init_db(db_path)

    @app.get("/sbom")
    def list_indexed_sboms():
        return list_sboms(conn)

    @app.post("/sbom")
    async def upload_sbom(
        file: UploadFile = File(...),
        name: str = Form(""),
    ):
        content = await file.read()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        ctx = TriageContext(sbom_path=tmp_path)
        ctx = parse(ctx)

        sbom_name = name or file.filename or "unnamed"
        ecosystem = ""
        for comp in ctx.components:
            if comp.ecosystem:
                ecosystem = comp.ecosystem
                break

        sbom_id = store_sbom(conn, name=sbom_name, ecosystem=ecosystem,
                             sbom_path=str(tmp_path))
        store_components(conn, sbom_id, ctx.components)

        return {
            "id": sbom_id,
            "name": sbom_name,
            "component_count": len(ctx.components),
            "indexed_at": list_sboms(conn)[0]["indexed_at"],
        }

    @app.post("/rescan")
    def rescan():
        sboms = list_sboms(conn)
        if not sboms:
            return {"sboms_scanned": 0, "total_findings": 0, "high_risk": 0}

        clear_findings(conn)
        total_findings = 0
        high_risk = 0

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

            store_findings(conn, sbom["id"], ctx.rankings)
            total_findings += len(ctx.rankings)
            high_risk += sum(
                1 for f in ctx.rankings if f.scored.combined_score >= 0.7
            )

        return {
            "sboms_scanned": len(sboms),
            "total_findings": total_findings,
            "high_risk": high_risk,
        }

    @app.get("/findings")
    def all_findings(severity: str | None = None, min_score: float | None = None):
        return get_findings(conn, severity=severity, min_score=min_score)

    @app.get("/findings/{sbom_id}")
    def sbom_findings(sbom_id: str):
        return get_findings_for_sbom(conn, sbom_id)

    return app
