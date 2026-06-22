from __future__ import annotations

import argparse
import sys
from pathlib import Path

from seevie_pri.context import TriageContext
from seevie_pri.db import (
    DEFAULT_DB_PATH,
    init_db,
    store_sbom,
    store_components,
    list_sboms,
    store_findings,
    clear_findings,
    get_findings,
)
from seevie_pri.pipeline import run
from seevie_pri.stages.match import match
from seevie_pri.stages.output import output, format_json, format_table
from seevie_pri.stages.parse import parse
from seevie_pri.stages.rank import rank
from seevie_pri.stages.score import score


def main():
    parser = argparse.ArgumentParser(
        prog="seevie-pri",
        description="Vulnerability triage engine",
    )
    sub = parser.add_subparsers(dest="command")

    # triage — one-shot mode (unchanged)
    triage_cmd = sub.add_parser("triage", help="One-shot SBOM triage")
    triage_cmd.add_argument("--sbom", required=True, type=Path)
    triage_cmd.add_argument("--format", choices=["table", "json"], default="table")
    triage_cmd.add_argument("--output", type=Path)
    triage_cmd.add_argument("--cve-data", type=Path)
    triage_cmd.add_argument("--ecosystem", choices=["maven", "npm", "pypi", "go"])
    triage_cmd.add_argument("--threshold", type=float, default=0.0)
    triage_cmd.add_argument("--no-nvd", action="store_true")
    triage_cmd.add_argument("--verbose", action="store_true")
    triage_cmd.add_argument("--repo", type=Path, help="Source code path for reachability analysis")

    # index — store SBOM in database
    index_cmd = sub.add_parser("index", help="Index an SBOM for persistent monitoring")
    index_cmd.add_argument("--sbom", required=True, type=Path)
    index_cmd.add_argument("--name", type=str, help="Human label for this SBOM")
    index_cmd.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)

    # rescan — re-triage all indexed SBOMs
    rescan_cmd = sub.add_parser("rescan", help="Re-triage all indexed SBOMs")
    rescan_cmd.add_argument("--format", choices=["table", "json"], default="table")
    rescan_cmd.add_argument("--output", type=Path)
    rescan_cmd.add_argument("--no-nvd", action="store_true")
    rescan_cmd.add_argument("--threshold", type=float, default=0.0)
    rescan_cmd.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    rescan_cmd.add_argument("--repo", type=Path, help="Source code path for reachability analysis")

    # serve — start REST API
    serve_cmd = sub.add_parser("serve", help="Start the REST API server")
    serve_cmd.add_argument("--port", type=int, default=8080)
    serve_cmd.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(2)

    if args.command == "triage":
        _cmd_triage(args)
    elif args.command == "index":
        _cmd_index(args)
    elif args.command == "rescan":
        _cmd_rescan(args)
    elif args.command == "serve":
        _cmd_serve(args)


def _cmd_triage(args):
    if not args.sbom.exists():
        print(f"Error: SBOM file not found: {args.sbom}", file=sys.stderr)
        sys.exit(2)

    ctx = TriageContext(
        sbom_path=args.sbom,
        options={
            "format": args.format,
            "output": str(args.output) if args.output else None,
            "cve_data": str(args.cve_data) if args.cve_data else None,
            "ecosystem": args.ecosystem,
            "threshold": args.threshold,
            "no_nvd": args.no_nvd,
            "verbose": args.verbose,
            "repo": str(args.repo) if args.repo else None,
        },
    )

    stages = [parse, match, score, rank, output]

    try:
        ctx = run(ctx, stages)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    high_risk = any(f.scored.combined_score >= 0.7 for f in ctx.rankings)
    sys.exit(1 if high_risk else 0)


def _cmd_index(args):
    if not args.sbom.exists():
        print(f"Error: SBOM file not found: {args.sbom}", file=sys.stderr)
        sys.exit(2)

    ctx = TriageContext(sbom_path=args.sbom)
    ctx = parse(ctx)

    name = args.name or args.sbom.stem
    ecosystem = ""
    for comp in ctx.components:
        if comp.ecosystem:
            ecosystem = comp.ecosystem
            break

    conn = init_db(args.db)
    existing = [s for s in list_sboms(conn) if s["name"] == name]
    sbom_id = store_sbom(conn, name=name, ecosystem=ecosystem,
                         sbom_path=str(args.sbom.resolve()))
    store_components(conn, sbom_id, ctx.components)
    conn.close()

    verb = "Updated" if existing else "Indexed"
    print(f"{verb} {name}: {len(ctx.components)} components (id: {sbom_id})")
    sys.exit(0)


def _cmd_rescan(args):
    conn = init_db(args.db)
    sboms = list_sboms(conn)

    if not sboms:
        print("No SBOMs indexed. Use 'seevie-pri index' first.", file=sys.stderr)
        conn.close()
        sys.exit(2)

    clear_findings(conn)

    all_rankings = []
    all_components = []

    for sbom in sboms:
        sbom_path = Path(sbom["sbom_path"])
        if not sbom_path.exists():
            print(f"Warning: SBOM file missing: {sbom_path}", file=sys.stderr)
            continue

        ctx = TriageContext(
            sbom_path=sbom_path,
            options={
                "no_nvd": args.no_nvd,
                "threshold": args.threshold,
                "repo": str(args.repo) if args.repo else None,
            },
        )

        stages = [parse, match, score, rank]
        try:
            ctx = run(ctx, stages)
        except Exception as e:
            print(f"Error scanning {sbom['name']}: {e}", file=sys.stderr)
            continue

        store_findings(conn, sbom["id"], ctx.rankings)
        all_rankings.extend(ctx.rankings)
        all_components.extend(ctx.components)

    conn.close()

    combined_ctx = TriageContext(
        components=all_components,
        rankings=all_rankings,
        options={
            "format": args.format,
            "output": str(args.output) if args.output else None,
        },
    )

    if args.format == "json":
        content = format_json(combined_ctx)
    else:
        content = format_table(combined_ctx)

    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")

    high_risk = any(f.scored.combined_score >= 0.7 for f in all_rankings)
    sys.exit(1 if high_risk else 0)


def _cmd_serve(args):
    import uvicorn
    from seevie_pri.server import create_app

    app = create_app(args.db)
    print(f"Starting SeeviePri API on port {args.port}")
    print(f"Database: {args.db}")
    print(f"API docs: http://localhost:{args.port}/docs")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
