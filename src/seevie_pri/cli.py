from __future__ import annotations

import argparse
import sys
from pathlib import Path

from seevie_pri.context import TriageContext
from seevie_pri.pipeline import run
from seevie_pri.stages.match import match
from seevie_pri.stages.output import output
from seevie_pri.stages.parse import parse
from seevie_pri.stages.rank import rank
from seevie_pri.stages.score import score


def main():
    parser = argparse.ArgumentParser(
        prog="seevie-pri",
        description="Vulnerability triage engine",
    )
    sub = parser.add_subparsers(dest="command")

    triage_cmd = sub.add_parser("triage", help="Triage vulnerabilities in an SBOM")
    triage_cmd.add_argument("--sbom", required=True, type=Path)
    triage_cmd.add_argument("--format", choices=["table", "json"], default="table")
    triage_cmd.add_argument("--output", type=Path)
    triage_cmd.add_argument("--cve-data", type=Path)
    triage_cmd.add_argument("--ecosystem", choices=["maven", "npm", "pypi", "go"])
    triage_cmd.add_argument("--threshold", type=float, default=0.0)
    triage_cmd.add_argument("--no-nvd", action="store_true")
    triage_cmd.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(2)

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
