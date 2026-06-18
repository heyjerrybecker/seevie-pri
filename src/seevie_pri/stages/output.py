from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.table import Table

from seevie_pri.context import TriageContext


def output(ctx: TriageContext) -> TriageContext:
    fmt = ctx.options.get("format", "table")
    output_path = ctx.options.get("output")

    if fmt == "json":
        content = format_json(ctx)
    else:
        content = format_table(ctx)

    if output_path:
        Path(output_path).write_text(content)
    else:
        print(content, end="")

    return ctx


def format_json(ctx: TriageContext) -> str:
    result = {
        "version": "1.0",
        "findings": [
            {
                "rank": f.rank,
                "cve_id": f.scored.match.cve_id,
                "severity": f.scored.match.severity,
                "component": f.scored.match.affected_component.name,
                "component_version": f.scored.match.affected_component.version,
                "fixed_version": f.scored.match.fixed_version,
                "topology_score": f.scored.topology_score,
                "compatibility_score": f.scored.compatibility_score,
                "combined_score": f.scored.combined_score,
                "upgrade_path": f.upgrade_path,
                "action": f.action,
            }
            for f in ctx.rankings
        ],
        "summary": {
            "total_findings": len(ctx.rankings),
            "high_risk": sum(
                1 for f in ctx.rankings if f.scored.combined_score >= 0.7
            ),
            "components_scanned": len(ctx.components),
        },
    }
    return json.dumps(result, indent=2)


def format_table(ctx: TriageContext) -> str:
    buf = StringIO()
    console = Console(file=buf, no_color=False, width=120)

    by_cve: dict[str, list] = {}
    for finding in ctx.rankings:
        cve_id = finding.scored.match.cve_id
        by_cve.setdefault(cve_id, []).append(finding)

    for cve_id, findings in by_cve.items():
        severity = findings[0].scored.match.severity
        affected_name = findings[0].scored.match.affected_component.name
        fixed = findings[0].scored.match.fixed_version or "unknown"

        console.print(f"\n[bold]{cve_id}[/bold] — [red]{severity}[/red]")
        console.print(f"  Affected: {affected_name} < {fixed}\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4)
        table.add_column("Component", min_width=30)
        table.add_column("Risk", width=6)
        table.add_column("Upgrade Path", width=18)
        table.add_column("Action", min_width=20)

        for f in findings:
            table.add_row(
                str(f.rank),
                f.scored.match.affected_component.name,
                f"{f.scored.combined_score:.2f}",
                f.upgrade_path,
                f.action,
            )

        console.print(table)

        high_risk = sum(1 for f in findings if f.scored.combined_score >= 0.7)
        console.print(
            f"  {len(findings)} affected component(s). {high_risk} high-risk.\n"
        )

    return buf.getvalue()
