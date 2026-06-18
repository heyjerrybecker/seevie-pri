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

    by_component: dict[str, list] = {}
    for finding in ctx.rankings:
        comp_name = finding.scored.match.affected_component.name
        by_component.setdefault(comp_name, []).append(finding)

    for comp_name, findings in by_component.items():
        comp = findings[0].scored.match.affected_component
        worst_severity = _worst_severity([f.scored.match.severity for f in findings])

        console.print(f"\n[bold]{comp_name}[/bold] @ {comp.version} — [red]{worst_severity}[/red]")
        console.print(f"  {len(findings)} CVE(s) affecting this component\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4)
        table.add_column("CVE", min_width=24)
        table.add_column("Severity", width=10)
        table.add_column("Risk", width=6)
        table.add_column("Fix", width=12)
        table.add_column("Action", min_width=20)

        for f in findings:
            table.add_row(
                str(f.rank),
                f.scored.match.cve_id,
                f.scored.match.severity,
                f"{f.scored.combined_score:.2f}",
                f.scored.match.fixed_version or "none",
                f.action,
            )

        console.print(table)

    total = len(ctx.rankings)
    high_risk = sum(1 for f in ctx.rankings if f.scored.combined_score >= 0.7)
    components_hit = len(by_component)
    console.print(
        f"\n[bold]{total} finding(s)[/bold] across {components_hit} component(s). "
        f"{high_risk} high-risk.\n"
    )

    return buf.getvalue()


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _worst_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0))
