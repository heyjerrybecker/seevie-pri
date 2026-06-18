from __future__ import annotations

from seevie_pri.context import CVEMatch, RankedFinding, TriageContext


def rank(ctx: TriageContext) -> TriageContext:
    threshold = ctx.options.get("threshold", 0.0)
    filtered = [s for s in ctx.scores if s.combined_score >= threshold]
    filtered.sort(key=lambda s: s.combined_score, reverse=True)

    rankings = []
    for i, scored in enumerate(filtered, 1):
        upgrade_path = _determine_upgrade_path(scored.match)
        action = _determine_action(scored.combined_score, upgrade_path)
        rankings.append(RankedFinding(
            rank=i,
            scored=scored,
            action=action,
            upgrade_path=upgrade_path,
        ))

    ctx.rankings = rankings
    return ctx


def _determine_upgrade_path(match: CVEMatch) -> str:
    if match.fixed_version is None:
        return "no fix available"
    if match.affected_component.direct:
        return "clean"
    return "transitive"


def _determine_action(combined_score: float, upgrade_path: str) -> str:
    if combined_score >= 0.7:
        if upgrade_path == "no fix available":
            return "INVESTIGATE — NO FIX AVAILABLE"
        if upgrade_path == "transitive":
            return "MANUAL UPGRADE REQUIRED"
        return "UPGRADE AVAILABLE"
    if combined_score >= 0.3:
        return "PRIORITIZE"
    return "SCHEDULE FOR NEXT SPRINT"
