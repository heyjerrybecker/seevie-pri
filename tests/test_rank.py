from seevie_pri.context import (
    Component, CVEMatch, RankedFinding, ScoredMatch, TriageContext,
)
from seevie_pri.stages.rank import rank


def _scored(name, combined, severity="HIGH", direct=True, fixed="2.0"):
    comp = Component(name=name, version="1.0", ecosystem="maven", direct=direct)
    m = CVEMatch(cve_id="CVE-1", severity=severity, affected_component=comp,
                 fixed_version=fixed)
    return ScoredMatch(match=m, topology_score=combined, compatibility_score=0.0,
                       combined_score=combined)


def test_rank_sorts_descending():
    ctx = TriageContext(scores=[
        _scored("low", 0.2),
        _scored("high", 0.9),
        _scored("mid", 0.5),
    ])
    ctx = rank(ctx)

    assert [r.scored.match.affected_component.name for r in ctx.rankings] == [
        "high", "mid", "low"
    ]
    assert [r.rank for r in ctx.rankings] == [1, 2, 3]


def test_rank_action_high_risk_direct():
    ctx = TriageContext(scores=[_scored("lib", 0.8, direct=True, fixed="2.0")])
    ctx = rank(ctx)
    assert ctx.rankings[0].action == "UPGRADE AVAILABLE"
    assert ctx.rankings[0].upgrade_path == "clean"


def test_rank_action_high_risk_transitive():
    ctx = TriageContext(scores=[_scored("lib", 0.8, direct=False, fixed="2.0")])
    ctx = rank(ctx)
    assert ctx.rankings[0].action == "MANUAL UPGRADE REQUIRED"
    assert ctx.rankings[0].upgrade_path == "transitive"


def test_rank_action_no_fix():
    ctx = TriageContext(scores=[_scored("lib", 0.8, fixed=None)])
    ctx = rank(ctx)
    assert "NO FIX" in ctx.rankings[0].action
    assert ctx.rankings[0].upgrade_path == "no fix available"


def test_rank_action_medium():
    ctx = TriageContext(scores=[_scored("lib", 0.5)])
    ctx = rank(ctx)
    assert ctx.rankings[0].action == "PRIORITIZE"


def test_rank_action_low():
    ctx = TriageContext(scores=[_scored("lib", 0.1)])
    ctx = rank(ctx)
    assert ctx.rankings[0].action == "SCHEDULE FOR NEXT SPRINT"


def test_rank_threshold_filters():
    ctx = TriageContext(
        scores=[_scored("high", 0.9), _scored("low", 0.1)],
        options={"threshold": 0.5},
    )
    ctx = rank(ctx)
    assert len(ctx.rankings) == 1
    assert ctx.rankings[0].scored.match.affected_component.name == "high"
