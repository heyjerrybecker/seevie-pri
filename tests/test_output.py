import json

from seevie_pri.context import (
    Component, CVEMatch, RankedFinding, ScoredMatch, TriageContext,
)
from seevie_pri.stages.output import output, format_json, format_table


def _make_ctx():
    comp = Component(
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1",
        ecosystem="maven",
        direct=True,
    )
    match = CVEMatch(
        cve_id="CVE-2021-44228",
        severity="CRITICAL",
        affected_component=comp,
        fixed_version="2.16.0",
        source="osv",
    )
    scored = ScoredMatch(
        match=match,
        topology_score=0.85,
        compatibility_score=0.8,
        combined_score=0.17,
    )
    finding = RankedFinding(
        rank=1,
        scored=scored,
        action="UPGRADE AVAILABLE",
        upgrade_path="clean",
    )
    return TriageContext(
        components=[comp],
        rankings=[finding],
        options={"format": "json"},
    )


def test_format_json_structure():
    ctx = _make_ctx()
    raw = format_json(ctx)
    data = json.loads(raw)

    assert data["version"] == "1.0"
    assert len(data["findings"]) == 1

    f = data["findings"][0]
    assert f["cve_id"] == "CVE-2021-44228"
    assert f["severity"] == "CRITICAL"
    assert f["component"] == "org.apache.logging.log4j:log4j-core"
    assert f["fixed_version"] == "2.16.0"
    assert f["combined_score"] == 0.17
    assert f["action"] == "UPGRADE AVAILABLE"

    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["components_scanned"] == 1


def test_format_table_contains_key_info():
    ctx = _make_ctx()
    ctx.options["format"] = "table"
    text = format_table(ctx)

    assert "CVE-2021-44228" in text
    assert "CRITICAL" in text
    assert "log4j-core" in text
    assert "UPGRADE AVAILABLE" in text


def test_output_writes_to_file(tmp_path):
    ctx = _make_ctx()
    out_file = tmp_path / "results.json"
    ctx.options["output"] = str(out_file)
    ctx.options["format"] = "json"

    output(ctx)

    data = json.loads(out_file.read_text())
    assert len(data["findings"]) == 1
