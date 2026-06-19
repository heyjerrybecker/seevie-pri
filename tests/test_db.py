from pathlib import Path

from seevie_pri.db import (
    init_db,
    store_sbom,
    store_components,
    list_sboms,
    store_findings,
    get_findings,
    get_findings_for_sbom,
    clear_findings,
    get_summary,
)
from seevie_pri.context import Component, RankedFinding, ScoredMatch, CVEMatch


def test_init_db_creates_tables(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]
    assert "sboms" in tables
    assert "components" in tables
    assert "findings" in tables
    conn.close()


def test_store_and_list_sboms(tmp_path):
    conn = init_db(tmp_path / "test.db")
    sbom_id = store_sbom(conn, name="payment-api", ecosystem="maven",
                         sbom_path="/path/to/bom.json")

    sboms = list_sboms(conn)
    assert len(sboms) == 1
    assert sboms[0]["id"] == sbom_id
    assert sboms[0]["name"] == "payment-api"
    assert sboms[0]["ecosystem"] == "maven"
    conn.close()


def test_store_and_retrieve_components(tmp_path):
    conn = init_db(tmp_path / "test.db")
    sbom_id = store_sbom(conn, name="test", ecosystem="maven",
                         sbom_path="/path/to/bom.json")

    components = [
        Component(name="log4j-core", version="2.14.1", ecosystem="maven",
                  purl="pkg:maven/org.apache/log4j-core@2.14.1", direct=True),
        Component(name="spring-beans", version="5.3.17", ecosystem="maven",
                  purl="pkg:maven/org.springframework/spring-beans@5.3.17", direct=False),
    ]
    store_components(conn, sbom_id, components)

    sboms = list_sboms(conn)
    assert sboms[0]["component_count"] == 2
    conn.close()


def test_store_and_get_findings(tmp_path):
    conn = init_db(tmp_path / "test.db")
    sbom_id = store_sbom(conn, name="test", ecosystem="maven",
                         sbom_path="/path/to/bom.json")

    comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven", direct=True)
    match = CVEMatch(cve_id="CVE-2021-44228", severity="CRITICAL",
                     affected_component=comp, fixed_version="2.16.0")
    scored = ScoredMatch(match=match, topology_score=0.3,
                         compatibility_score=0.8, combined_score=0.06)
    finding = RankedFinding(rank=1, scored=scored, action="UPGRADE AVAILABLE",
                            upgrade_path="clean")

    store_findings(conn, sbom_id, [finding])

    results = get_findings(conn)
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2021-44228"
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["sbom_name"] == "test"

    results_by_sbom = get_findings_for_sbom(conn, sbom_id)
    assert len(results_by_sbom) == 1
    conn.close()


def test_clear_findings(tmp_path):
    conn = init_db(tmp_path / "test.db")
    sbom_id = store_sbom(conn, name="test", ecosystem="maven",
                         sbom_path="/path/to/bom.json")

    comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven", direct=True)
    match = CVEMatch(cve_id="CVE-1", severity="HIGH", affected_component=comp)
    scored = ScoredMatch(match=match, combined_score=0.5)
    finding = RankedFinding(rank=1, scored=scored, action="PRIORITIZE",
                            upgrade_path="clean")

    store_findings(conn, sbom_id, [finding])
    assert len(get_findings(conn)) == 1

    clear_findings(conn)
    assert len(get_findings(conn)) == 0
    conn.close()


def test_store_sbom_upsert(tmp_path):
    conn = init_db(tmp_path / "test.db")

    sbom_id_1 = store_sbom(conn, name="payment-api", ecosystem="maven",
                           sbom_path="/v1/bom.json")
    components_v1 = [
        Component(name="log4j-core", version="2.14.1", ecosystem="maven", direct=True),
    ]
    store_components(conn, sbom_id_1, components_v1)
    assert list_sboms(conn)[0]["component_count"] == 1

    sbom_id_2 = store_sbom(conn, name="payment-api", ecosystem="maven",
                           sbom_path="/v2/bom.json")
    components_v2 = [
        Component(name="log4j-core", version="2.16.0", ecosystem="maven", direct=True),
        Component(name="spring-beans", version="5.3.18", ecosystem="maven", direct=False),
    ]
    store_components(conn, sbom_id_2, components_v2)

    assert sbom_id_1 == sbom_id_2
    sboms = list_sboms(conn)
    assert len(sboms) == 1
    assert sboms[0]["component_count"] == 2
    assert sboms[0]["sbom_path"] == "/v2/bom.json"
    conn.close()


def test_get_summary(tmp_path):
    conn = init_db(tmp_path / "test.db")
    sbom_id = store_sbom(conn, name="test", ecosystem="maven",
                         sbom_path="/path/to/bom.json")

    comp = Component(name="log4j-core", version="2.14.1", ecosystem="maven", direct=True)
    match = CVEMatch(cve_id="CVE-1", severity="CRITICAL", affected_component=comp,
                     fixed_version="2.16.0")
    scored = ScoredMatch(match=match, topology_score=0.85,
                         compatibility_score=0.8, combined_score=0.85)
    finding = RankedFinding(rank=1, scored=scored, action="UPGRADE AVAILABLE",
                            upgrade_path="clean")
    store_findings(conn, sbom_id, [finding])

    summary = get_summary(conn)
    assert summary["total_findings"] == 1
    assert summary["high_risk"] == 1
    assert summary["services"] == 1
    assert summary["critical"] == 1
    assert summary["severity_counts"]["CRITICAL"] == 1
    assert "service_findings" in summary
    assert summary["service_findings"][0]["name"] == "test"
    conn.close()


def test_get_summary_empty(tmp_path):
    conn = init_db(tmp_path / "test.db")
    summary = get_summary(conn)
    assert summary["total_findings"] == 0
    assert summary["services"] == 0
    conn.close()
