from unittest.mock import patch, MagicMock
from pathlib import Path

from seevie_pri.context import Component, TriageContext, CVEMatch
from seevie_pri.stages.match import match, osv_match, offline_match, deduplicate

FIXTURES = Path(__file__).parent / "fixtures"


def _make_component(name, version, purl, direct=True):
    return Component(
        name=name, version=version, ecosystem="maven",
        purl=purl, direct=direct,
    )


BATCH_RESPONSE = {
    "results": [
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01T00:00:00Z"}]},
        {"vulns": []},
    ]
}

VULN_DETAIL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Log4j RCE",
    "affected": [
        {
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.0"},
                        {"fixed": "2.16.0"},
                    ],
                }
            ],
            "database_specific": {"severity": "CRITICAL"},
        }
    ],
}


@patch("seevie_pri.stages.match.httpx")
def test_osv_match_finds_vulnerability(mock_httpx):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = BATCH_RESPONSE
    mock_post_resp.raise_for_status = MagicMock()
    mock_httpx.post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = VULN_DETAIL
    mock_get_resp.raise_for_status = MagicMock()
    mock_httpx.get.return_value = mock_get_resp

    components = [
        _make_component(
            "org.apache.logging.log4j:log4j-core", "2.14.1",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        ),
        _make_component(
            "com.fasterxml.jackson.core:jackson-databind", "2.13.2",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
        ),
    ]

    matches = osv_match(components)

    assert len(matches) == 1
    assert matches[0].cve_id == "GHSA-jfh8-c2jp-5v3q"
    assert matches[0].severity == "CRITICAL"
    assert matches[0].fixed_version == "2.16.0"
    assert matches[0].affected_component.name == "org.apache.logging.log4j:log4j-core"
    assert matches[0].source == "osv"


@patch("seevie_pri.stages.match.httpx")
def test_osv_match_skips_components_without_purl(mock_httpx):
    comp = Component(name="some-lib", version="1.0", ecosystem="maven", purl=None)
    matches = osv_match([comp])
    assert matches == []
    mock_httpx.post.assert_not_called()


def test_offline_match():
    comp = _make_component(
        "org.apache.logging.log4j:log4j-core", "2.14.1",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    )
    matches = offline_match([comp], FIXTURES / "offline_cve_data.json")

    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2021-44228"
    assert matches[0].severity == "CRITICAL"
    assert matches[0].fixed_version == "2.16.0"
    assert matches[0].source == "manual"


def test_offline_match_no_match():
    comp = _make_component(
        "com.example:safe-lib", "1.0.0",
        "pkg:maven/com.example/safe-lib@1.0.0",
    )
    matches = offline_match([comp], FIXTURES / "offline_cve_data.json")
    assert matches == []


def test_deduplicate_osv_wins():
    comp = _make_component("lib", "1.0", "pkg:maven/g/lib@1.0")
    osv = CVEMatch(cve_id="CVE-1", severity="CRITICAL", affected_component=comp,
                   fixed_version="2.0", source="osv")
    nvd = CVEMatch(cve_id="CVE-1", severity="HIGH", affected_component=comp,
                   fixed_version=None, source="nvd")

    result = deduplicate([nvd, osv])
    assert len(result) == 1
    assert result[0].source == "osv"
    assert result[0].severity == "CRITICAL"
