from unittest.mock import patch, MagicMock

from seevie_pri.context import Component, TriageContext
from seevie_pri.stages.match import match, osv_match


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
