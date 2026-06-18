import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from seevie_pri.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_osv(mock_httpx, batch_response, vuln_detail):
    mock_post = MagicMock()
    mock_post.json.return_value = batch_response
    mock_post.raise_for_status = MagicMock()
    mock_httpx.post.return_value = mock_post

    mock_get = MagicMock()
    mock_get.json.return_value = vuln_detail
    mock_get.raise_for_status = MagicMock()
    mock_httpx.get.return_value = mock_get


@patch("seevie_pri.stages.match.httpx")
def test_npm_pipeline(mock_httpx, tmp_path):
    _mock_osv(mock_httpx, {
        "results": [
            {"vulns": []},
            {"vulns": []},
            {"vulns": [{"id": "GHSA-x5rq-j2xg-h7qm", "modified": "2024-01-01"}]},
            {"vulns": []},
        ]
    }, {
        "id": "GHSA-x5rq-j2xg-h7qm",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }],
    })

    out_file = tmp_path / "results.json"

    with patch("sys.argv", [
        "seevie-pri", "triage",
        "--sbom", str(FIXTURES / "npm_cyclonedx.json"),
        "--format", "json",
        "--output", str(out_file),
        "--no-nvd",
    ]):
        try:
            main()
        except SystemExit:
            pass

    data = json.loads(out_file.read_text())
    assert len(data["findings"]) >= 1
    finding = data["findings"][0]
    assert finding["component"] == "lodash"
    assert finding["severity"] == "HIGH"
    assert finding["fixed_version"] == "4.17.21"
    assert finding["topology_score"] > 0


@patch("seevie_pri.stages.match.httpx")
def test_pypi_pipeline(mock_httpx, tmp_path):
    _mock_osv(mock_httpx, {
        "results": [
            {"vulns": []},
            {"vulns": [{"id": "PYSEC-2021-66", "modified": "2024-01-01"}]},
            {"vulns": []},
            {"vulns": []},
        ]
    }, {
        "id": "PYSEC-2021-66",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "jinja2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}],
        }],
    })

    out_file = tmp_path / "results.json"

    with patch("sys.argv", [
        "seevie-pri", "triage",
        "--sbom", str(FIXTURES / "pypi_cyclonedx.json"),
        "--format", "json",
        "--output", str(out_file),
        "--no-nvd",
    ]):
        try:
            main()
        except SystemExit:
            pass

    data = json.loads(out_file.read_text())
    assert len(data["findings"]) >= 1
    finding = data["findings"][0]
    assert finding["component"] == "jinja2"
    assert finding["severity"] == "HIGH"
    assert finding["topology_score"] > 0


@patch("seevie_pri.stages.match.httpx")
def test_go_pipeline(mock_httpx, tmp_path):
    _mock_osv(mock_httpx, {
        "results": [
            {"vulns": []},
            {"vulns": [{"id": "GO-2022-1059", "modified": "2024-01-01"}]},
            {"vulns": []},
            {"vulns": []},
        ]
    }, {
        "id": "GO-2022-1059",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "Go", "name": "golang.org/x/text"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}],
        }],
    })

    out_file = tmp_path / "results.json"

    with patch("sys.argv", [
        "seevie-pri", "triage",
        "--sbom", str(FIXTURES / "go_cyclonedx.json"),
        "--format", "json",
        "--output", str(out_file),
        "--no-nvd",
    ]):
        try:
            main()
        except SystemExit:
            pass

    data = json.loads(out_file.read_text())
    assert len(data["findings"]) >= 1
    finding = data["findings"][0]
    assert finding["component"] == "golang.org/x/text"
    assert finding["severity"] == "HIGH"
    assert finding["fixed_version"] == "0.3.8"
    assert finding["topology_score"] > 0
