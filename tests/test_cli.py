import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from seevie_pri.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

OSV_BATCH = {
    "results": [
        {"vulns": []},  # starter-web
        {"vulns": []},  # spring-webmvc
        {"vulns": []},  # spring-beans
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01"}]},  # log4j-core
        {"vulns": []},  # log4j-api
        {"vulns": []},  # jackson-databind
    ]
}

OSV_DETAIL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "affected": [{
        "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.16.0"}]}],
        "database_specific": {"severity": "CRITICAL"},
    }],
}


@patch("seevie_pri.stages.match.httpx")
def test_cli_triage_json_output(mock_httpx, tmp_path):
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.json.return_value = OSV_BATCH
    mock_post.raise_for_status = MagicMock()
    mock_httpx.post.return_value = mock_post

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.json.return_value = OSV_DETAIL
    mock_get.raise_for_status = MagicMock()
    mock_httpx.get.return_value = mock_get

    out_file = tmp_path / "results.json"

    with patch("sys.argv", [
        "seevie-pri", "triage",
        "--sbom", str(FIXTURES / "cyclonedx_sample.json"),
        "--format", "json",
        "--output", str(out_file),
        "--no-nvd",
    ]):
        try:
            main()
        except SystemExit:
            pass

    data = json.loads(out_file.read_text())
    assert data["version"] == "1.0"
    assert len(data["findings"]) >= 1

    finding = data["findings"][0]
    assert finding["cve_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert finding["component"] == "org.apache.logging.log4j:log4j-core"
    assert finding["severity"] == "CRITICAL"
    assert finding["fixed_version"] == "2.16.0"
    assert finding["topology_score"] > 0
    assert finding["action"] in (
        "UPGRADE AVAILABLE", "MANUAL UPGRADE REQUIRED", "PRIORITIZE",
        "SCHEDULE FOR NEXT SPRINT",
    )


@patch("seevie_pri.stages.match.httpx")
def test_cli_offline_mode(mock_httpx, tmp_path):
    out_file = tmp_path / "results.json"

    with patch("sys.argv", [
        "seevie-pri", "triage",
        "--sbom", str(FIXTURES / "cyclonedx_sample.json"),
        "--format", "json",
        "--output", str(out_file),
        "--cve-data", str(FIXTURES / "offline_cve_data.json"),
    ]):
        try:
            main()
        except SystemExit:
            pass

    mock_httpx.post.assert_not_called()

    data = json.loads(out_file.read_text())
    assert len(data["findings"]) >= 1
    assert data["findings"][0]["cve_id"] == "CVE-2021-44228"
