import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from seevie_pri.server import create_app

FIXTURES = Path(__file__).parent / "fixtures"

OSV_BATCH = {
    "results": [
        {"vulns": []},
        {"vulns": []},
        {"vulns": []},
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01"}]},
        {"vulns": []},
        {"vulns": []},
    ]
}

OSV_DETAIL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.16.0"}]}],
    }],
}


def _make_client(tmp_path):
    db_path = tmp_path / "test.db"
    app = create_app(db_path)
    return TestClient(app)


def test_list_sboms_empty(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/sbom")
    assert resp.status_code == 200
    assert resp.json() == []


def test_upload_sbom(tmp_path):
    client = _make_client(tmp_path)
    sbom_file = FIXTURES / "cyclonedx_sample.json"

    resp = client.post(
        "/sbom",
        files={"file": ("bom.json", sbom_file.read_bytes(), "application/json")},
        data={"name": "payment-api"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "payment-api"
    assert data["component_count"] == 7
    assert "id" in data

    resp = client.get("/sbom")
    assert len(resp.json()) == 1


@patch("seevie_pri.stages.match.httpx")
def test_rescan_and_get_findings(mock_httpx, tmp_path):
    mock_post = MagicMock()
    mock_post.json.return_value = OSV_BATCH
    mock_post.raise_for_status = MagicMock()
    mock_httpx.post.return_value = mock_post

    mock_get = MagicMock()
    mock_get.json.return_value = OSV_DETAIL
    mock_get.raise_for_status = MagicMock()
    mock_httpx.get.return_value = mock_get

    client = _make_client(tmp_path)
    sbom_file = FIXTURES / "cyclonedx_sample.json"

    upload_resp = client.post(
        "/sbom",
        files={"file": ("bom.json", sbom_file.read_bytes(), "application/json")},
        data={"name": "test-app"},
    )
    sbom_id = upload_resp.json()["id"]

    rescan_resp = client.post("/rescan")
    assert rescan_resp.status_code == 200
    assert rescan_resp.json()["sboms_scanned"] == 1
    assert rescan_resp.json()["total_findings"] >= 1

    findings_resp = client.get("/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1
    assert findings[0]["cve_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert findings[0]["sbom_name"] == "test-app"

    sbom_findings_resp = client.get(f"/findings/{sbom_id}")
    assert sbom_findings_resp.status_code == 200
    assert len(sbom_findings_resp.json()) >= 1


def test_get_findings_with_filters(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/findings?severity=CRITICAL&min_score=0.7")
    assert resp.status_code == 200
    assert resp.json() == []
