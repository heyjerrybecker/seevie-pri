from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from seevie_pri.server import create_app

FIXTURES = Path(__file__).parent / "fixtures"

OSV_BATCH = {
    "results": [
        {"vulns": []}, {"vulns": []}, {"vulns": []},
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01"}]},
        {"vulns": []}, {"vulns": []},
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


def test_dashboard_overview(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/dashboard/")
    assert resp.status_code == 200
    assert "SeeviePri" in resp.text
    assert "Get started" in resp.text


def test_dashboard_services(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/dashboard/services")
    assert resp.status_code == 200
    assert "Services" in resp.text


def test_dashboard_findings(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/dashboard/findings")
    assert resp.status_code == 200
    assert "Findings" in resp.text


def test_dashboard_upload(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/dashboard/upload")
    assert resp.status_code == 200
    assert "Upload" in resp.text


def test_dashboard_architecture(tmp_path):
    client = _make_client(tmp_path)
    resp = client.get("/dashboard/architecture")
    assert resp.status_code == 200
    assert "Architecture" in resp.text


@patch("seevie_pri.stages.match.httpx")
def test_overview_with_data(mock_httpx, tmp_path):
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
    client.post("/sbom", files={"file": ("bom.json", sbom_file.read_bytes(), "application/json")}, data={"name": "spring-app"})
    client.post("/rescan")

    resp = client.get("/dashboard/")
    assert resp.status_code == 200
    assert "spring-app" in resp.text
    assert "CRITICAL" in resp.text
