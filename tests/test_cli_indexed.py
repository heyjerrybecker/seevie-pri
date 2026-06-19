import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from seevie_pri.cli import main

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


def test_index_stores_sbom(tmp_path):
    db_path = tmp_path / "test.db"

    with patch("sys.argv", [
        "seevie-pri", "index",
        "--sbom", str(FIXTURES / "cyclonedx_sample.json"),
        "--name", "payment-api",
        "--db", str(db_path),
    ]):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0 or e.code is None

    from seevie_pri.db import init_db, list_sboms
    conn = init_db(db_path)
    sboms = list_sboms(conn)
    assert len(sboms) == 1
    assert sboms[0]["name"] == "payment-api"
    assert sboms[0]["component_count"] == 7
    conn.close()


@patch("seevie_pri.stages.match.httpx")
def test_rescan_triages_indexed_sboms(mock_httpx, tmp_path):
    mock_post = MagicMock()
    mock_post.json.return_value = OSV_BATCH
    mock_post.raise_for_status = MagicMock()
    mock_httpx.post.return_value = mock_post

    mock_get = MagicMock()
    mock_get.json.return_value = OSV_DETAIL
    mock_get.raise_for_status = MagicMock()
    mock_httpx.get.return_value = mock_get

    db_path = tmp_path / "test.db"

    # First, index the SBOM
    with patch("sys.argv", [
        "seevie-pri", "index",
        "--sbom", str(FIXTURES / "cyclonedx_sample.json"),
        "--name", "test-app",
        "--db", str(db_path),
    ]):
        try:
            main()
        except SystemExit:
            pass

    # Then rescan
    out_file = tmp_path / "results.json"
    with patch("sys.argv", [
        "seevie-pri", "rescan",
        "--db", str(db_path),
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
    assert data["findings"][0]["cve_id"] == "GHSA-jfh8-c2jp-5v3q"

    # Verify findings are also in the database
    from seevie_pri.db import init_db, get_findings
    conn = init_db(db_path)
    db_findings = get_findings(conn)
    assert len(db_findings) >= 1
    conn.close()
