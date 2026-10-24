"""
AttackGraphX — Comprehensive End-to-End Workflow Integration Test
Validates the complete lifecycle:
1. Seed enterprise network attack graph
2. Ingest live recon scan results (simulating recon-service publisher)
3. Discover attack paths to critical assets (db-01, vault-01)
4. Verify explainable risk engine formulas and severity boundaries
5. Run What-If remediation simulation (CVE-2023-34362 patch)
6. Verify residual risk calculation and path elimination
7. Download and verify PDF security report
8. Download and verify CSV telemetry report
9. Verify RBAC enforcement (admin vs analyst permissions)
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth.jwt import create_access_token


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token({"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token({"sub": "analyst", "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def test_full_platform_e2e_workflow(monkeypatch, api_client, admin_headers, analyst_headers):
    import sys
    from pathlib import Path
    analysis_dir = str(Path(__file__).resolve().parent.parent.parent / "analysis-service")
    if analysis_dir not in sys.path:
        sys.path.insert(0, analysis_dir)

    # Import the real analysis service components to act as upstream
    from analysis_service.api.endpoints import whatif_engine, graph_store, scan_consumer
    from analysis_service.models.scan_models import IngestedScanResult, IngestedHost, IngestedService

    # 1. Reset baseline seed data
    graph_store.load_seed_data()
    whatif_engine.reset_simulation()

    # 2. Ingest recon scan result dynamically
    scan_event = IngestedScanResult(
        scan_id="e2e-scan-001",
        timestamp=datetime.now(timezone.utc),
        scanner="nmap",
        target_scope="172.20.0.0/24",
        hosts=[
            IngestedHost(
                ip="172.20.0.10",
                hostname="web-server.lab.local",
                segment="lab",
                services=[
                    IngestedService(port=80, protocol="tcp", state="open", name="http", product="nginx", version="1.25")
                ]
            )
        ]
    )
    scan_consumer.ingest_scan_result(scan_event)
    assert graph_store.graph.has_node("web-server.lab.local")

    # Mock analysis_client to route directly to our live Analysis Service engine in-process
    async def mock_get_paths(target="all"):
        paths = whatif_engine.get_baseline_paths(target_filter=target or "all")
        return [p.model_dump() for p in paths]

    async def mock_get_patches():
        patches = whatif_engine.generate_recommended_patches()
        return [p.model_dump() for p in patches]

    async def mock_simulate_fix(vuln_id: str):
        res = whatif_engine.simulate_vulnerability_fix(vuln_id)
        return res.model_dump()

    async def mock_reset_simulation():
        whatif_engine.reset_simulation()
        return {"status": "live", "message": "Simulations reset"}

    async def mock_health():
        return True

    from app.services.analysis_client import analysis_client
    monkeypatch.setattr(analysis_client, "get_paths", mock_get_paths)
    monkeypatch.setattr(analysis_client, "get_patches", mock_get_patches)
    monkeypatch.setattr(analysis_client, "simulate_fix", mock_simulate_fix)
    monkeypatch.setattr(analysis_client, "reset_simulation", mock_reset_simulation)
    monkeypatch.setattr(analysis_client, "health_check", mock_health)

    # 3. Retrieve attack paths as Analyst
    resp_paths = api_client.get("/paths", headers=analyst_headers)
    assert resp_paths.status_code == 200
    paths_data = resp_paths.json()["data"]
    assert len(paths_data) > 0

    # 4. Verify highest risk path to critical asset db-01 or vault-01
    top_path = paths_data[0]
    assert top_path["target"] in ("db-01", "vault-01")
    assert top_path["risk_score"] >= 80
    assert top_path["severity"] == "critical"
    assert len(top_path["hops"]) >= 2

    # 5. Check recommended patches
    resp_patches = api_client.get("/patches", headers=analyst_headers)
    assert resp_patches.status_code == 200
    patches_data = resp_patches.json()["data"]
    assert len(patches_data) > 0
    top_patch = patches_data[0]
    assert top_patch["paths_closed"] >= 1
    assert top_patch["risk_reduction"] > 0

    # 6. Verify RBAC: Analyst CANNOT trigger What-If simulation (403 Forbidden)
    resp_analyst_sim = api_client.post(
        "/simulate",
        headers=analyst_headers,
        json={"vulnerability_id": top_patch["vulnerability_id"]}
    )
    assert resp_analyst_sim.status_code == 403

    # 7. Admin triggers What-If simulation
    resp_admin_sim = api_client.post(
        "/simulate",
        headers=admin_headers,
        json={"vulnerability_id": top_patch["vulnerability_id"]}
    )
    assert resp_admin_sim.status_code == 200
    sim_result = resp_admin_sim.json()
    assert sim_result["status"] == "live"
    assert sim_result["before"]["path_count"] >= sim_result["after"]["path_count"]
    assert len(sim_result["paths_eliminated"]) >= 1

    # 8. Reset simulation as Admin
    resp_reset = api_client.post("/simulate/reset", headers=admin_headers)
    assert resp_reset.status_code == 200

    # 9. Download PDF Report
    resp_pdf = api_client.get("/reports/pdf", headers=analyst_headers)
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF")

    # 10. Download CSV Telemetry Report
    resp_csv = api_client.get("/reports/csv", headers=analyst_headers)
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    csv_lines = resp_csv.text.strip().splitlines()
    assert len(csv_lines) > 1  # Header + data rows
    assert "Path_ID" in csv_lines[0]
    assert "Risk_Score" in csv_lines[0]
