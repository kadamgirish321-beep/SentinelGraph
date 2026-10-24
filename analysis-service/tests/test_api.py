"""
Integration tests for Analysis Service HTTP APIs.
"""
def test_get_paths_api(test_client):
    response = test_client.get("/paths")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    first = data[0]
    assert "id" in first
    assert "target" in first
    assert "risk_score" in first
    assert "hops" in first


def test_get_paths_target_filter(test_client):
    response = test_client.get("/paths?target=vault-01")
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    for p in data:
        assert p["target"] == "vault-01"


def test_get_patches_api(test_client):
    response = test_client.get("/patches")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    first = data[0]
    assert "id" in first
    assert "vulnerability_id" in first
    assert "risk_reduction" in first


def test_simulate_api(test_client):
    response = test_client.post("/simulate", json={"vulnerability_id": "CVE-2023-34362"})
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "live"
    assert res["vulnerability_id"] == "CVE-2023-34362"
    assert "before" in res
    assert "after" in res


def test_simulate_reset_api(test_client):
    response = test_client.post("/simulate/reset")
    assert response.status_code == 200
    assert response.json()["status"] == "live"


def test_scan_status_api(test_client):
    response = test_client.get("/scan/status")
    assert response.status_code == 200
    res = response.json()
    assert "status" in res
    assert "last_scan" in res


def test_health_api(test_client):
    response = test_client.get("/health")
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "healthy"
    assert "graph_nodes" in res
    assert res["graph_nodes"] > 0


def test_topology_api(test_client):
    response = test_client.get("/topology")
    assert response.status_code == 200
    res = response.json()
    assert "elements" in res
    assert len(res["elements"]) > 0


def test_assets_api(test_client):
    response = test_client.get("/assets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
