"""
Unit tests for GraphStore.
"""
def test_seed_data_loaded(test_graph_store):
    hosts = test_graph_store.get_hosts()
    assets = test_graph_store.get_assets()
    vulns = test_graph_store.get_vulnerabilities()

    assert len(hosts) >= 12
    assert len(assets) >= 5
    assert len(vulns) >= 8

    # Specific key hosts present
    host_ids = {h["id"] for h in hosts}
    assert "cloud-gateway" in host_ids
    assert "web-01" in host_ids
    assert "jump-01" in host_ids
    assert "db-01" in host_ids
    assert "vault-01" in host_ids


def test_add_host_and_service(test_graph_store):
    test_graph_store.add_host({
        "id": "test-box",
        "ip": "10.0.99.1",
        "hostname": "test-box.local",
        "segment": "test",
        "state": "up",
    })
    test_graph_store.add_service({
        "id": "test-box:8080",
        "host_id": "test-box",
        "port": 8080,
        "protocol": "tcp",
        "name": "http-alt",
    })

    assert test_graph_store.graph.has_node("test-box")
    assert test_graph_store.graph.has_node("test-box:8080")
    assert test_graph_store.graph.has_edge("test-box", "test-box:8080")


def test_remove_vulnerability(test_graph_store):
    vuln_id = "CVE-2023-34362"
    assert test_graph_store.graph.has_node(vuln_id)

    # Check edges exist
    matching_edges = [
        (u, v) for u, v, d in test_graph_store.graph.edges(data=True)
        if d.get("vulnerability_id") == vuln_id
    ]
    assert len(matching_edges) > 0

    test_graph_store.remove_vulnerability(vuln_id)

    assert not test_graph_store.graph.has_node(vuln_id)
    remaining_edges = [
        (u, v) for u, v, d in test_graph_store.graph.edges(data=True)
        if d.get("vulnerability_id") == vuln_id
    ]
    assert len(remaining_edges) == 0


def test_clone_isolation(test_graph_store):
    cloned = test_graph_store.clone()
    assert cloned.graph.number_of_nodes() == test_graph_store.graph.number_of_nodes()

    # Mutating cloned graph does not affect baseline
    cloned.remove_vulnerability("CVE-2021-44228")
    assert not cloned.graph.has_node("CVE-2021-44228")
    assert test_graph_store.graph.has_node("CVE-2021-44228")


def test_cytoscape_elements_serialization(test_graph_store):
    elements = test_graph_store.to_cytoscape_elements()
    assert len(elements) > 10

    # Ensure valid Cytoscape data dictionary
    node_elements = [e for e in elements if "source" not in e["data"]]
    edge_elements = [e for e in elements if "source" in e["data"]]

    assert len(node_elements) > 0
    assert len(edge_elements) > 0
    assert "id" in node_elements[0]["data"]
    assert "source" in edge_elements[0]["data"]
    assert "target" in edge_elements[0]["data"]
