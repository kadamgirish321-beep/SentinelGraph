"""
Unit tests for Dijkstra and Yen's K-Shortest Paths pathfinding.
"""
import networkx as nx
import pytest

from analysis_service.algorithms.pathfinder import AttackPathfinder


def test_dijkstra_simple_path():
    g = nx.DiGraph()
    g.add_node("A", ip="10.0.0.1")
    g.add_node("B", ip="10.0.0.2")
    g.add_node("C", ip="10.0.0.3")

    g.add_edge("A", "B", relation="CAN_REACH", weight=5.0)
    g.add_edge("B", "C", relation="CAN_COMPROMISE", weight=3.0)

    pf = AttackPathfinder(g)
    path, cost = pf.dijkstra_shortest_path("A", "C")

    assert path == ["A", "B", "C"]
    assert cost == 8.0


def test_dijkstra_prefers_lower_cost_path():
    g = nx.DiGraph()
    # Route 1: A -> B -> D (5 + 10 = 15)
    # Route 2: A -> C -> D (2 + 3 = 5, lower cost)
    g.add_edge("A", "B", relation="CAN_REACH", weight=5.0)
    g.add_edge("B", "D", relation="CAN_COMPROMISE", weight=10.0)
    g.add_edge("A", "C", relation="CAN_REACH", weight=2.0)
    g.add_edge("C", "D", relation="CAN_COMPROMISE", weight=3.0)

    pf = AttackPathfinder(g)
    path, cost = pf.dijkstra_shortest_path("A", "D")

    assert path == ["A", "C", "D"]
    assert cost == 5.0


def test_dijkstra_unreachable_target():
    g = nx.DiGraph()
    g.add_node("A")
    g.add_node("B")  # Disconnected

    pf = AttackPathfinder(g)
    assert pf.dijkstra_shortest_path("A", "B") is None


def test_yen_k_shortest_paths(test_graph_store):
    pf = AttackPathfinder(test_graph_store.graph)
    paths = pf.find_k_shortest_paths("cloud-gateway", "db-01", k=3)

    assert len(paths) >= 1
    # Check all discovered paths end at db-01
    for p, cost in paths:
        assert p[-1] == "db-01"
        assert cost > 0


def test_path_hops_builder(test_graph_store):
    pf = AttackPathfinder(test_graph_store.graph)
    path_nodes = ["cloud-gateway", "web-01", "app-01", "db-01"]
    hops = pf.build_path_hops(path_nodes)

    assert len(hops) == 4
    assert hops[0].host == "cloud-gateway"
    assert hops[1].host == "web-01"
    assert hops[2].host == "app-01"
    assert hops[3].host == "db-01"
    # Verify vulnerability references
    assert hops[1].vulnerability == "CVE-2021-44228"
    assert hops[3].vulnerability == "CVE-2023-23397"
