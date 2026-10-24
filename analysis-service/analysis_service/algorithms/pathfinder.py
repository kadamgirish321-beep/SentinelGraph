"""
AttackGraphX Analysis Service — Attack Pathfinding Algorithms
Implements:
- Dijkstra's algorithm for minimum-cost feasible paths
- Yen's K-Shortest Paths for alternative attack path enumeration
- Cycle avoidance, loop prevention, and disconnected graph handling
- Multi-source (ingress) to multi-target (critical assets) path discovery
"""
import heapq
import itertools
from typing import Any, Optional

import networkx as nx

from analysis_service.models.path_models import HopModel


class AttackPathfinder:
    """
    Computes feasible attack paths across the security graph.
    Edge weights represent transition difficulty (lower = easier / more feasible).
    """

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def dijkstra_shortest_path(self, source: str, target: str) -> Optional[tuple[list[str], float]]:
        """
        Calculates the single lowest-cost attack route between source and target
        using Dijkstra's algorithm with a priority queue (min-heap).
        """
        if not self.graph.has_node(source) or not self.graph.has_node(target):
            return None

        # Priority queue stores (cost, current_node, path_nodes)
        pq: list[tuple[float, str, list[str]]] = [(0.0, source, [source])]
        visited_costs: dict[str, float] = {}

        while pq:
            cost, u, path = heapq.heappop(pq)

            if u == target:
                return path, cost

            if u in visited_costs and visited_costs[u] <= cost:
                continue
            visited_costs[u] = cost

            for v in self.graph.successors(u):
                # Avoid cycles in the path
                if v in path:
                    continue
                edge_data = self.graph.get_edge_data(u, v) or {}
                # Filter out metadata links like HAS_VULNERABILITY or EXPOSES
                rel = edge_data.get("relation", "")
                if rel in ("HAS_VULNERABILITY", "EXPOSES"):
                    continue

                edge_weight = max(1.0, float(edge_data.get("weight", 10.0)))
                new_cost = cost + edge_weight

                if v not in visited_costs or new_cost < visited_costs[v]:
                    heapq.heappush(pq, (new_cost, v, path + [v]))

        return None

    def find_k_shortest_paths(
        self,
        source: str,
        target: str,
        k: int = 5,
        max_hops: int = 8,
    ) -> list[tuple[list[str], float]]:
        """
        Yen's K-Shortest Paths algorithm.
        Finds up to K loopless alternative attack paths between source and target.
        """
        if not self.graph.has_node(source) or not self.graph.has_node(target):
            return []

        # Find the first shortest path
        first_path = self.dijkstra_shortest_path(source, target)
        if not first_path:
            return []

        A: list[tuple[list[str], float]] = [first_path]
        B: list[tuple[float, list[str]]] = []  # Candidate heap: (cost, path)

        for i in range(1, k):
            prev_path, _ = A[i - 1]

            # Iterate over all spur nodes in the previous path
            for spur_idx in range(len(prev_path) - 1):
                spur_node = prev_path[spur_idx]
                root_path = prev_path[:spur_idx + 1]

                # Temporarily remove edges part of previous paths that share root_path
                removed_edges = []
                for p, _ in A:
                    if len(p) > spur_idx + 1 and p[:spur_idx + 1] == root_path:
                        u = p[spur_idx]
                        v = p[spur_idx + 1]
                        if self.graph.has_edge(u, v):
                            data = self.graph.get_edge_data(u, v)
                            self.graph.remove_edge(u, v)
                            removed_edges.append((u, v, data))

                # Temporarily remove root nodes except spur_node to prevent loops
                removed_nodes = []
                for node in root_path[:-1]:
                    if self.graph.has_node(node):
                        edges_in = list(self.graph.in_edges(node, data=True))
                        edges_out = list(self.graph.out_edges(node, data=True))
                        self.graph.remove_node(node)
                        removed_nodes.append((node, edges_in, edges_out))

                # Calculate spur path from spur_node to target
                spur_result = self.dijkstra_shortest_path(spur_node, target)
                if spur_result:
                    spur_path, _ = spur_result
                    total_path = root_path[:-1] + spur_path
                    if len(total_path) <= max_hops + 1:
                        # Compute true cost of total_path
                        total_cost = self._calculate_path_cost(total_path)
                        # Check duplicate in B
                        if not any(total_path == candidate_path for _, candidate_path in B):
                            heapq.heappush(B, (total_cost, total_path))

                # Restore removed nodes and edges
                for node, edges_in, edges_out in reversed(removed_nodes):
                    self.graph.add_node(node)
                    for u, v, d in edges_in:
                        self.graph.add_edge(u, v, **d)
                    for u, v, d in edges_out:
                        self.graph.add_edge(u, v, **d)

                for u, v, data in removed_edges:
                    self.graph.add_edge(u, v, **data)

            if not B:
                break

            # Add lowest cost candidate from B to A
            cand_cost, cand_path = heapq.heappop(B)
            # Ensure not duplicate of an already chosen path
            if not any(cand_path == p for p, _ in A):
                A.append((cand_path, cand_cost))

        return A

    def _calculate_path_cost(self, path: list[str]) -> float:
        total = 0.0
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            data = self.graph.get_edge_data(u, v) or {}
            total += max(1.0, float(data.get("weight", 10.0)))
        return total

    def build_path_hops(self, path_nodes: list[str]) -> list[HopModel]:
        """
        Converts a list of host node IDs into structured HopModels with vulnerability,
        IP, technique, and narrative descriptions.
        """
        hops: list[HopModel] = []
        for i in range(len(path_nodes)):
            current = path_nodes[i]
            if current == "EXTERNAL":
                continue

            node_data = self.graph.nodes.get(current, {})
            ip = node_data.get("ip")

            # Look up incoming transition metadata
            vuln_id = None
            technique = None
            description = None

            if i > 0:
                prev = path_nodes[i - 1]
                edge_data = self.graph.get_edge_data(prev, current) or {}
                vuln_id = edge_data.get("vulnerability_id")
                technique = edge_data.get("technique")
                description = edge_data.get("description")

            # If no direct edge vuln, look for node's associated vulnerability
            if not vuln_id:
                for neighbor in self.graph.successors(current):
                    n_data = self.graph.nodes.get(neighbor, {})
                    if n_data.get("node_type") == "Vulnerability":
                        vuln_id = neighbor
                        technique = n_data.get("attack_technique")
                        description = n_data.get("description")
                        break

            hops.append(
                HopModel(
                    host=current,
                    ip=ip,
                    vulnerability=vuln_id,
                    attack_technique=technique,
                    description=description,
                )
            )

        return hops
