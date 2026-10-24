"""
AttackGraphX Analysis Service — What-If Remediation Engine
Simulates defensive interventions on an isolated graph snapshot:
- Vulnerability patching
- Credential revocation
- Recalculates reachable paths, critical assets, and residual risk
- Evaluates: Risk Reduction = Baseline Risk − Simulated Risk
- Ranks candidate remediation actions by risk reduction
"""
import copy
from typing import Any

from analysis_service.algorithms.pathfinder import AttackPathfinder
from analysis_service.graph.graph_store import GraphStore
from analysis_service.models.path_models import (
    HopModel,
    PathModel,
    PatchModel,
    SimulateStats,
    SimulateResponse,
)
from analysis_service.risk.risk_engine import ExplainableRiskEngine


class WhatIfEngine:
    """
    Simulates defensive remediations and evaluates security risk delta.
    """

    def __init__(self, graph_store: GraphStore):
        self.graph_store = graph_store
        self.risk_engine = ExplainableRiskEngine()
        self.active_simulated_fixes: set[str] = set()

    def get_baseline_paths(self, target_filter: str = "all") -> list[PathModel]:
        """Calculates all feasible attack paths on the current baseline graph."""
        return self._compute_paths_on_graph(self.graph_store.graph, target_filter)

    def simulate_vulnerability_fix(self, vulnerability_id: str) -> SimulateResponse:
        """
        Simulates patching a vulnerability on an isolated cloned graph.
        Does not mutate the baseline graph store.
        """
        # 1. Compute baseline stats
        baseline_paths = self.get_baseline_paths(target_filter="all")
        before_stats = self._calculate_stats(baseline_paths)

        # 2. Add to active fixes
        self.active_simulated_fixes.add(vulnerability_id)

        # 3. Create isolated clone and apply active fixes
        sim_store = self.graph_store.clone()
        for fix_vuln in self.active_simulated_fixes:
            sim_store.remove_vulnerability(fix_vuln)

        # 4. Compute simulated remaining paths
        sim_paths = self._compute_paths_on_graph(sim_store.graph, target_filter="all")
        after_stats = self._calculate_stats(sim_paths)

        # 5. Determine eliminated and remaining paths
        sim_routes = {tuple(h.host for h in p.hops) for p in sim_paths}
        eliminated = []
        for p in baseline_paths:
            route = tuple(h.host for h in p.hops)
            has_fixed_vuln = any(h.vulnerability in self.active_simulated_fixes for h in p.hops)
            if has_fixed_vuln or route not in sim_routes:
                eliminated.append(p.id)

        remaining = [p.id for p in sim_paths]

        risk_reduction = max(0, before_stats.avg_risk - after_stats.avg_risk)

        return SimulateResponse(
            before=before_stats,
            after=after_stats,
            vulnerability_id=vulnerability_id,
            status="live",
            paths_eliminated=eliminated,
            remaining_paths=remaining,
            risk_reduction=risk_reduction,
        )

    def reset_simulation(self) -> None:
        """Clears all active simulation overrides."""
        self.active_simulated_fixes.clear()

    def generate_recommended_patches(self) -> list[PatchModel]:
        """
        Evaluates every vulnerability present in the graph and ranks them
        by expected risk reduction and paths closed.
        """
        baseline_paths = self.get_baseline_paths(target_filter="all")
        baseline_stats = self._calculate_stats(baseline_paths)

        patches: list[PatchModel] = []
        vulns = self.graph_store.get_vulnerabilities()

        for idx, v in enumerate(vulns, start=1):
            vid = v["id"]
            host = v.get("host", "unknown")
            desc = v.get("patch_description") or v.get("description", f"Mitigate {vid}")

            # Test impact of patching this single vulnerability in isolation
            sim_store = self.graph_store.clone()
            sim_store.remove_vulnerability(vid)
            sim_paths = self._compute_paths_on_graph(sim_store.graph, target_filter="all")
            sim_stats = self._calculate_stats(sim_paths)

            paths_closed = max(0, baseline_stats.path_count - sim_stats.path_count)
            # Comprehensive risk reduction formula: closed critical paths + average risk delta
            crit_delta = max(0, baseline_stats.critical_paths - sim_stats.critical_paths)
            avg_delta = max(0, baseline_stats.avg_risk - sim_stats.avg_risk)
            total_reduction = (paths_closed * 10) + (crit_delta * 5) + avg_delta

            patches.append(
                PatchModel(
                    id=f"PATCH-{idx:03d}",
                    vulnerability_id=vid,
                    host=host,
                    description=desc,
                    paths_closed=paths_closed,
                    risk_reduction=total_reduction,
                )
            )

        # Rank patches by risk reduction descending
        patches.sort(key=lambda p: (p.risk_reduction, p.paths_closed), reverse=True)
        return patches

    def _compute_paths_on_graph(self, graph: Any, target_filter: str = "all") -> list[PathModel]:
        """Discovers and scores attack paths across all ingress nodes to target assets."""
        pathfinder = AttackPathfinder(graph)
        discovered_paths: list[PathModel] = []
        path_counter = 1

        # Identify ingress entry from perimeter
        ingress_nodes = ["EXTERNAL"]
        target_nodes = ["db-01", "vault-01", "auth-01", "app-01", "app-02", "k8s-node-01", "db-02", "k8s-node-02"]

        if target_filter and target_filter.lower() != "all":
            target_nodes = [t for t in target_nodes if t.lower() == target_filter.lower()]

        seen_routes: set[tuple[str, ...]] = set()

        for target in target_nodes:
            if not graph.has_node(target):
                continue

            for source in ingress_nodes:
                if not graph.has_node(source):
                    continue

                k_paths = pathfinder.find_k_shortest_paths(source, target, k=3, max_hops=6)
                for route_nodes, cost in k_paths:
                    # Filter out EXTERNAL from route representation
                    effective_route = tuple(n for n in route_nodes if n != "EXTERNAL")
                    if len(effective_route) < 2 or effective_route in seen_routes:
                        continue
                    seen_routes.add(effective_route)

                    hops = pathfinder.build_path_hops(list(effective_route))
                    eval_result = self.risk_engine.evaluate_path_risk(list(effective_route), hops, graph)

                    discovered_paths.append(
                        PathModel(
                            id=f"PATH-{path_counter:03d}",
                            target=target,
                            risk_score=eval_result["risk_score"],
                            severity=eval_result["severity"],
                            detectability=eval_result["detectability"],
                            hops=hops,
                            cost=round(cost, 2),
                            rationale=eval_result["rationale"],
                        )
                    )
                    path_counter += 1

        # Sort paths by risk score descending (highest risk first)
        discovered_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return discovered_paths

    def _calculate_stats(self, paths: list[PathModel]) -> SimulateStats:
        count = len(paths)
        if count == 0:
            return SimulateStats(path_count=0, avg_risk=0, critical_paths=0)
        avg = int(round(sum(p.risk_score for p in paths) / count))
        criticals = sum(1 for p in paths if p.severity == "critical")
        return SimulateStats(path_count=count, avg_risk=avg, critical_paths=criticals)
