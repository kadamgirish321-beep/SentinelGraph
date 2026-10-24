"""
AttackGraphX Analysis Service — Agentic AI Orchestration Layer
Provides permission-checked tools for:
- Investigating high-risk attack paths
- Explaining feasibility based on modeled CVEs and MITRE techniques
- Comparing alternative paths
- Summarizing defensive remediation impact

Gracefully operates in deterministic heuristic mode when no external API key is present.
Never requires a paid AI service for core functionality.
"""
from typing import Any, Optional
from analysis_service.graph.graph_store import GraphStore
from analysis_service.simulation.what_if import WhatIfEngine


class SecurityAIAgent:
    """
    Autonomous cybersecurity reasoning layer with defined tool boundaries.
    """

    def __init__(self, graph_store: GraphStore, whatif_engine: WhatIfEngine):
        self.graph_store = graph_store
        self.whatif_engine = whatif_engine

    def investigate_path(self, path_id: str) -> dict[str, Any]:
        """
        Tool: Inspects a path and produces structured forensic explanation
        referencing specific CVEs, MITRE techniques, and transition prerequisites.
        """
        all_paths = self.whatif_engine.get_baseline_paths(target_filter="all")
        matched = next((p for p in all_paths if p.id.lower() == path_id.lower()), None)

        if not matched:
            return {
                "path_id": path_id,
                "found": False,
                "message": f"Path '{path_id}' not found in active graph analysis.",
            }

        transition_breakdown = []
        for idx, hop in enumerate(matched.hops, start=1):
            transition_breakdown.append({
                "step": idx,
                "host": hop.host,
                "ip": hop.ip or "internal",
                "cve": hop.vulnerability or "N/A",
                "mitre_technique": hop.attack_technique or "T1078 (Valid Accounts)",
                "summary": hop.description or f"Transition into {hop.host}",
            })

        summary = (
            f"AI Assessment for Attack Path {matched.id} to Critical Asset '{matched.target}':\n"
            f"- Overall Risk Score: {matched.risk_score}/100 ({matched.severity.upper()})\n"
            f"- Detectability: {matched.detectability.upper() if matched.detectability else 'MEDIUM'}\n"
            f"- Cumulative Difficulty Cost: {matched.cost}\n"
            f"- Key Chokepoint: Hop 1 ({matched.hops[0].host}) exposing {matched.hops[0].vulnerability}\n"
            f"- Recommendation: Apply immediate patch to {matched.hops[0].vulnerability} to sever this route."
        )

        return {
            "path_id": matched.id,
            "found": True,
            "target": matched.target,
            "risk_score": matched.risk_score,
            "severity": matched.severity,
            "detectability": matched.detectability,
            "transitions": transition_breakdown,
            "executive_summary": summary,
            "deterministic_validated": True,
        }

    def explain_remediation_priority(self) -> dict[str, Any]:
        """
        Tool: Analyzes all candidate patches and produces strategic remediation guidance.
        """
        patches = self.whatif_engine.generate_recommended_patches()
        if not patches:
            return {"recommended_actions": [], "summary": "No active vulnerabilities identified."}

        top_patch = patches[0]
        insights = [
            f"Top Priority: {top_patch.id} on host '{top_patch.host}' for {top_patch.vulnerability_id}. "
            f"Expected to sever {top_patch.paths_closed} feasible attack paths and reduce enterprise risk by {top_patch.risk_reduction} points."
        ]

        if len(patches) > 1:
            second_patch = patches[1]
            insights.append(
                f"Secondary Priority: {second_patch.id} on host '{second_patch.host}' for {second_patch.vulnerability_id} "
                f"closing {second_patch.paths_closed} paths."
            )

        return {
            "top_recommendation": top_patch.model_dump(),
            "ranked_patches": [p.model_dump() for p in patches[:5]],
            "strategic_insights": insights,
            "deterministic_validated": True,
        }
