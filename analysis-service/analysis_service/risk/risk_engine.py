"""
AttackGraphX Analysis Service — Explainable Risk Engine
Calculates risk scores strictly adhering to the project formula:
    Risk Score = (Exploitability × 0.4) + (Asset Criticality × 0.4) + (Exposure × 0.2)

Severity Bands:
    0–30   : LOW
    31–60  : MEDIUM
    61–80  : HIGH
    81–100 : CRITICAL
"""
from typing import Any, Literal
from analysis_service.config import settings
from analysis_service.models.path_models import HopModel, PathModel


def classify_severity(score: int) -> Literal["low", "medium", "high", "critical"]:
    """Classifies a 0-100 normalized risk score into severity bands."""
    if score <= 30:
        return "low"
    elif score <= 60:
        return "medium"
    elif score <= 80:
        return "high"
    else:
        return "critical"


class ExplainableRiskEngine:
    """
    Computes explainable, deterministic risk scores and narratives
    for multi-hop attack paths.
    """

    def __init__(
        self,
        weight_exploitability: float = 0.4,
        weight_criticality: float = 0.4,
        weight_exposure: float = 0.2,
    ):
        self.w_exploit = weight_exploitability
        self.w_crit = weight_criticality
        self.w_expo = weight_exposure

    def calculate_single_risk(
        self,
        exploitability: float,
        criticality: float,
        exposure: float,
    ) -> int:
        """
        Calculates raw composite risk score for given factor components.
        Clamps inputs and final result to [0, 100].
        """
        e = max(0.0, min(100.0, float(exploitability)))
        c = max(0.0, min(100.0, float(criticality)))
        x = max(0.0, min(100.0, float(exposure)))

        raw = (e * self.w_exploit) + (c * self.w_crit) + (x * self.w_expo)
        return int(round(max(0.0, min(100.0, raw))))

    def evaluate_path_risk(
        self,
        path_nodes: list[str],
        hops: list[HopModel],
        graph: Any,
    ) -> dict[str, Any]:
        """
        Evaluates risk for an entire multi-hop attack path toward a target asset.
        """
        target_node = path_nodes[-1]
        target_data = graph.nodes.get(target_node, {})

        # 1. Target Asset Criticality
        criticality = float(target_data.get("criticality", 75))

        # 2. Exposure: based on ingress entry host
        ingress_node = path_nodes[0] if path_nodes[0] != "EXTERNAL" else (path_nodes[1] if len(path_nodes) > 1 else target_node)
        ingress_data = graph.nodes.get(ingress_node, {})
        base_exposure = float(ingress_data.get("exposure", 80))

        # Attenuate exposure slightly with length (deeper paths require more lateral movement)
        hop_count = len(hops)
        path_exposure = max(20.0, base_exposure - max(0, (hop_count - 2) * 5.0))

        # 3. Path Exploitability:
        # Aggregates exploitability across hops.
        # Combines the bottleneck (weakest link) with average hop exploitability.
        hop_exploitabilities: list[float] = []
        techniques_used: list[str] = []

        for h in hops:
            if h.vulnerability:
                v_data = graph.nodes.get(h.vulnerability, {})
                exp = float(v_data.get("exploitability", 70))
                hop_exploitabilities.append(exp)
            else:
                hop_exploitabilities.append(60.0)

            if h.attack_technique:
                techniques_used.append(h.attack_technique)

        if not hop_exploitabilities:
            hop_exploitabilities = [60.0]

        bottleneck_exploitability = min(hop_exploitabilities)
        average_exploitability = sum(hop_exploitabilities) / len(hop_exploitabilities)
        composite_exploitability = (0.6 * bottleneck_exploitability) + (0.4 * average_exploitability)

        # 4. Final Risk Calculation
        risk_score = self.calculate_single_risk(
            composite_exploitability,
            criticality,
            path_exposure,
        )
        severity = classify_severity(risk_score)

        # 5. Attacker Detectability Assessment
        # E.g. Zero-days, SSH backdoors, memory injection = low detectability (harder to catch)
        if any(t in ("T1021", "T1552", "T1190") for t in techniques_used):
            detectability = "low"
        elif any(t in ("T1059", "T1068") for t in techniques_used):
            detectability = "medium"
        else:
            detectability = "high"

        # 6. Rationale explanation
        rationale = (
            f"Path reaches critical asset '{target_node}' (Criticality: {int(criticality)}/100) "
            f"via ingress entry '{ingress_node}' (Exposure: {int(path_exposure)}/100). "
            f"Bottleneck exploitability is {int(bottleneck_exploitability)}/100 with composite path score of {int(composite_exploitability)}/100. "
            f"Overall risk evaluated as {risk_score}/100 ({severity.upper()})."
        )

        return {
            "risk_score": risk_score,
            "severity": severity,
            "detectability": detectability,
            "composite_exploitability": round(composite_exploitability, 1),
            "asset_criticality": round(criticality, 1),
            "path_exposure": round(path_exposure, 1),
            "rationale": rationale,
        }
