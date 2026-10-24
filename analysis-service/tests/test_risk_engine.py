"""
Unit tests for ExplainableRiskEngine.
"""
import pytest
from analysis_service.risk.risk_engine import ExplainableRiskEngine, classify_severity
from analysis_service.models.path_models import HopModel


def test_classify_severity_boundaries():
    assert classify_severity(0) == "low"
    assert classify_severity(30) == "low"
    assert classify_severity(31) == "medium"
    assert classify_severity(60) == "medium"
    assert classify_severity(61) == "high"
    assert classify_severity(80) == "high"
    assert classify_severity(81) == "critical"
    assert classify_severity(100) == "critical"


def test_calculate_single_risk_formula(test_risk_engine):
    # Risk Score = (Exploitability * 0.4) + (Asset Criticality * 0.4) + (Exposure * 0.2)
    # E = 100, C = 100, X = 100 -> 40 + 40 + 20 = 100
    assert test_risk_engine.calculate_single_risk(100, 100, 100) == 100

    # E = 0, C = 0, X = 0 -> 0
    assert test_risk_engine.calculate_single_risk(0, 0, 0) == 0

    # E = 50, C = 50, X = 50 -> 20 + 20 + 10 = 50
    assert test_risk_engine.calculate_single_risk(50, 50, 50) == 50

    # E = 90, C = 95, X = 80 -> (90*0.4=36) + (95*0.4=38) + (80*0.2=16) = 90
    assert test_risk_engine.calculate_single_risk(90, 95, 80) == 90


def test_calculate_single_risk_clamps_inputs(test_risk_engine):
    # Extreme inputs clamped to 0-100
    assert test_risk_engine.calculate_single_risk(150, 200, 300) == 100
    assert test_risk_engine.calculate_single_risk(-50, -20, -10) == 0


def test_evaluate_path_risk(test_risk_engine, test_graph_store):
    path_nodes = ["cloud-gateway", "web-01", "app-01", "db-01"]
    hops = [
        HopModel(host="cloud-gateway", vulnerability="CVE-2023-34362", attack_technique="T1190"),
        HopModel(host="web-01", vulnerability="CVE-2021-44228", attack_technique="T1059"),
        HopModel(host="app-01", vulnerability="CVE-2022-22965", attack_technique="T1068"),
        HopModel(host="db-01", vulnerability="CVE-2023-23397", attack_technique="T1078"),
    ]

    result = test_risk_engine.evaluate_path_risk(path_nodes, hops, test_graph_store.graph)

    assert "risk_score" in result
    assert "severity" in result
    assert "detectability" in result
    assert "rationale" in result
    assert 0 <= result["risk_score"] <= 100
    assert result["severity"] in ("critical", "high")
    assert "db-01" in result["rationale"]
