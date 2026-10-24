"""
Unit tests for WhatIfEngine remediation simulation.
"""
def test_baseline_paths_generated(test_whatif_engine):
    paths = test_whatif_engine.get_baseline_paths(target_filter="all")
    assert len(paths) > 0

    # Riskiest paths should be first
    for i in range(len(paths) - 1):
        assert paths[i].risk_score >= paths[i + 1].risk_score

    # Check top path connects to a critical asset
    top_path = paths[0]
    assert top_path.target in ("db-01", "vault-01")
    assert top_path.risk_score >= 80


def test_target_filter(test_whatif_engine):
    db_paths = test_whatif_engine.get_baseline_paths(target_filter="db-01")
    assert len(db_paths) > 0
    for p in db_paths:
        assert p.target == "db-01"


def test_simulate_vulnerability_fix(test_whatif_engine):
    # Simulate fixing CVE-2023-34362 (MOVEit Transfer on cloud-gateway)
    res = test_whatif_engine.simulate_vulnerability_fix("CVE-2023-34362")

    assert res.status == "live"
    assert res.vulnerability_id == "CVE-2023-34362"
    assert res.before.path_count >= res.after.path_count
    # Should have eliminated at least one path
    assert len(res.paths_eliminated) > 0
    assert len(res.remaining_paths) == res.after.path_count


def test_simulate_reset(test_whatif_engine):
    test_whatif_engine.simulate_vulnerability_fix("CVE-2023-34362")
    assert len(test_whatif_engine.active_simulated_fixes) == 1

    test_whatif_engine.reset_simulation()
    assert len(test_whatif_engine.active_simulated_fixes) == 0


def test_generate_recommended_patches(test_whatif_engine):
    patches = test_whatif_engine.generate_recommended_patches()
    assert len(patches) > 0

    # Patches sorted by risk reduction
    for i in range(len(patches) - 1):
        assert patches[i].risk_reduction >= patches[i + 1].risk_reduction

    top = patches[0]
    assert top.paths_closed >= 1
    assert top.risk_reduction > 0
    assert top.vulnerability_id.startswith("CVE-")
