"""
Tests for AI Agent and Reinforcement Learning extension.
"""
from analysis_service.ai.agent import SecurityAIAgent
from analysis_service.rl.env import AttackSimulationEnv, TabularQLearningAgent, run_rl_vs_dijkstra_benchmark


def test_ai_investigate_path(test_graph_store, test_whatif_engine):
    agent = SecurityAIAgent(test_graph_store, test_whatif_engine)
    report = agent.investigate_path("PATH-001")

    assert report["found"] is True
    assert "transitions" in report
    assert len(report["transitions"]) > 0
    assert "executive_summary" in report
    assert report["deterministic_validated"] is True


def test_ai_recommendations(test_graph_store, test_whatif_engine):
    agent = SecurityAIAgent(test_graph_store, test_whatif_engine)
    res = agent.explain_remediation_priority()

    assert "top_recommendation" in res
    assert "strategic_insights" in res
    assert len(res["strategic_insights"]) > 0


def test_rl_env_step_and_benchmark(test_graph_store):
    env = AttackSimulationEnv(test_graph_store.graph, start_node="cloud-gateway", target_asset="db-01")
    state = env.reset()
    assert state == "cloud-gateway"

    valid_actions = env.get_valid_actions()
    assert len(valid_actions) > 0

    next_state, reward, done, info = env.step(valid_actions[0])
    assert next_state == valid_actions[0]
    assert isinstance(reward, float)

    # Run small benchmark
    benchmark = run_rl_vs_dijkstra_benchmark(
        test_graph_store.graph,
        start="cloud-gateway",
        target="db-01",
        episodes=30,
    )
    assert "episodes_trained" in benchmark
    assert "training_success_rate" in benchmark
    assert "dijkstra_baseline_path" in benchmark
    assert len(benchmark["dijkstra_baseline_path"]) > 0
