"""
AttackGraphX Analysis Service — Reinforcement Learning Simulation Extension
Implements a controlled, gym-style attack simulation environment:
- Discrete state space: (current_node, set of compromised nodes)
- Action space: outgoing feasible attack transitions
- Reward function: +100 for target compromise, -5 step penalty, detection penalty
- Tabular Q-learning agent with epsilon-greedy exploration
- Evaluates against Dijkstra minimum-cost baseline
"""
import random
from typing import Any, Optional
import networkx as nx

from analysis_service.algorithms.pathfinder import AttackPathfinder


class AttackSimulationEnv:
    """
    Simulated cybersecurity attack graph environment for RL experimentation.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        start_node: str = "cloud-gateway",
        target_asset: str = "db-01",
        max_steps: int = 10,
    ):
        self.graph = graph
        self.start_node = start_node
        self.target_asset = target_asset
        self.max_steps = max_steps

        self.current_node = start_node
        self.step_count = 0
        self.compromised_nodes: set[str] = {start_node}

    def reset(self) -> str:
        """Reset environment to initial state."""
        self.current_node = self.start_node
        self.step_count = 0
        self.compromised_nodes = {self.start_node}
        return self.current_node

    def get_valid_actions(self) -> list[str]:
        """Returns reachable neighbor nodes."""
        actions = []
        for neighbor in self.graph.successors(self.current_node):
            if neighbor not in self.compromised_nodes and neighbor != "EXTERNAL":
                edge_data = self.graph.get_edge_data(self.current_node, neighbor) or {}
                rel = edge_data.get("relation", "")
                if rel not in ("HAS_VULNERABILITY", "EXPOSES"):
                    actions.append(neighbor)
        return actions

    def step(self, action: str) -> tuple[str, float, bool, dict[str, Any]]:
        """
        Execute transition to target node.
        Returns: (next_state, reward, done, info)
        """
        self.step_count += 1
        valid_actions = self.get_valid_actions()

        if action not in valid_actions:
            # Invalid action penalty
            return self.current_node, -50.0, True, {"reason": "invalid_action"}

        # Edge cost and detection metadata
        edge_data = self.graph.get_edge_data(self.current_node, action) or {}
        technique = edge_data.get("technique", "T1078")
        detect_penalty = 10.0 if technique in ("T1059", "T1068") else 2.0

        self.current_node = action
        self.compromised_nodes.add(action)

        # Check goal reached
        if self.current_node == self.target_asset:
            reward = 100.0 - (self.step_count * 5.0) - detect_penalty
            return self.current_node, reward, True, {"reason": "target_compromised"}

        if self.step_count >= self.max_steps:
            return self.current_node, -20.0, True, {"reason": "max_steps_exceeded"}

        # Standard step cost
        reward = -5.0 - detect_penalty
        return self.current_node, reward, False, {"reason": "transition_success"}


class TabularQLearningAgent:
    """Simple tabular Q-learning agent for attack path discovery evaluation."""

    def __init__(self, alpha: float = 0.2, gamma: float = 0.9, epsilon: float = 0.2):
        self.q_table: dict[str, dict[str, float]] = {}
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

    def get_action(self, state: str, valid_actions: list[str]) -> Optional[str]:
        if not valid_actions:
            return None
        if random.random() < self.epsilon:
            return random.choice(valid_actions)

        state_q = self.q_table.setdefault(state, {})
        best_val = -float("inf")
        best_action = valid_actions[0]
        for a in valid_actions:
            val = state_q.get(a, 0.0)
            if val > best_val:
                best_val = val
                best_action = a
        return best_action

    def update(self, state: str, action: str, reward: float, next_state: str, next_actions: list[str]) -> None:
        state_q = self.q_table.setdefault(state, {})
        old_val = state_q.get(action, 0.0)

        next_q = self.q_table.setdefault(next_state, {})
        max_next = max([next_q.get(a, 0.0) for a in next_actions], default=0.0)

        state_q[action] = old_val + self.alpha * (reward + self.gamma * max_next - old_val)


def run_rl_vs_dijkstra_benchmark(
    graph: nx.DiGraph,
    start: str = "cloud-gateway",
    target: str = "db-01",
    episodes: int = 200,
) -> dict[str, Any]:
    """
    Trains RL agent in simulated environment and compares discovered path
    against deterministic Dijkstra shortest path baseline.
    """
    env = AttackSimulationEnv(graph, start_node=start, target_asset=target)
    agent = TabularQLearningAgent()

    # Train agent
    success_count = 0
    for _ in range(episodes):
        state = env.reset()
        done = False
        while not done:
            valid = env.get_valid_actions()
            action = agent.get_action(state, valid)
            if not action:
                break
            next_state, reward, done, info = env.step(action)
            agent.update(state, action, reward, next_state, env.get_valid_actions())
            state = next_state
            if info.get("reason") == "target_compromised":
                success_count += 1

    # Evaluate trained agent path
    agent.epsilon = 0.0
    state = env.reset()
    rl_path = [state]
    done = False
    while not done:
        valid = env.get_valid_actions()
        action = agent.get_action(state, valid)
        if not action:
            break
        state, _, done, _ = env.step(action)
        rl_path.append(state)

    # Compute Dijkstra baseline
    pathfinder = AttackPathfinder(graph)
    dijkstra_result = pathfinder.dijkstra_shortest_path(start, target)
    dijkstra_path, dijkstra_cost = dijkstra_result if dijkstra_result else ([], 0.0)

    return {
        "start": start,
        "target": target,
        "episodes_trained": episodes,
        "training_success_rate": round(success_count / episodes, 2),
        "rl_discovered_path": rl_path,
        "rl_path_hops": len(rl_path) - 1,
        "dijkstra_baseline_path": dijkstra_path,
        "dijkstra_cost": dijkstra_cost,
        "dijkstra_hops": max(0, len(dijkstra_path) - 1),
    }
