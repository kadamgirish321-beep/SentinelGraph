"""
AttackGraphX Analysis Service — Test Configuration & Fixtures
"""
import pytest
from fastapi.testclient import TestClient

from analysis_service.main import app
from analysis_service.graph.graph_store import GraphStore
from analysis_service.simulation.what_if import WhatIfEngine
from analysis_service.risk.risk_engine import ExplainableRiskEngine
from analysis_service.consumer.redis_consumer import RedisScanConsumer


@pytest.fixture
def test_graph_store():
    """Provides a fresh in-memory graph store loaded with seed data."""
    store = GraphStore(use_neo4j=False)
    store.load_seed_data()
    return store


@pytest.fixture
def test_whatif_engine(test_graph_store):
    """Provides a WhatIfEngine backed by the test graph store."""
    return WhatIfEngine(test_graph_store)


@pytest.fixture
def test_risk_engine():
    """Provides an ExplainableRiskEngine instance."""
    return ExplainableRiskEngine()


@pytest.fixture
def test_client():
    """Provides a FastAPI test client for API endpoint testing."""
    with TestClient(app) as client:
        yield client
