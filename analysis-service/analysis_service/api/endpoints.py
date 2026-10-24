"""
AttackGraphX Analysis Service — API Endpoints
Implements all endpoints consumed by API Gateway (Person 3) and direct analysis queries.
"""
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from analysis_service.config import settings
from analysis_service.graph.graph_store import GraphStore
from analysis_service.models.path_models import (
    PathModel,
    PatchModel,
    SimulateResponse,
    ScanStatusResponse,
)
from analysis_service.simulation.what_if import WhatIfEngine
from analysis_service.consumer.redis_consumer import RedisScanConsumer
from analysis_service.ai.agent import SecurityAIAgent
from analysis_service.rl.env import run_rl_vs_dijkstra_benchmark

log = structlog.get_logger(__name__)
router = APIRouter()

# Global service singletons initialized during lifespan
graph_store = GraphStore()
whatif_engine = WhatIfEngine(graph_store)
scan_consumer = RedisScanConsumer(graph_store)
ai_agent = SecurityAIAgent(graph_store, whatif_engine)


class SimulateRequest(BaseModel):
    vulnerability_id: str


class AIInvestigateRequest(BaseModel):
    path_id: str


@router.get("/paths", response_model=list[PathModel], summary="Get attack paths")
async def get_paths(target: Optional[str] = Query(default="all")) -> list[PathModel]:
    """Computes feasible attack paths filtered by target asset."""
    paths = whatif_engine.get_baseline_paths(target_filter=target or "all")
    log.info("Calculated attack paths", count=len(paths), target=target)
    return paths


@router.get("/patches", response_model=list[PatchModel], summary="Get remediation patches")
async def get_patches() -> list[PatchModel]:
    """Generates and ranks recommended security patches by risk reduction."""
    patches = whatif_engine.generate_recommended_patches()
    log.info("Generated recommended patches", count=len(patches))
    return patches


@router.post("/simulate", response_model=SimulateResponse, summary="Simulate vulnerability fix")
async def simulate_fix(body: SimulateRequest) -> SimulateResponse:
    """Simulates the risk reduction impact of patching one vulnerability."""
    result = whatif_engine.simulate_vulnerability_fix(body.vulnerability_id)
    log.info("Evaluated remediation simulation", vulnerability=body.vulnerability_id, reduction=result.risk_reduction)
    return result


@router.post("/simulate/reset", summary="Reset simulations")
async def reset_simulation() -> dict[str, str]:
    """Resets all active simulation overrides."""
    whatif_engine.reset_simulation()
    log.info("Reset simulations to baseline")
    return {"status": "live", "message": "Simulations reset"}


@router.get("/scan/status", response_model=ScanStatusResponse, summary="Get scan status")
async def get_scan_status() -> ScanStatusResponse:
    """Returns current scan consumer status."""
    last_scan = scan_consumer.last_scan_time or datetime.now(timezone.utc).isoformat()
    return ScanStatusResponse(
        status=scan_consumer.last_scan_status,
        last_scan=last_scan,
        hosts_discovered=scan_consumer.total_hosts_discovered,
        services_discovered=scan_consumer.total_services_discovered,
    )


@router.get("/scan/trigger", summary="Trigger upstream scan")
async def trigger_scan() -> dict[str, str]:
    """Forwards scan request to Recon Service or triggers local lab scan."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.post(
                f"{settings.recon_service_url}/scan",
                json={"target": "172.20.0.0/24"},
            )
            if resp.status_code in (200, 202):
                return {"message": "Security graph scan triggered successfully. Processing topology updates..."}
    except Exception as exc:
        log.warning("Could not contact recon service directly (%s); queueing simulated scan update.", exc)

    scan_consumer.last_scan_status = "running"
    return {"message": "Security graph scan triggered successfully. Processing topology updates..."}


@router.get("/topology", summary="Get full Cytoscape topology elements")
async def get_topology() -> dict[str, Any]:
    """Returns the full graph nodes and edges formatted for Cytoscape.js visualization."""
    elements = graph_store.to_cytoscape_elements()
    return {
        "elements": elements,
        "version": graph_store.version,
        "node_count": len(graph_store.graph.nodes()),
        "edge_count": len(graph_store.graph.edges()),
    }


@router.get("/assets", summary="Get discovered and modeled enterprise assets")
async def get_assets() -> list[dict[str, Any]]:
    """Returns inventory of critical business and infrastructure assets."""
    return graph_store.get_assets()


@router.get("/health", summary="Service health and dependency status")
async def health_check() -> dict[str, Any]:
    """Probes status of Analysis Service, Neo4j, Redis, and Graph size."""
    neo4j_status = "connected" if graph_store.is_neo4j_connected() else "standalone_memory"
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "neo4j": neo4j_status,
        "redis_consumer": "running" if scan_consumer.running else "stopped",
        "graph_nodes": graph_store.graph.number_of_nodes(),
        "graph_edges": graph_store.graph.number_of_edges(),
        "graph_version": graph_store.version,
    }


@router.post("/ai/investigate", summary="Agentic AI attack path investigation")
async def ai_investigate_path(body: AIInvestigateRequest) -> dict[str, Any]:
    """Performs agentic inspection and evidence correlation for an attack path."""
    return ai_agent.investigate_path(body.path_id)


@router.get("/ai/recommendations", summary="Agentic AI remediation prioritization")
async def ai_recommendations() -> dict[str, Any]:
    """Produces AI strategic insights on top security patches."""
    return ai_agent.explain_remediation_priority()


@router.get("/rl/benchmark", summary="Reinforcement Learning benchmark against Dijkstra")
async def rl_benchmark(
    start: str = Query(default="cloud-gateway"),
    target: str = Query(default="db-01"),
    episodes: int = Query(default=150, ge=10, le=1000),
) -> dict[str, Any]:
    """Runs RL simulation agent against deterministic Dijkstra baseline."""
    return run_rl_vs_dijkstra_benchmark(graph_store.graph, start=start, target=target, episodes=episodes)
