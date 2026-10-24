"""
AttackGraphX Analysis Service — Graph Store
Hybrid Neo4j and in-memory NetworkX graph store supporting:
- Parameterized Cypher queries against Neo4j when available
- Pure Python in-memory DiGraph fallback for resilience, unit tests, and instant startup
- Graph cloning for isolated What-If simulations
- Cytoscape format serialization for frontend rendering
"""
import copy
import logging
from typing import Any, Optional

import networkx as nx

from analysis_service.config import settings
from analysis_service.graph.seed_data import (
    DATASET_LABEL,
    SEED_HOSTS,
    SEED_ASSETS,
    SEED_VULNERABILITIES,
    SEED_ATTACK_EDGES,
)

logger = logging.getLogger(__name__)


class GraphStore:
    """
    Central graph storage abstraction for AttackGraphX.
    Maintains nodes (Host, Service, Vulnerability, Credential, Asset)
    and edges (CAN_REACH, CAN_COMPROMISE, HAS_VULNERABILITY, etc.).
    """

    def __init__(self, use_neo4j: bool = True):
        self._graph = nx.DiGraph()
        self._neo4j_driver = None
        self._neo4j_available = False
        self._version = 1

        if use_neo4j and settings.use_neo4j:
            self._init_neo4j()

        # Seed with initial enterprise topology
        self.load_seed_data()

    def _init_neo4j(self) -> None:
        """Attempt to connect to Neo4j database."""
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            # Verify connectivity
            driver.verify_connectivity()
            self._neo4j_driver = driver
            self._neo4j_available = True
            logger.info("Connected to Neo4j graph database at %s", settings.neo4j_uri)
            self._setup_neo4j_schema()
        except Exception as exc:
            logger.info("Neo4j database not reachable (%s); using resilient in-memory graph engine.", exc)
            self._neo4j_available = False
            self._neo4j_driver = None

    def _setup_neo4j_schema(self) -> None:
        """Set up constraints and indexes in Neo4j."""
        if not self._neo4j_available or not self._neo4j_driver:
            return
        constraints = [
            "CREATE CONSTRAINT host_id_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
            "CREATE CONSTRAINT service_id_unique IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
        ]
        try:
            with self._neo4j_driver.session(database=settings.neo4j_database) as session:
                for q in constraints:
                    session.run(q)
            logger.info("Neo4j constraints verified.")
        except Exception as exc:
            logger.warning("Could not create Neo4j constraints: %s", exc)

    def is_neo4j_connected(self) -> bool:
        if not self._neo4j_driver:
            return False
        try:
            self._neo4j_driver.verify_connectivity()
            return True
        except Exception:
            return False

    @property
    def version(self) -> int:
        return self._version

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def load_seed_data(self) -> None:
        """Populate graph with simulated enterprise network dataset."""
        self._graph.clear()
        self._version += 1

        # Add Hosts
        for h in SEED_HOSTS:
            self.add_host(h)

        # Add Assets
        for a in SEED_ASSETS:
            self.add_asset(a)

        # Add Vulnerabilities
        for v in SEED_VULNERABILITIES:
            self.add_vulnerability(v)

        # Add Edges
        for e in SEED_ATTACK_EDGES:
            self.add_edge(
                source=e["source"],
                target=e["target"],
                relation=e["relation"],
                weight=float(e.get("weight", 10.0)),
                properties={
                    "vulnerability_id": e.get("vulnerability_id"),
                    "technique": e.get("technique"),
                    "description": e.get("description"),
                },
            )

        # Sync with Neo4j if connected
        if self._neo4j_available and self._neo4j_driver:
            self._sync_seed_to_neo4j()

        logger.info(
            "Graph initialized with seed data | nodes=%d | edges=%d | version=%d",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
            self._version,
        )

    def _sync_seed_to_neo4j(self) -> None:
        """Sync seed nodes and edges to Neo4j using parameterized Cypher."""
        if not self._neo4j_available or not self._neo4j_driver:
            return
        try:
            with self._neo4j_driver.session(database=settings.neo4j_database) as session:
                for h in SEED_HOSTS:
                    session.run(
                        """
                        MERGE (h:Host {id: $id})
                        SET h.ip = $ip, h.hostname = $hostname, h.segment = $segment,
                            h.state = $state, h.os = $os, h.exposure = $exposure,
                            h.dataset = $dataset
                        """,
                        id=h["id"], ip=h["ip"], hostname=h.get("hostname", ""),
                        segment=h.get("segment", "internal"), state=h.get("state", "up"),
                        os=h.get("os", ""), exposure=h.get("exposure", 50),
                        dataset=DATASET_LABEL,
                    )
                for a in SEED_ASSETS:
                    session.run(
                        """
                        MERGE (a:Asset {id: $id})
                        SET a.name = $name, a.criticality = $criticality,
                            a.asset_type = $asset_type, a.classification = $data_classification
                        """,
                        id=a["id"], name=a["name"], criticality=a["criticality"],
                        asset_type=a["asset_type"], data_classification=a["data_classification"],
                    )
                for v in SEED_VULNERABILITIES:
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v.cve = $cve, v.cvss = $cvss, v.exploitability = $exploitability,
                            v.technique = $attack_technique, v.description = $description,
                            v.host = $host
                        """,
                        id=v["id"], cve=v["cve"], cvss=v["cvss"],
                        exploitability=v["exploitability"], attack_technique=v["attack_technique"],
                        description=v["description"], host=v["host"],
                    )
                for e in SEED_ATTACK_EDGES:
                    session.run(
                        """
                        MERGE (s:Host {id: $source})
                        MERGE (t:Host {id: $target})
                        MERGE (s)-[r:ATTACK_TRANSITION {relation: $relation, vuln: $vuln}]->(t)
                        SET r.weight = $weight, r.technique = $technique, r.description = $description
                        """,
                        source=e["source"], target=e["target"], relation=e["relation"],
                        vuln=e.get("vulnerability_id", ""), weight=float(e.get("weight", 10.0)),
                        technique=e.get("technique", ""), description=e.get("description", ""),
                    )
        except Exception as exc:
            logger.warning("Failed to sync seed data to Neo4j: %s", exc)

    def add_host(self, host: dict[str, Any]) -> None:
        host_id = host["id"]
        attrs = dict(host)
        attrs["node_type"] = "Host"
        self._graph.add_node(host_id, **attrs)

    def add_asset(self, asset: dict[str, Any]) -> None:
        asset_id = asset["id"]
        if self._graph.has_node(asset_id):
            self._graph.nodes[asset_id].update({
                "is_critical_asset": True,
                "asset_name": asset.get("name"),
                "criticality": asset.get("criticality", 80),
                "asset_type": asset.get("asset_type", "database"),
                "data_classification": asset.get("data_classification", "confidential"),
            })
        else:
            attrs = dict(asset)
            attrs["node_type"] = "Asset"
            attrs["is_critical_asset"] = True
            self._graph.add_node(asset_id, **attrs)

    def add_vulnerability(self, vuln: dict[str, Any]) -> None:
        vid = vuln["id"]
        attrs = dict(vuln)
        attrs["node_type"] = "Vulnerability"
        self._graph.add_node(vid, **attrs)
        # Link host to vulnerability
        host_id = vuln.get("host")
        if host_id and self._graph.has_node(host_id):
            self.add_edge(host_id, vid, relation="HAS_VULNERABILITY", weight=1.0)

    def add_service(self, service: dict[str, Any]) -> None:
        sid = service["id"]
        attrs = dict(service)
        attrs["node_type"] = "Service"
        self._graph.add_node(sid, **attrs)
        host_id = service.get("host_id")
        if host_id and self._graph.has_node(host_id):
            self.add_edge(host_id, sid, relation="EXPOSES", weight=1.0)

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        weight: float = 1.0,
        properties: Optional[dict[str, Any]] = None,
    ) -> None:
        if not self._graph.has_node(source):
            self._graph.add_node(source, node_type="Host", id=source, ip="0.0.0.0")
        if not self._graph.has_node(target):
            self._graph.add_node(target, node_type="Host", id=target, ip="0.0.0.0")

        edge_data = {
            "relation": relation,
            "weight": max(1.0, float(weight)),
            **(properties or {}),
        }
        self._graph.add_edge(source, target, **edge_data)

    def remove_vulnerability(self, vuln_id: str) -> None:
        """
        Removes edges and paths associated with a given vulnerability.
        Used by the What-If simulation engine.
        """
        edges_to_remove = []
        for u, v, data in self._graph.edges(data=True):
            if data.get("vulnerability_id") == vuln_id:
                edges_to_remove.append((u, v))

        for u, v in edges_to_remove:
            self._graph.remove_edge(u, v)

        if self._graph.has_node(vuln_id):
            self._graph.remove_node(vuln_id)

        self._version += 1

    def get_hosts(self) -> list[dict[str, Any]]:
        return [
            {"id": n, **data}
            for n, data in self._graph.nodes(data=True)
            if data.get("node_type") in ("Host", "Asset") and n != "EXTERNAL"
        ]

    def get_assets(self) -> list[dict[str, Any]]:
        return [
            {"id": n, **data}
            for n, data in self._graph.nodes(data=True)
            if data.get("node_type") == "Asset" or data.get("is_critical_asset")
        ]

    def get_vulnerabilities(self) -> list[dict[str, Any]]:
        return [
            {"id": n, **data}
            for n, data in self._graph.nodes(data=True)
            if data.get("node_type") == "Vulnerability"
        ]

    def clone(self) -> "GraphStore":
        """Produce an isolated deep-copy snapshot for What-If simulation."""
        cloned = GraphStore(use_neo4j=False)
        cloned._graph = copy.deepcopy(self._graph)
        cloned._version = self._version
        return cloned

    def to_cytoscape_elements(self) -> list[dict[str, Any]]:
        """Serialize nodes and edges to Cytoscape.js JSON elements."""
        elements = []
        for node_id, data in self._graph.nodes(data=True):
            if node_id == "EXTERNAL":
                continue
            ntype = data.get("node_type", "Host")
            label = data.get("hostname") or data.get("name") or node_id
            elements.append({
                "data": {
                    "id": str(node_id),
                    "label": str(label),
                    "type": str(ntype).lower(),
                    "ip": data.get("ip", ""),
                    "segment": data.get("segment", "internal"),
                    "criticality": data.get("criticality", 0),
                    "is_critical": data.get("is_critical_asset", False) or (data.get("criticality", 0) >= 80),
                }
            })

        for u, v, data in self._graph.edges(data=True):
            if u == "EXTERNAL":
                continue
            edge_id = f"{u}->{v}"
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": str(u),
                    "target": str(v),
                    "label": data.get("relation", "CAN_REACH"),
                    "relation": data.get("relation", "CAN_REACH"),
                    "vulnerability": data.get("vulnerability_id", ""),
                    "weight": data.get("weight", 1.0),
                    "technique": data.get("technique", ""),
                }
            })
        return elements
