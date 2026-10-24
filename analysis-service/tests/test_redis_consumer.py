"""
Unit tests for RedisScanConsumer and dynamic topology ingestion.
"""
from datetime import datetime, timezone
from analysis_service.consumer.redis_consumer import RedisScanConsumer
from analysis_service.models.scan_models import (
    IngestedHost,
    IngestedService,
    IngestedScanResult,
)


def test_scan_ingestion_updates_topology(test_graph_store):
    consumer = RedisScanConsumer(test_graph_store)

    initial_nodes = test_graph_store.graph.number_of_nodes()

    scan_result = IngestedScanResult(
        scan_id="scan-unit-test-1",
        timestamp=datetime.now(timezone.utc),
        scanner="nmap",
        target_scope="172.20.0.0/24",
        hosts=[
            IngestedHost(
                ip="172.20.0.25",
                hostname="new-target-box",
                state="up",
                segment="lab",
                services=[
                    IngestedService(
                        port=80,
                        protocol="tcp",
                        state="open",
                        name="http",
                        product="apache",
                        version="2.4",
                    )
                ],
            )
        ],
    )

    consumer.ingest_scan_result(scan_result)

    assert test_graph_store.graph.number_of_nodes() > initial_nodes
    assert test_graph_store.graph.has_node("new-target-box")
    assert test_graph_store.graph.has_node("new-target-box:80")
    # Discovered web port 80 connected to external entry
    assert test_graph_store.graph.has_edge("EXTERNAL", "new-target-box")
