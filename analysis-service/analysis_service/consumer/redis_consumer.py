"""
AttackGraphX Analysis Service — Redis Stream Consumer
Consumes normalized scan results published by Person 1 (recon-service).
Implements:
- Redis Consumer Groups with persistent offsets
- Duplicate message protection (idempotent scan_id tracking)
- Dynamic graph topology updates from discovered hosts & services
- Message acknowledgement (XACK) and error recovery
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError

from analysis_service.config import settings
from analysis_service.graph.graph_store import GraphStore
from analysis_service.models.scan_models import IngestedScanResult

logger = logging.getLogger(__name__)


class RedisScanConsumer:
    """
    Consumes ScanResult events from Redis Streams, updates the attack graph,
    and maintains scan lifecycle records.
    """

    def __init__(self, graph_store: GraphStore):
        self.graph_store = graph_store
        self.running = False
        self._processed_scan_ids: set[str] = set()
        self.last_scan_time: Optional[str] = None
        self.last_scan_status: str = "idle"
        self.total_hosts_discovered = 0
        self.total_services_discovered = 0
        self._consumer_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Starts background consumption loop."""
        self.running = True
        self._consumer_task = asyncio.create_task(self._consume_loop())
        logger.info("Redis scan consumer started on stream '%s'", settings.redis_stream_topic)

    async def stop(self) -> None:
        """Stops background consumption loop."""
        self.running = False
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        logger.info("Redis scan consumer stopped")

    async def _consume_loop(self) -> None:
        """Continuous consumer loop with connection retry backoff."""
        stream = settings.redis_stream_topic
        group = settings.redis_consumer_group
        consumer_name = settings.redis_consumer_name

        while self.running:
            client = None
            try:
                client = aioredis.from_url(
                    settings.redis_url,
                    socket_connect_timeout=settings.redis_connect_timeout,
                    decode_responses=True,
                )

                # Initialize consumer group if not existing
                try:
                    await client.xgroup_create(stream, group, id="0", mkstream=True)
                    logger.info("Created Redis consumer group '%s' for stream '%s'", group, stream)
                except RedisError:
                    # Group likely already exists
                    pass

                while self.running:
                    try:
                        # Read new messages for this consumer group
                        entries = await client.xreadgroup(
                            groupname=group,
                            consumername=consumer_name,
                            streams={stream: ">"},
                            count=5,
                            block=2000,
                        )

                        if not entries:
                            await asyncio.sleep(0.5)
                            continue

                        for stream_name, messages in entries:
                            for message_id, fields in messages:
                                await self._process_stream_message(client, stream, group, message_id, fields)

                    except asyncio.CancelledError:
                        raise
                    except (RedisConnectionError, RedisError) as exc:
                        logger.warning("Redis stream read error: %s", exc)
                        break

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.info("Redis consumer waiting for Redis at %s (%s)", settings.redis_url, exc)
                await asyncio.sleep(5.0)
            finally:
                if client:
                    await client.aclose()

    async def _process_stream_message(
        self,
        client: Any,
        stream: str,
        group: str,
        message_id: str,
        fields: dict[str, Any],
    ) -> None:
        """Parses scan payload, updates graph idempotently, and acknowledges message."""
        try:
            raw_data = fields.get("data")
            if not raw_data:
                await client.xack(stream, group, message_id)
                return

            scan_dict = json.loads(raw_data)
            scan_result = IngestedScanResult.model_validate(scan_dict)

            # Duplicate protection
            if scan_result.scan_id in self._processed_scan_ids:
                logger.info("Skipping duplicate scan_id=%s", scan_result.scan_id)
                await client.xack(stream, group, message_id)
                return

            self._processed_scan_ids.add(scan_result.scan_id)
            self.last_scan_time = scan_result.timestamp.isoformat()
            self.last_scan_status = "completed"

            # Ingest into attack graph
            self.ingest_scan_result(scan_result)

            # Acknowledge processed message
            await client.xack(stream, group, message_id)
            logger.info("Successfully ingested scan_id=%s with %d hosts", scan_result.scan_id, len(scan_result.hosts))

        except Exception as exc:
            logger.error("Failed to process Redis stream message %s: %s", message_id, exc)
            # Acknowledge to prevent infinite poison pill loop
            try:
                await client.xack(stream, group, message_id)
            except Exception:
                pass

    def ingest_scan_result(self, scan_result: IngestedScanResult) -> None:
        """
        Dynamically updates graph topology from discovered hosts and ports.
        Connects newly discovered services and establishes reachability edges.
        """
        hosts_count = 0
        services_count = 0

        for host in scan_result.hosts:
            host_id = host.hostname or host.ip
            segment = host.segment or ("lab" if host.ip.startswith("172.20.") else "discovered")

            host_dict = {
                "id": host_id,
                "ip": host.ip,
                "hostname": host.hostname or host_id,
                "segment": segment,
                "state": host.state,
                "os": "Linux / Discovered",
                "is_compromised": False,
                "is_critical_asset": False,
                "exposure": 85 if segment in ("dmz", "lab") else 50,
            }
            self.graph_store.add_host(host_dict)
            hosts_count += 1

            for s in host.services:
                service_id = f"{host_id}:{s.port}"
                svc_dict = {
                    "id": service_id,
                    "host_id": host_id,
                    "port": s.port,
                    "protocol": s.protocol,
                    "name": s.name or "unknown",
                    "product": s.product or "",
                    "version": s.version or "",
                    "state": s.state,
                }
                self.graph_store.add_service(svc_dict)
                services_count += 1

                # If HTTP/web service discovered in lab range, connect to edge entry
                if s.port in (80, 8080, 5000):
                    self.graph_store.add_edge(
                        source="EXTERNAL",
                        target=host_id,
                        relation="CAN_REACH",
                        weight=5.0,
                        properties={"description": f"Exposed Web Service port {s.port}"},
                    )

        self.total_hosts_discovered += hosts_count
        self.total_services_discovered += services_count
        logger.info(
            "Topology updated dynamically | hosts_added=%d | services_added=%d | total_hosts=%d",
            hosts_count,
            services_count,
            self.total_hosts_discovered,
        )
