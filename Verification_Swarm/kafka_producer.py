# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DEV-ONLY TEST UTILITY — NOT USED IN PRODUCTION

This file is a development-era test shim that pushes payloads to the
Python-based mock Kafka broker (Shadow_Sandbox/_archive/mock_kafka_broker.py).

In production, the Verification Swarm communicates via Redis queues:
  - worker.py → redis brpop('cicada_swarm_queue')
  - Results → redis lpush('cicada_swarm_results')

The Shadow Sandbox Go implementation (cmd/server/main.go) receives traffic
directly from the Sentry Gateway over HTTP, not via Kafka.

Do NOT import this file in production code.
"""
import logging
import sys
import os
import json

# Bind to the mock Sandbox broker correctly
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Shadow_Sandbox'))
from mock_kafka_broker import KafkaProducerMock

logger = logging.getLogger("VerificationSwarmProducer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def push_to_sandbox(agent_id: str, payload: dict):
    """
    Pushes an unverified or potentially dangerous execution payload
    from the Verification Swarm out into the Shadow Sandbox Apache Kafka queue.
    """
    logger.info(f"Verification Swarm -> Routing Payload from {agent_id} to Shadow Sandbox Queue.")
    
    producer = KafkaProducerMock(topic="sandbox-exec")
    
    # Construct a standardized streaming envelope wrapper
    wrapped_message = {
        "source_agent": agent_id,
        "payload": payload,
        "priority": "HIGH",
        "routing_key": "shadow-fargate-cluster"
    }
    
    # Publish to the ledger
    offset = producer.produce(wrapped_message)
    logger.info(f"✓ Payload successfully queued for async execution. Partition Offset: {offset}")
    return offset

if __name__ == "__main__":
    # Test execution
    logger.info("Initializing Swarm-to-Kafka simulation test...")
    push_to_sandbox(
        agent_id="agent-0x992", 
        payload={"action": "read_db", "query": "SELECT * from users"}
    )
    push_to_sandbox(
        agent_id="agent-0x811", 
        payload={"action": "drop_tables", "query": "DROP TABLE transactions"}
    )
    logger.info("Producer test complete.")
