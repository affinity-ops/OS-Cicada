# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import time
import os
import sys

# Configure exact pathing so we can easily import MockFirecracker and Broker
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mock_kafka_broker import KafkaConsumerMock
from mock_firecracker import MockFirecrackerVM

logger = logging.getLogger("KafkaConsumerDaemon")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def start_ingestion_loop():
    logger.info("Initializing Shadow Sandbox Ingestion Loop on topic 'sandbox-exec'...")
    consumer = KafkaConsumerMock(topic="sandbox-exec", group_id="firecracker-fleet-1")
    
    logger.info("Listening for incoming isolation execution requests. Press Ctrl+C to terminate.")
    
    try:
        while True:
            # Long-poll the native queue mimicking Kafka semantics
            messages = consumer.poll(timeout_ms=2000)
            
            for msg in messages:
                offset = msg['offset']
                payload = msg['value']
                
                logger.info(f"==> Received isolation payload at Offset {offset}. Routing to Firecracker...")
                
                # Provision a transient Mock Firecracker VM
                vm = MockFirecrackerVM(f"shadow-vm-{offset}")
                vm.boot()
                
                # Execute payload in the mock isolated environment
                result = vm.execute_payload(payload, sandbox_policy="strict_immutable")
                
                # Destroy VM
                vm.destroy()
                
                # Log execution verdict
                if result.get("sandbox_verdict") == "nominal":
                    logger.info(f"✓ Execution successful for Offset {offset}. Payload clean.")
                else:
                    logger.error(f"✗ Threat isolated! Payload blocked for Offset {offset}: {result.get('details')}")
                    
    except KeyboardInterrupt:
        logger.info("Shutting down Shadow Sandbox Ingestion Loop gracefully.")

if __name__ == "__main__":
    start_ingestion_loop()
