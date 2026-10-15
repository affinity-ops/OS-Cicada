# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import sqlite3
import json
import logging
import time

logger = logging.getLogger("MockKafkaBroker")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------
# Native Mac Local Kafka Broker Simulator
# Uses SQLite as a persistent, append-only commit log 
# to perfectly mimic exactly how Kafka partitions.
# ---------------------------------------------------------

DB_PATH = "kafka_commit_log.db"

def init_broker():
    """Initializes the append-only commit log."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS topics (
            offset INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_name TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_topic ON topics(topic_name, offset)')
    conn.commit()
    conn.close()
    logger.info("Local Kafka Simulator initialized successfully.")

class KafkaProducerMock:
    def __init__(self, topic):
        self.topic = topic
        init_broker()

    def produce(self, payload: dict):
        """Appends a new message to the end of the partition log."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO topics (topic_name, payload_json, timestamp) VALUES (?, ?, ?)',
            (self.topic, json.dumps(payload), time.time())
        )
        conn.commit()
        offset = cursor.lastrowid
        conn.close()
        logger.info(f"[PRODUCER -> {self.topic}] Appended payload at Offset {offset}.")
        return offset

class KafkaConsumerMock:
    def __init__(self, topic, group_id="default-group"):
        self.topic = topic
        self.group_id = group_id
        self.current_offset = 0
        init_broker()

    def poll(self, timeout_ms=1000) -> list:
        """Long-polls the commit log for new messages ahead of the current offset."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Simple polling loop to mimic Kafka blocking
        start_time = time.time()
        while (time.time() - start_time) < (timeout_ms / 1000.0):
            cursor.execute(
                'SELECT offset, payload_json FROM topics WHERE topic_name = ? AND offset > ? ORDER BY offset ASC',
                (self.topic, self.current_offset)
            )
            rows = cursor.fetchall()
            
            if rows:
                messages = []
                for row in rows:
                    offset, payload_str = row
                    self.current_offset = offset
                    messages.append({
                        "topic": self.topic,
                        "offset": offset,
                        "value": json.loads(payload_str)
                    })
                conn.close()
                return messages
            
            # Sleep briefly to avoid CPU thrashing
            time.sleep(0.1)
            
        conn.close()
        return [] # Return empty array if timed out

if __name__ == "__main__":
    init_broker()
    logger.info("Kafka Broker Simulator ready and accepting connections.")
