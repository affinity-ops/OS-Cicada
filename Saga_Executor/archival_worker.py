# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import time
import logging
import psycopg2
from psycopg2 import sql
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import boto3
from datetime import datetime
from dateutil.relativedelta import relativedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ArchivalWorker')

DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_DATABASE', 'cicada_ledger')
DB_USER = os.getenv('DB_USERNAME', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')

S3_BUCKET = os.getenv('AWS_BUCKET', '')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', '')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', '')

# Path for local fallback if S3 is not configured
LOCAL_ARCHIVE_DIR = os.getenv('LOCAL_ARCHIVE_DIR', '/tmp/cicada_archives')

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

def upload_to_s3(file_path, object_name):
    if not S3_BUCKET:
        logger.info(f"S3 not configured. Keeping local archive: {file_path}")
        return True

    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY
        )
        s3_client.upload_file(file_path, S3_BUCKET, object_name)
        logger.info(f"Successfully uploaded {file_path} to s3://{S3_BUCKET}/{object_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload to S3: {e}")
        return False

def check_and_archive_partitions():
    logger.info("Checking for partitions older than 90 days...")
    
    # 90 days ago
    cutoff_date = datetime.now() - relativedelta(days=90)
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Query to find partitions of action_ledger
        cur.execute("""
            SELECT
                inhrelid::regclass::text AS partition_name
            FROM pg_class c
            JOIN pg_inherits i ON c.oid = i.inhrelid
            WHERE i.inhparent = 'action_ledger'::regclass;
        """)
        
        partitions = cur.fetchall()
        
        for (partition_name,) in partitions:
            # Expected format: action_ledger_yYYYYmMM
            if not partition_name.startswith('action_ledger_y'):
                continue
                
            try:
                # Extract year and month
                # Example: action_ledger_y2026m04
                parts = partition_name.split('_y')
                date_part = parts[1] # 2026m04
                year = int(date_part[:4])
                month = int(date_part[5:7])
                
                # We check the end of the partition's month to be safe
                # If the partition represents April 2026, we check if May 1st 2026 is older than 90 days ago.
                partition_end_date = datetime(year, month, 1) + relativedelta(months=1)
                
                if partition_end_date < cutoff_date:
                    logger.info(f"Partition {partition_name} is older than 90 days. Archiving...")
                    
                    # Use psycopg2.sql.Identifier for safe table name quoting
                    # to prevent SQL injection via partition names.
                    query = sql.SQL("SELECT * FROM {}").format(sql.Identifier(partition_name))
                    # Using pandas read_sql_query directly with psycopg2 connection
                    df = pd.read_sql_query(query.as_string(conn), conn)
                    
                    if not os.path.exists(LOCAL_ARCHIVE_DIR):
                        os.makedirs(LOCAL_ARCHIVE_DIR)
                        
                    parquet_filename = f"{partition_name}.parquet"
                    local_file_path = os.path.join(LOCAL_ARCHIVE_DIR, parquet_filename)
                    
                    df.to_parquet(local_file_path, index=False)
                    logger.info(f"Exported {len(df)} rows to {local_file_path}")
                    
                    # 2. Upload to S3
                    s3_object_name = f"action_ledger_archives/{year}/{month:02d}/{parquet_filename}"
                    success = upload_to_s3(local_file_path, s3_object_name)
                    
                    # 3. Drop partition if upload successful
                    if success:
                        cur.execute(sql.SQL("DROP TABLE {}").format(sql.Identifier(partition_name)))
                        conn.commit()
                        logger.info(f"Dropped partition {partition_name} from database.")
                        
                        # Cleanup local file if uploaded to S3
                        if S3_BUCKET and os.path.exists(local_file_path):
                            os.remove(local_file_path)
                    else:
                        logger.error(f"Skipping DROP TABLE for {partition_name} due to upload failure.")
                        
            except Exception as e:
                logger.error(f"Error processing partition {partition_name}: {e}")
                
        cur.close()
    except Exception as e:
        logger.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    logger.info("Archival worker started.")
    while True:
        check_and_archive_partitions()
        # Run once a day
        time.sleep(86400)
