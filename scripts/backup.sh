#!/usr/bin/env bash
# Cicada Action Ledger Backup Script
# Run via cron, e.g., daily at 2AM: 0 2 * * * /path/to/backup.sh
# Requires: pg_dump, gzip, aws-cli

set -euo pipefail

# Configuration
DB_CONTAINER="cicada_postgres"
DB_USER="cicada_admin"
DB_NAME="cicada_ledger"
BACKUP_DIR="/opt/cicada/backups"
S3_BUCKET="s3://your-cicada-backups-bucket"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="cicada_ledger_${DATE}.dump.gz"

echo "[$(date)] Starting Cicada DB Backup..."

# 1. Create local dir if needed
mkdir -p "${BACKUP_DIR}"

# 2. Dump from Docker container and compress
# We use custom format (-Fc) to allow granular restores with pg_restore
echo "[$(date)] Dumping database..."
docker exec ${DB_CONTAINER} pg_dump -U ${DB_USER} -Fc ${DB_NAME} | gzip > "${BACKUP_DIR}/${FILENAME}"

# 3. Restrict permissions
chmod 600 "${BACKUP_DIR}/${FILENAME}"

# 4. Sync to S3 (optional but highly recommended)
# if command -v aws >/dev/null 2>&1; then
#     echo "[$(date)] Uploading to S3..."
#     aws s3 cp "${BACKUP_DIR}/${FILENAME}" "${S3_BUCKET}/${FILENAME}" --storage-class STANDARD_IA
# fi

# 5. Cleanup local backups older than 7 days
find "${BACKUP_DIR}" -name "cicada_ledger_*.dump.gz" -mtime +7 -delete

echo "[$(date)] Backup complete: ${BACKUP_DIR}/${FILENAME}"
