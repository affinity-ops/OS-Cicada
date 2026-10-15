#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# Cicada Platform — Backup Verification Script (Phase 6.1)
#
# Automated PostgreSQL backup + verification via row-count comparison.
# Can be scheduled via cron, GitHub Actions, or called manually.
#
# Usage:
#   ./scripts/backup-verify.sh                    # Uses .env defaults
#   ./scripts/backup-verify.sh --db cicada_prod   # Override database
#
# Environment:
#   DATABASE_URL  — PostgreSQL connection string (or individual vars below)
#   DB_HOST       — PostgreSQL host (default: localhost)
#   DB_PORT       — PostgreSQL port (default: 5432)
#   DB_USERNAME   — PostgreSQL user (default: cicada)
#   DB_PASSWORD   — PostgreSQL password
#   DB_DATABASE   — PostgreSQL database (default: cicada)
#   BACKUP_DIR    — Directory for backup files (default: ./backups)
#
# Exit codes:
#   0 — Backup created and verified successfully
#   1 — Backup creation failed
#   2 — Restoration to temp DB failed
#   3 — Row-count mismatch detected
#   4 — Cleanup failed (non-fatal warning)
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USERNAME:-cicada}"
DB_PASS="${DB_PASSWORD:-}"
DB_NAME="${DB_DATABASE:-cicada}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEMP_DB="cicada_verify_${TIMESTAMP}"
BACKUP_FILE="${BACKUP_DIR}/cicada_backup_${TIMESTAMP}.sql.gz"

# Override database name from CLI
while [[ $# -gt 0 ]]; do
    case $1 in
        --db) DB_NAME="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Set PGPASSWORD for non-interactive auth
export PGPASSWORD="${DB_PASS}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

# ── 1. Create backup ──────────────────────────────────────────────────────

mkdir -p "${BACKUP_DIR}"

log "Starting backup of ${DB_NAME}@${DB_HOST}:${DB_PORT}"
log "Backup file: ${BACKUP_FILE}"

if ! pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
    --no-owner --no-acl --serializable-deferrable 2>/dev/null | gzip > "${BACKUP_FILE}"; then
    log "ERROR: pg_dump failed"
    exit 1
fi

BACKUP_SIZE=$(du -sh "${BACKUP_FILE}" | cut -f1)
log "Backup created: ${BACKUP_SIZE}"

# ── 2. Extract row counts from source database ────────────────────────────

log "Extracting row counts from source database..."

CRITICAL_TABLES=(
    "agents"
    "tenants"
    "action_ledger"
    "personal_access_tokens"
    "certification_events"
    "agent_policies"
    "credential_rotation_events"
    "federation_providers"
    "federation_audit_log"
    "operators"
    "operator_alerts"
)

declare -A SOURCE_COUNTS
for table in "${CRITICAL_TABLES[@]}"; do
    count=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
        -t -A -c "SELECT COUNT(*) FROM ${table}" 2>/dev/null || echo "SKIP")
    if [[ "${count}" == "SKIP" ]]; then
        log "  SKIP: ${table} (does not exist)"
    else
        SOURCE_COUNTS[${table}]=${count}
        log "  ${table}: ${count} rows"
    fi
done

# ── 3. Restore to temporary database ──────────────────────────────────────

log "Creating temporary verification database: ${TEMP_DB}"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
    -c "CREATE DATABASE ${TEMP_DB}" 2>/dev/null

log "Restoring backup to ${TEMP_DB}..."

if ! gunzip -c "${BACKUP_FILE}" | psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" \
    -d "${TEMP_DB}" --quiet 2>/dev/null; then
    log "ERROR: Restoration failed"
    # Cleanup temp DB on failure
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
        -c "DROP DATABASE IF EXISTS ${TEMP_DB}" 2>/dev/null || true
    exit 2
fi

log "Restoration complete"

# ── 4. Verify row counts ──────────────────────────────────────────────────

log "Verifying row counts..."

MISMATCH=0
VERIFIED=0

for table in "${!SOURCE_COUNTS[@]}"; do
    source_count=${SOURCE_COUNTS[${table}]}
    restored_count=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TEMP_DB}" \
        -t -A -c "SELECT COUNT(*) FROM ${table}" 2>/dev/null || echo "MISSING")

    if [[ "${restored_count}" == "MISSING" ]]; then
        log "  FAIL: ${table} — table missing from restored database"
        MISMATCH=1
    elif [[ "${source_count}" != "${restored_count}" ]]; then
        log "  FAIL: ${table} — source=${source_count}, restored=${restored_count}"
        MISMATCH=1
    else
        log "  OK:   ${table} — ${source_count} rows verified"
        ((VERIFIED++))
    fi
done

# ── 5. Cleanup ────────────────────────────────────────────────────────────

log "Dropping temporary database ${TEMP_DB}..."
if ! psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
    -c "DROP DATABASE IF EXISTS ${TEMP_DB}" 2>/dev/null; then
    log "WARNING: Failed to drop temp database ${TEMP_DB} — manual cleanup needed"
fi

# ── 6. Report ─────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  BACKUP VERIFICATION REPORT"
echo "═══════════════════════════════════════════════════════════════"
echo "  Database:     ${DB_NAME}"
echo "  Backup file:  ${BACKUP_FILE}"
echo "  Backup size:  ${BACKUP_SIZE}"
echo "  Tables checked: ${#SOURCE_COUNTS[@]}"
echo "  Tables verified: ${VERIFIED}"
echo "  Timestamp:    ${TIMESTAMP}"
echo ""

if [[ ${MISMATCH} -eq 1 ]]; then
    echo "  STATUS: ❌ VERIFICATION FAILED — row count mismatch detected"
    echo "═══════════════════════════════════════════════════════════════"
    exit 3
else
    echo "  STATUS: ✅ BACKUP VERIFIED — all row counts match"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
fi
