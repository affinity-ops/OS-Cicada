#!/bin/bash
# ============================================================================
# Schema Parity Verification Script
# ============================================================================
#
# Compares every table and column between cicada_ledger (production) and
# cicada_test (test) to catch schema drift before it becomes a test failure.
#
# Exit code:
#   0 = schemas are identical
#   1 = drift detected (details printed to stdout)
#
# Usage:
#   ./scripts/verify-schema-parity.sh
#   ./scripts/verify-schema-parity.sh --ci   (fails loudly for CI pipelines)
#
# This script is designed to run as a CI gate. Any future Go-managed column
# that doesn't have a corresponding Laravel migration will be caught here.
# ============================================================================

set -euo pipefail

DB_USER="${DB_USERNAME:-patrickmatthews}"
DB_HOST="${DB_HOST:-127.0.0.1}"
PROD_DB="${DB_DATABASE:-cicada_ledger}"
TEST_DB="${DB_TEST_DATABASE:-cicada_test}"
CI_MODE="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DRIFT_FOUND=0

echo "══════════════════════════════════════════════════════════════"
echo "  Schema Parity Check: ${PROD_DB} ↔ ${TEST_DB}"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Compare table lists ─────────────────────────────────────────────

PROD_TABLES=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$PROD_DB" -t -A -c \
  "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'action_ledger_y%' AND tablename != 'action_ledger_default' ORDER BY tablename;" 2>/dev/null)

TEST_TABLES=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$TEST_DB" -t -A -c \
  "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'action_ledger_y%' AND tablename != 'action_ledger_default' ORDER BY tablename;" 2>/dev/null)

MISSING_IN_TEST=$(comm -23 <(echo "$PROD_TABLES") <(echo "$TEST_TABLES"))
EXTRA_IN_TEST=$(comm -13 <(echo "$PROD_TABLES") <(echo "$TEST_TABLES"))

if [ -n "$MISSING_IN_TEST" ]; then
  echo -e "${RED}✘ Tables in PRODUCTION but missing from TEST:${NC}"
  echo "$MISSING_IN_TEST" | while read -r t; do echo "    - $t"; done
  DRIFT_FOUND=1
fi

if [ -n "$EXTRA_IN_TEST" ]; then
  echo -e "${YELLOW}⚠ Tables in TEST but not in PRODUCTION (may be test-only):${NC}"
  echo "$EXTRA_IN_TEST" | while read -r t; do echo "    - $t"; done
fi

# ── Step 2: Compare columns for each shared table ───────────────────────────

SHARED_TABLES=$(comm -12 <(echo "$PROD_TABLES") <(echo "$TEST_TABLES"))

TABLE_COUNT=0
COLUMN_DRIFT_COUNT=0

while IFS= read -r table; do
  [ -z "$table" ] && continue
  TABLE_COUNT=$((TABLE_COUNT + 1))

  PROD_COLS=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$PROD_DB" -t -A -c \
    "SELECT column_name FROM information_schema.columns WHERE table_name='$table' ORDER BY column_name;" 2>/dev/null)

  TEST_COLS=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$TEST_DB" -t -A -c \
    "SELECT column_name FROM information_schema.columns WHERE table_name='$table' ORDER BY column_name;" 2>/dev/null)

  MISSING_COLS=$(comm -23 <(echo "$PROD_COLS") <(echo "$TEST_COLS"))
  EXTRA_COLS=$(comm -13 <(echo "$PROD_COLS") <(echo "$TEST_COLS"))

  if [ -n "$MISSING_COLS" ]; then
    echo -e "${RED}✘ ${table}: columns in PRODUCTION but missing from TEST:${NC}"
    echo "$MISSING_COLS" | while read -r c; do echo "    - $c"; done
    COLUMN_DRIFT_COUNT=$((COLUMN_DRIFT_COUNT + 1))
    DRIFT_FOUND=1
  fi

  if [ -n "$EXTRA_COLS" ]; then
    echo -e "${YELLOW}⚠ ${table}: columns in TEST but not in PRODUCTION:${NC}"
    echo "$EXTRA_COLS" | while read -r c; do echo "    - $c"; done
  fi
done <<< "$SHARED_TABLES"

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "──────────────────────────────────────────────────────────────"
if [ "$DRIFT_FOUND" -eq 0 ]; then
  echo -e "${GREEN}✔ PASS: All tables and columns match across ${TABLE_COUNT} tables${NC}"
  echo "  Production: ${PROD_DB}"
  echo "  Test:       ${TEST_DB}"
  exit 0
else
  echo -e "${RED}✘ FAIL: Schema drift detected${NC}"
  echo "  Tables with column drift: ${COLUMN_DRIFT_COUNT}"
  echo ""
  echo "  Fix: Create a Laravel migration in Core_API/database/migrations/"
  echo "  Then: php artisan migrate && DB_DATABASE=cicada_test php artisan migrate:fresh"
  if [ "$CI_MODE" = "--ci" ]; then
    echo ""
    echo -e "${RED}CI GATE BLOCKED — schema parity required before merge${NC}"
  fi
  exit 1
fi
