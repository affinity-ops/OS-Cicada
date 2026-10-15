#!/bin/bash
# Cicada Platform — Environment Validation Script
# Run this BEFORE deploying to catch missing or invalid configuration.
#
# Usage: ./scripts/validate-env.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

check_required() {
  local file=$1 var=$2 desc=$3
  if [ ! -f "$file" ]; then
    echo -e "${RED}✗ File not found: $file${NC}"
    ERRORS=$((ERRORS + 1))
    return
  fi
  val=$(grep "^${var}=" "$file" 2>/dev/null | cut -d'=' -f2-)
  if [ -z "$val" ] || [ "$val" = "" ]; then
    echo -e "${RED}✗ MISSING: ${var} in ${file} — ${desc}${NC}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "${GREEN}✓ ${var}${NC}"
  fi
}

check_warning() {
  local file=$1 var=$2 desc=$3
  if [ ! -f "$file" ]; then return; fi
  val=$(grep "^${var}=" "$file" 2>/dev/null | cut -d'=' -f2-)
  if [ -z "$val" ] || [ "$val" = "" ]; then
    echo -e "${YELLOW}⚠ OPTIONAL: ${var} in ${file} — ${desc}${NC}"
    WARNINGS=$((WARNINGS + 1))
  else
    echo -e "${GREEN}✓ ${var}${NC}"
  fi
}

check_not_default() {
  local file=$1 var=$2 bad_val=$3 desc=$4
  if [ ! -f "$file" ]; then return; fi
  val=$(grep "^${var}=" "$file" 2>/dev/null | cut -d'=' -f2-)
  if [ "$val" = "$bad_val" ]; then
    echo -e "${RED}✗ INSECURE DEFAULT: ${var} in ${file} — ${desc}${NC}"
    ERRORS=$((ERRORS + 1))
  fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Cicada Platform — Environment Validation"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Core API ──────────────────────────────────────────────
echo "── Core API (.env) ────────────────────────────────────"
API_ENV="Core_API/.env"
check_required "$API_ENV" "APP_KEY"              "Laravel encryption key (run: php artisan key:generate)"
check_required "$API_ENV" "DB_HOST"              "PostgreSQL host"
check_required "$API_ENV" "DB_DATABASE"          "PostgreSQL database name"
check_required "$API_ENV" "DB_USERNAME"          "PostgreSQL username"
check_required "$API_ENV" "DB_PASSWORD"          "PostgreSQL password"
check_required "$API_ENV" "OPERATOR_API_KEY"     "Operator dashboard authentication key"
check_required "$API_ENV" "STRIPE_WEBHOOK_SECRET" "Stripe webhook signing secret"
check_required "$API_ENV" "FRONTEND_URL"         "Developer Portal URL"
check_required "$API_ENV" "GATEWAY_PORTAL_URL"   "Gateway Portal URL"
check_required "$API_ENV" "DASHBOARD_URL"        "Operator Dashboard URL"
check_required "$API_ENV" "CICADA_GATEWAY_URL"   "Sentry Gateway URL for EVAR minting"
check_warning  "$API_ENV" "GATEWAY_INTERNAL_KEY" "Inter-service auth key (Gateway→Core API)"
check_warning  "$API_ENV" "GITHUB_CLIENT_ID"     "GitHub OAuth app ID"
check_warning  "$API_ENV" "GOOGLE_CLIENT_ID"     "Google OAuth client ID"
check_not_default "$API_ENV" "APP_DEBUG" "true"  "APP_DEBUG must be false in production"
check_not_default "$API_ENV" "APP_ENV" "local"   "APP_ENV should be 'production'"
echo ""

# ── Dashboard ─────────────────────────────────────────────
echo "── Dashboard (.env) ───────────────────────────────────"
DASH_ENV="dashboard/.env"
[ ! -f "$DASH_ENV" ] && DASH_ENV="dashboard/.env.local"
check_required "$DASH_ENV" "NEXT_PUBLIC_CORE_API_URL"  "Core API URL"
check_required "$DASH_ENV" "NEXT_PUBLIC_OPERATOR_KEY"  "Must match OPERATOR_API_KEY in Core API"
check_warning  "$DASH_ENV" "WEBAUTHN_RP_ID"            "WebAuthn Relying Party ID (e.g. cicada.io)"
check_warning  "$DASH_ENV" "WEBAUTHN_ORIGIN"           "WebAuthn expected origin (e.g. https://admin.cicada.io)"
echo ""

# ── Sentry Gateway ────────────────────────────────────────
echo "── Sentry Gateway (.env) ──────────────────────────────"
GW_ENV="Sentry_Gateway/.env"
check_required "$GW_ENV" "DATABASE_URL"           "PostgreSQL connection string"
check_required "$GW_ENV" "REDIS_URL"              "Redis connection string"
check_warning  "$GW_ENV" "CICADA_INTERNAL_KEY"    "Must match GATEWAY_INTERNAL_KEY in Core API"
check_warning  "$GW_ENV" "CICADA_KEY_PATH"        "Path to Ed25519 private key file"
check_warning  "$GW_ENV" "TLS_CERT_FILE"          "TLS certificate for HTTPS"
check_warning  "$GW_ENV" "TLS_KEY_FILE"           "TLS private key for HTTPS"
echo ""

# ── Developer Portal ──────────────────────────────────────
echo "── Developer Portal (.env) ────────────────────────────"
DEV_ENV="Developer_Portal/.env"
[ ! -f "$DEV_ENV" ] && DEV_ENV="Developer_Portal/.env.local"
check_required "$DEV_ENV" "NEXT_PUBLIC_CORE_API_URL" "Core API URL"
echo ""

# ── Gateway Portal ────────────────────────────────────────
echo "── Gateway Portal (.env) ──────────────────────────────"
GWP_ENV="Gateway_Portal/.env"
[ ! -f "$GWP_ENV" ] && GWP_ENV="Gateway_Portal/.env.local"
check_required "$GWP_ENV" "NEXT_PUBLIC_CORE_API_URL" "Core API URL"
echo ""

# ── Key Consistency Checks ────────────────────────────────
echo "── Cross-Service Consistency ──────────────────────────"
OP_KEY_API=$(grep "^OPERATOR_API_KEY=" "$API_ENV" 2>/dev/null | cut -d'=' -f2-)
OP_KEY_DASH=$(grep "^NEXT_PUBLIC_OPERATOR_KEY=" "$DASH_ENV" 2>/dev/null | cut -d'=' -f2-)
if [ -n "$OP_KEY_API" ] && [ -n "$OP_KEY_DASH" ]; then
  if [ "$OP_KEY_API" = "$OP_KEY_DASH" ]; then
    echo -e "${GREEN}✓ OPERATOR_API_KEY matches across Core API and Dashboard${NC}"
  else
    echo -e "${RED}✗ OPERATOR_API_KEY MISMATCH between Core API and Dashboard — Dashboard will be locked out${NC}"
    ERRORS=$((ERRORS + 1))
  fi
fi

GW_INT_API=$(grep "^GATEWAY_INTERNAL_KEY=" "$API_ENV" 2>/dev/null | cut -d'=' -f2-)
GW_INT_GW=$(grep "^CICADA_INTERNAL_KEY=" "$GW_ENV" 2>/dev/null | cut -d'=' -f2-)
if [ -n "$GW_INT_API" ] && [ -n "$GW_INT_GW" ]; then
  if [ "$GW_INT_API" = "$GW_INT_GW" ]; then
    echo -e "${GREEN}✓ GATEWAY_INTERNAL_KEY matches across Core API and Sentry Gateway${NC}"
  else
    echo -e "${RED}✗ GATEWAY_INTERNAL_KEY MISMATCH — Gateway will be rejected by Core API${NC}"
    ERRORS=$((ERRORS + 1))
  fi
fi
echo ""

# ── Ed25519 Key File ──────────────────────────────────────
echo "── Ed25519 Key Persistence ────────────────────────────"
KEY_PATH=$(grep "^CICADA_KEY_PATH=" "$GW_ENV" 2>/dev/null | cut -d'=' -f2-)
KEY_PATH=${KEY_PATH:-"Sentry_Gateway/sentry_ed25519.key"}
if [ -f "$KEY_PATH" ]; then
  echo -e "${GREEN}✓ Ed25519 key file exists at ${KEY_PATH}${NC}"
else
  echo -e "${YELLOW}⚠ Ed25519 key file not found at ${KEY_PATH} — will be auto-generated on first boot${NC}"
  WARNINGS=$((WARNINGS + 1))
fi
echo ""

# ── Summary ───────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}  $ERRORS ERROR(S), $WARNINGS WARNING(S) — DO NOT DEPLOY${NC}"
  exit 1
elif [ "$WARNINGS" -gt 0 ]; then
  echo -e "${YELLOW}  0 ERRORS, $WARNINGS WARNING(S) — Review before deploying${NC}"
  exit 0
else
  echo -e "${GREEN}  ALL CHECKS PASSED — Ready to deploy${NC}"
  exit 0
fi
