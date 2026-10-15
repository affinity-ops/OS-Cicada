#!/bin/bash
# start_fleet.sh — Cicada platform startup (no Docker)
# Startup order: PostgreSQL(pre-flight) → Redis(pre-flight) → Sentry Gateway → Core API → Swarm → Saga → Shadow Sandbox → Operator Dashboard → Developer Portal → Gateway Portal → Landing Page → APK Server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PHP="/Users/patrickmatthews/Library/Application Support/Herd/bin/php"
LOGS="$SCRIPT_DIR/logs"
PIDS="$SCRIPT_DIR/.fleet_pids"

mkdir -p "$LOGS"

# ─── Cleanup: Kill stale processes from a previous run ────────────────────────
kill_port() {
  local port="$1"
  local pid
  pid=$(lsof -ti :"$port" 2>/dev/null)
  if [ -n "$pid" ]; then
    echo "  [cleanup] Killing stale process on :$port (PID $pid)"
    kill -9 "$pid" 2>/dev/null
    sleep 0.5
  fi
}

if [ -f "$PIDS" ]; then
  echo "[cleanup] Killing stale processes from previous fleet run..."
  while IFS='=' read -r name pid; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      echo "  Stopped stale $name (PID $pid)"
    fi
  done < "$PIDS"
  sleep 1
fi

# Force-clear critical ports
for port in 8080 8000 9090 9091 3000 3001 3002 3003 3004 3005 3006; do
  kill_port "$port"
done

# Kill orphaned Python workers that don't bind ports.
# The bash wrappers in start_service get recorded in $PIDS, but
# kill -9 on a bash parent does NOT propagate to the Python child —
# it gets reparented to launchd and keeps running. These workers use
# Redis BRPOP, not TCP ports, so the port cleanup above misses them.
for pattern in "python saga_worker.py" "python worker.py"; do
  pids=$(pgrep -f "$pattern" 2>/dev/null)
  if [ -n "$pids" ]; then
    echo "  [cleanup] Killing orphaned '$pattern' processes: $pids"
    echo "$pids" | xargs kill 2>/dev/null
    sleep 0.5
  fi
done

> "$PIDS"   # Reset PID file

# ─── Pre-flight: .env ────────────────────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/.env" ]; then
  echo "✗ FATAL: .env not found. Copy .env.example and fill in values."
  exit 1
fi

# Load environment
set -a
source .env
set +a

# ─── Pre-flight: PostgreSQL ───────────────────────────────────────────────────
echo "[pre-flight] PostgreSQL"
# Strip scheme, then strip optional user:pass@ prefix, then split host:port
_pg_authority=$(echo "$CICADA_POSTGRES_URL" | sed -E 's|^postgres(ql)?://||' | sed -E 's|^[^@]*@||')
PG_HOST=$(echo "$_pg_authority" | cut -d: -f1 | cut -d/ -f1)
PG_PORT=$(echo "$_pg_authority" | cut -d: -f2 | cut -d/ -f1)
PG_PORT="${PG_PORT:-5432}"
if ! pg_isready -h "$PG_HOST" -p "$PG_PORT" -q 2>/dev/null; then
  echo "✗ FATAL: PostgreSQL is not reachable at $PG_HOST:$PG_PORT"
  echo "  Start PostgreSQL first: brew services start postgresql@15"
  exit 1
fi
echo "  PostgreSQL ✓ ($PG_HOST:$PG_PORT)"

# ─── Pre-flight: Redis ────────────────────────────────────────────────────────
echo "[pre-flight] Redis"
_redis_authority=$(echo "$CICADA_REDIS_URL" | sed -E 's|^redis://||')
REDIS_HOST=$(echo "$_redis_authority" | cut -d: -f1)
REDIS_PORT=$(echo "$_redis_authority" | cut -d: -f2)
REDIS_PORT="${REDIS_PORT:-6379}"
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG; then
  echo "✗ FATAL: Redis is not reachable at $REDIS_HOST:$REDIS_PORT"
  echo "  Start Redis first: brew services start redis"
  exit 1
fi
echo "  Redis ✓ ($REDIS_HOST:$REDIS_PORT)"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       CICADA PLATFORM — STARTING         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── Helpers ────────────────────────────────────────────────────────────────

wait_for_http() {
  local url="$1" label="$2" retries="${3:-30}"
  echo -n "  Waiting for $label"
  for i in $(seq 1 "$retries"); do
    if curl -sf --max-time 2 "$url" > /dev/null 2>&1; then
      echo " ✓"
      return 0
    fi
    echo -n "."
    sleep 2
  done
  echo " ✗ (timeout after ${retries}s — check logs)"
  return 0  # Don't abort fleet for a slow service; just warn.
}

start_service() {
  local label="$1" pid_var="$2"
  shift 2
  "$@" &
  local pid=$!
  echo "$pid_var=$pid" >> "$PIDS"
  echo "  [$label] started (PID $pid)"
}

# ─── 1. Sentry Gateway ───────────────────────────────────────────────────────
echo "[1/10] Sentry Gateway (Go, :8080)"

# Auto-detect the LAN IP for the QR payload's gw field.
# The phone connects to this IP — NOT localhost.
LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "localhost")
export GATEWAY_PUBLIC_URL="http://${LAN_IP}:8080"
# Core API URL — Gateway uses this for portal session authentication and
# QR code generation. Must point to wherever Laravel is running.
export CICADA_CORE_API_URL="http://localhost:8000"
echo "  GATEWAY_PUBLIC_URL=${GATEWAY_PUBLIC_URL}"
echo "  CICADA_CORE_API_URL=${CICADA_CORE_API_URL}"

echo "  Building latest binary..."
(cd "$SCRIPT_DIR/Sentry_Gateway" && go build -o sentry ./cmd/sentry) || {
  echo "✗ FATAL: Sentry Gateway build failed. Run: cd Sentry_Gateway && go build -o sentry ./cmd/sentry"
  exit 1
}
start_service "sentry" "SENTRY_PID" \
  bash -c "cd '$SCRIPT_DIR/Sentry_Gateway' && CICADA_DEV_MODE=true CICADA_MOCK_MODE=true GATEWAY_PUBLIC_URL='$GATEWAY_PUBLIC_URL' CICADA_CORE_API_URL='$CICADA_CORE_API_URL' ./sentry >> '$LOGS/sentry.log' 2>&1"
wait_for_http "http://localhost:8080/health" "Sentry Gateway :8080" 15

# ─── 2. Core API ─────────────────────────────────────────────────────────────
echo "[2/10] Core API (Laravel, :8000)"
start_service "core_api" "LARAVEL_PID" \
  bash -c "cd '$SCRIPT_DIR/Core_API' && '$PHP' artisan serve --port=8000 >> '$LOGS/core_api.log' 2>&1"
wait_for_http "http://localhost:8000/api/v1/dashboard/summary" "Core API :8000" 45

start_service "swarm_results_worker" "SWARM_RES_PID" \
  bash -c "cd '$SCRIPT_DIR/Core_API' && '$PHP' artisan cicada:process-swarm-results >> '$LOGS/swarm_results.log' 2>&1"
echo "  [core_api] swarm results worker running"

# ─── 3. Verification Swarm ───────────────────────────────────────────────────
echo "[3/10] Verification Swarm (Python)"
if [ ! -f "$SCRIPT_DIR/Verification_Swarm/.venv/bin/python" ]; then
  echo "  No venv found — creating and installing..."
  (cd "$SCRIPT_DIR/Verification_Swarm" && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt) || {
    echo "✗ FATAL: Verification Swarm venv setup failed."
    exit 1
  }
fi
start_service "swarm_server" "SWARM_SERVER_PID" \
  bash -c "cd '$SCRIPT_DIR/Verification_Swarm' && .venv/bin/python server.py >> '$LOGS/swarm_server.log' 2>&1"
wait_for_http "http://localhost:9091/health" "Verification Swarm :9091" 15
echo "  [swarm] sync http server running"

start_service "swarm_worker" "SWARM_WORKER_PID" \
  bash -c "cd '$SCRIPT_DIR/Verification_Swarm' && .venv/bin/python worker.py >> '$LOGS/swarm_worker.log' 2>&1"
echo "  [swarm] background queue worker running"

# ─── 4. Saga Executor ────────────────────────────────────────────────────────
echo "[4/10] Saga Executor (Python)"
if [ ! -f "$SCRIPT_DIR/Saga_Executor/.venv/bin/python" ]; then
  echo "  No venv found — creating and installing..."
  (cd "$SCRIPT_DIR/Saga_Executor" && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt) || {
    echo "✗ FATAL: Saga Executor venv setup failed."
    exit 1
  }
fi
start_service "saga" "SAGA_PID" \
  bash -c "cd '$SCRIPT_DIR/Saga_Executor' && .venv/bin/python saga_worker.py >> '$LOGS/saga.log' 2>&1"
echo "  [saga] worker running"

# ─── 5. Shadow Sandbox (Local Go binary, :9090) ────────────────────────────────────
echo "[5/10] Shadow Sandbox (Go, :9090)"
echo "  Building latest binary..."
(cd "$SCRIPT_DIR/Shadow_Sandbox" && go build -o sandbox ./cmd/server) || {
  echo "✗ FATAL: Shadow Sandbox build failed."
  exit 1
}
mkdir -p "$SCRIPT_DIR/Shadow_Sandbox/data"
start_service "sandbox" "SANDBOX_PID" \
  bash -c "cd '$SCRIPT_DIR/Shadow_Sandbox' && SANDBOX_PORT=9090 SANDBOX_DB_PATH='$SCRIPT_DIR/Shadow_Sandbox/data/sandbox.db' CICADA_GATEWAY_GOSSIP_URL='http://localhost:8080/v1/sandbox/report' ./sandbox >> '$LOGS/shadow_sandbox.log' 2>&1"
wait_for_http "http://localhost:9090/health" "Shadow Sandbox :9090" 15

# ─── 6. Operator Dashboard ───────────────────────────────────────────────────
echo "[6/10] Operator Dashboard (Next.js, :3000)"
start_service "dashboard" "DASH_PID" \
  bash -c "cd '$SCRIPT_DIR/dashboard' && npm start >> '$LOGS/dashboard.log' 2>&1"
wait_for_http "http://localhost:3000" "Operator Dashboard :3000" 60

# ─── 7. Developer Portal ─────────────────────────────────────────────────────
echo "[7/10] Developer Portal (Next.js, :3001)"
start_service "dev_portal" "DEV_PID" \
  bash -c "cd '$SCRIPT_DIR/Developer_Portal' && npm start >> '$LOGS/developer_portal.log' 2>&1"
wait_for_http "http://localhost:3001" "Developer Portal :3001" 60

# ─── 8. Gateway Portal ───────────────────────────────────────────────────────
echo "[8/10] Gateway Portal (Next.js, :3002)"
start_service "gw_portal" "GW_PID" \
  bash -c "cd '$SCRIPT_DIR/Gateway_Portal' && npm start >> '$LOGS/gateway_portal.log' 2>&1"
wait_for_http "http://localhost:3002" "Gateway Portal :3002" 60

# ─── 9. APK Download Server ─────────────────────────────────────────────────
echo "[9/10] APK Download Server (Python, :3004)"
start_service "apk_server" "APK_PID" \
  bash -c "cd '$SCRIPT_DIR/Ciba_Flutter_App/apk_server' && python3 -m http.server 3004 --bind 0.0.0.0 >> '$LOGS/apk_server.log' 2>&1"
wait_for_http "http://localhost:3004" "APK Server :3004" 10

# ─── 10. Master Admin Panel ──────────────────────────────────────────────────
echo "[10/10] Master Admin Panel (Next.js, :3005)"
# Rebuild native addon if compiled for a different Node version
(cd "$SCRIPT_DIR/Master_Admin_Panel" && npm rebuild better-sqlite3 > /dev/null 2>&1) || true
start_service "master_admin" "MASTER_ADMIN_PID" \
  bash -c "cd '$SCRIPT_DIR/Master_Admin_Panel' && PORT=3005 npm run dev >> '$LOGS/master_admin.log' 2>&1"
wait_for_http "http://localhost:3005" "Master Admin Panel :3005" 60

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        CICADA FLEET IS ONLINE            ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Sentry Gateway    →  http://localhost:8080"
echo "  Core API          →  http://localhost:8000"
echo "  Shadow Sandbox    →  http://localhost:9090"
echo "  Operator Dashboard→  http://localhost:3000"
echo "  Developer Portal  →  http://localhost:3001"
echo "  Gateway Portal    →  http://localhost:3002"
echo "  APK Download      →  http://localhost:3004"
echo "  Master Admin Panel→  http://localhost:3005"
echo ""
echo "  Logs              →  $LOGS/"
echo "  PIDs              →  $PIDS"
echo ""
echo "  Run ./stop_fleet.sh to shut down."
echo ""
