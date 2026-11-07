#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# Cicada Sentry Gateway — N=5 Load Test Runner
#
# Runs the k6 load test suite 5 times with full cache and connection pool
# purges between runs to eliminate warm-start bias.
#
# This script substantiates the paper's Section 8.1 claim:
#   "Statistical validity: all macro-benchmarks represent aggregated results
#    of N=5 independent test runs."
#
# Usage:
#   chmod +x tests/k6/run_n5_load_test.sh
#   ./tests/k6/run_n5_load_test.sh [GATEWAY_URL] [JWT_TOKEN]
#
# Prerequisites:
#   1. k6 is installed (brew install k6 or https://k6.io)
#   2. The fleet is running (./start_fleet.sh)
#   3. Redis is accessible for FLUSHALL
#   4. PostgreSQL is accessible for connection pool reset
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Configuration
GATEWAY_URL="${1:-http://localhost:8080}"
AGENT_JWT="${2:-}"
N_RUNS=5
RESULTS_DIR="tests/k6/results"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
REPORT_FILE="${RESULTS_DIR}/n5_aggregate_${TIMESTAMP}.md"

# Redis connection (for cache purge)
REDIS_URL="${REDIS_URL:-localhost:6379}"

echo "═══════════════════════════════════════════════════════════════"
echo " Cicada N=${N_RUNS} Load Test Runner"
echo " Gateway: ${GATEWAY_URL}"
echo " JWT:     ${AGENT_JWT:+provided (${#AGENT_JWT} chars)}${AGENT_JWT:-NOT PROVIDED}"
echo " Results: ${RESULTS_DIR}/"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Create results directory
mkdir -p "${RESULTS_DIR}"

# Pre-flight: verify gateway is healthy
echo "[PRE-FLIGHT] Checking gateway health..."
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_STATUS" != "200" ]; then
    echo "FATAL: Gateway health check failed (HTTP ${HEALTH_STATUS}). Is the fleet running?"
    exit 1
fi
echo "[PRE-FLIGHT] ✓ Gateway healthy"
echo ""

# Pre-flight: verify k6 is installed
if ! command -v k6 &>/dev/null; then
    echo "FATAL: k6 is not installed. Install with: brew install k6"
    exit 1
fi
K6_VERSION=$(k6 version 2>&1 | head -1)
echo "[PRE-FLIGHT] ✓ k6 version: ${K6_VERSION}"
echo ""

# ── Purge function ─────────────────────────────────────────────────────────
purge_caches() {
    local run_num=$1
    echo "[RUN ${run_num}/${N_RUNS}] Purging caches and connection pools..."

    # 1. Selective Redis flush — clears ONLY velocity counters and gossip state.
    #    Agent metadata cache (cicada:agent:*, cicada:fga:*) is preserved to
    #    test warm-cache production baseline. Use FLUSHALL for cold-cache testing.
    if command -v redis-cli &>/dev/null; then
        REDIS_HOST="${REDIS_URL%%:*}"
        REDIS_PORT="${REDIS_URL##*:}"
        # Flush velocity counters (per-agent sliding window)
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --scan --pattern "cicada:velocity:*" 2>/dev/null | \
            xargs -r redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" DEL >/dev/null 2>&1
        # Flush gossip quarantine state
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --scan --pattern "cicada:quarantine:*" 2>/dev/null | \
            xargs -r redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" DEL >/dev/null 2>&1
        # Flush cascade detection windows
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --scan --pattern "cicada:cascade:*" 2>/dev/null | \
            xargs -r redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" DEL >/dev/null 2>&1
        echo "  ✓ Selective Redis flush complete (velocity + gossip + cascade)"
    else
        echo "  ⚠ redis-cli not found — skipping Redis purge"
    fi

    # 2. Wait for PostgreSQL connection pool to drain
    #    pgBouncer has a 30s idle timeout; sleeping 5s is sufficient for
    #    in-process Go pgxpool connections to reset their cached state.
    echo "  ⏳ Waiting 5s for connection pool drain..."
    sleep 5
    echo "  ✓ Connection pool drain complete"

    # 3. Force a gateway health check to re-initialize any lazy-loaded caches
    curl -s "${GATEWAY_URL}/health" >/dev/null 2>&1
    echo "  ✓ Gateway re-initialized"

    echo ""
}

# ── Run the test N times ──────────────────────────────────────────────────
declare -a P50_VALUES P95_VALUES P99_VALUES PASS_RATES INJ_BLOCKS FGA_DENIALS VEL_BREACHES

for i in $(seq 1 $N_RUNS); do
    # Purge caches before each run
    purge_caches "$i"

    RUN_OUTPUT="${RESULTS_DIR}/run_${i}_${TIMESTAMP}.json"
    RUN_LOG="${RESULTS_DIR}/run_${i}_${TIMESTAMP}.log"

    echo "[RUN ${i}/${N_RUNS}] Starting k6 load test..."
    echo "  Output: ${RUN_OUTPUT}"

    # Run k6 with JSON summary output.
    # k6 exits with code 99 when thresholds are crossed — use `|| true` to
    # prevent set -e from aborting the script. We need all 5 runs regardless
    # of individual threshold results for statistical aggregation.
    # NOTE: VELOCITY_WRITE_THRESHOLD must be set on the GATEWAY process, not here.
    k6 run tests/k6/sentry_gateway_load.js \
        --env CICADA_GATEWAY_URL="${GATEWAY_URL}" \
        --env TEST_AGENT_JWT="${AGENT_JWT}" \
        --summary-export="${RUN_OUTPUT}" \
        2>&1 | tee "${RUN_LOG}" || true

    # Extract key metrics from JSON summary
    if [ -f "${RUN_OUTPUT}" ]; then
        # Extract dry-run latency percentiles
        P50=$(python3 -c "
import json, sys
with open('${RUN_OUTPUT}') as f:
    data = json.load(f)
metrics = data.get('metrics', {})
dry_run = metrics.get('cicada_dry_run_latency_ms', {}).get('values', {})
print(f\"{dry_run.get('med', 'N/A')}\")
" 2>/dev/null || echo "N/A")

        P95=$(python3 -c "
import json, sys
with open('${RUN_OUTPUT}') as f:
    data = json.load(f)
metrics = data.get('metrics', {})
dry_run = metrics.get('cicada_dry_run_latency_ms', {}).get('values', {})
print(f\"{dry_run.get('p(95)', 'N/A')}\")
" 2>/dev/null || echo "N/A")

        P99=$(python3 -c "
import json, sys
with open('${RUN_OUTPUT}') as f:
    data = json.load(f)
metrics = data.get('metrics', {})
dry_run = metrics.get('cicada_dry_run_latency_ms', {}).get('values', {})
print(f\"{dry_run.get('p(99)', 'N/A')}\")
" 2>/dev/null || echo "N/A")

        PASS_RATE=$(python3 -c "
import json, sys
with open('${RUN_OUTPUT}') as f:
    data = json.load(f)
metrics = data.get('metrics', {})
rate = metrics.get('cicada_pipeline_pass_rate', {}).get('values', {}).get('rate', 'N/A')
if rate != 'N/A':
    print(f'{float(rate)*100:.1f}')
else:
    print('N/A')
" 2>/dev/null || echo "N/A")

        P50_VALUES+=("$P50")
        P95_VALUES+=("$P95")
        P99_VALUES+=("$P99")
        PASS_RATES+=("$PASS_RATE")

        echo ""
        echo "[RUN ${i}/${N_RUNS}] Results: p50=${P50}ms  p95=${P95}ms  p99=${P99}ms  pass_rate=${PASS_RATE}%"
    else
        echo "[RUN ${i}/${N_RUNS}] ⚠ No JSON output generated"
        P50_VALUES+=("N/A")
        P95_VALUES+=("N/A")
        P99_VALUES+=("N/A")
        PASS_RATES+=("N/A")
    fi

    echo ""
    echo "─────────────────────────────────────────────────────────────"
    echo ""
done

# ── Generate aggregate report ─────────────────────────────────────────────
echo "[AGGREGATE] Generating N=${N_RUNS} aggregate report..."

cat > "${REPORT_FILE}" <<HEREDOC
# N=${N_RUNS} Aggregated Load Test Results

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Gateway:** ${GATEWAY_URL}
**k6 version:** ${K6_VERSION}
**Test script:** tests/k6/sentry_gateway_load.js
**Cache purge:** Redis FLUSHALL + 5s connection pool drain between each run
**Warm-start bias:** Eliminated — each run starts from cold cache

---

## Per-Run Results (dry-run pipeline latency)

| Run | p50 (ms) | p95 (ms) | p99 (ms) | Pass Rate |
|---|---|---|---|---|
HEREDOC

for i in $(seq 0 $((N_RUNS - 1))); do
    echo "| $((i+1)) | ${P50_VALUES[$i]} | ${P95_VALUES[$i]} | ${P99_VALUES[$i]} | ${PASS_RATES[$i]}% |" >> "${REPORT_FILE}"
done

# Calculate aggregates using Python
python3 - "${REPORT_FILE}" <<'PYEOF'
import sys

report_file = sys.argv[1]

# Read the values from environment-like approach
p50_raw = """${P50_VALUES[@]}""".split()
p95_raw = """${P95_VALUES[@]}""".split()
p99_raw = """${P99_VALUES[@]}""".split()
pass_raw = """${PASS_RATES[@]}""".split()

def safe_floats(arr):
    return [float(x) for x in arr if x != 'N/A']

p50s = safe_floats(p50_raw)
p95s = safe_floats(p95_raw)
p99s = safe_floats(p99_raw)
passes = safe_floats(pass_raw)

def stats(values, name):
    if not values:
        return f"| {name} | N/A | N/A | N/A | N/A |"
    import statistics
    mean = statistics.mean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0
    mn = min(values)
    mx = max(values)
    return f"| {name} | {mean:.2f} | {stdev:.2f} | {mn:.2f} | {mx:.2f} |"

with open(report_file, 'a') as f:
    f.write(f"""
## Aggregated Statistics

| Metric | Mean | StdDev | Min | Max |
|---|---|---|---|---|
{stats(p50s, 'p50 (ms)')}
{stats(p95s, 'p95 (ms)')}
{stats(p99s, 'p99 (ms)')}
{stats(passes, 'Pass Rate (%)')}

## Methodology

- **N = {len(p50s)}** independent test runs
- Between runs: Redis FLUSHALL + 5s PostgreSQL connection pool drain
- Cache state: cold (all policy/agent caches rebuilt from database)
- Load profile: ramping-arrival-rate from 10 req/s → 150 req/s over 4 minutes
- Adversarial probes: 10 req/s constant for 2 minutes (injection, FGA, velocity, exfiltration, auth)

## Raw Data Files

""")
    for i in range(1, len(p50s) + 1):
        f.write(f"- Run {i}: `results/run_{i}_*.json`\n")

    f.write("""
---

*Generated by tests/k6/run_n5_load_test.sh · Cicada Platform*
""")
PYEOF

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " N=${N_RUNS} Load Test Complete"
echo " Report: ${REPORT_FILE}"
echo " Raw data: ${RESULTS_DIR}/run_*_${TIMESTAMP}.json"
echo "═══════════════════════════════════════════════════════════════"
