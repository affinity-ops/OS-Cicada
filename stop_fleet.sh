#!/bin/bash
# stop_fleet.sh — Gracefully stop all Cicada services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS="$SCRIPT_DIR/.fleet_pids"

echo ""
echo "Stopping Cicada fleet..."

if [ -f "$PIDS" ]; then
  while IFS='=' read -r name pid; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null && echo "  Stopped $name (PID $pid)"
    fi
  done < "$PIDS"
  rm -f "$PIDS"
fi

# Always force-clear all Cicada ports — ensures the old process has released
# the port before start_fleet.sh tries to bind. Without this, the new binary
# fails silently and the old (stale) binary keeps running.
for port in 8080 8000 3000 3001 3002 3003 3004 3005 9090 9091; do
  pid=$(lsof -ti ":$port" 2>/dev/null)
  if [ -n "$pid" ]; then
    kill -9 "$pid" 2>/dev/null && echo "  Force-killed PID $pid on :$port"
  fi
done

echo "  Fleet stopped."
echo ""
