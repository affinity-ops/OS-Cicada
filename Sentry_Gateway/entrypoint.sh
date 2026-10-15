#!/bin/sh
# Cicada Sentry Gateway — Entrypoint with Ed25519 Key Persistence Guard
#
# Prevents silent key regeneration that would invalidate all active EVARs.
#
# Behaviour:
#   First boot:  Gateway generates key normally, marker created on same volume.
#   Subsequent:  If marker exists but key is missing → FATAL EXIT.
#   Override:    Set ALLOW_KEY_REGEN=true to force fresh key (burns all EVARs).
#
# CRITICAL: Both the key file and marker MUST live on the same persistent volume.
#           If the marker is on ephemeral container root, restarts would wrongly
#           treat every boot as first boot, defeating the guard entirely.

set -e

KEY_PATH="${CICADA_KEY_PATH:-/data/sentry_ed25519.key}"
KEY_DIR="$(dirname "$KEY_PATH")"
MARKER_FILE="${KEY_PATH}.booted"    # Co-located with key on persistent volume
LOCK_FILE="${KEY_DIR}/.startup.lock"

# Ensure the key directory exists
mkdir -p "$KEY_DIR"

# ── Intentional reset escape hatch ────────────────────────────────────────
if [ "${ALLOW_KEY_REGEN}" = "true" ]; then
  echo "════════════════════════════════════════════════════════════════"
  echo "  WARNING: ALLOW_KEY_REGEN=true — key guard OVERRIDDEN"
  echo ""
  echo "  If the key file is missing, a new one will be generated."
  echo "  ALL existing EVARs will be INVALIDATED."
  echo "  ALL agents must be re-provisioned."
  echo ""
  echo "  Remove ALLOW_KEY_REGEN after this boot to re-enable the guard."
  echo "════════════════════════════════════════════════════════════════"
  rm -f "$MARKER_FILE"
fi

# ── Startup guard (with flock to prevent race conditions) ─────────────────
(
  flock -n 9 || {
    echo "[GUARD] Another instance is starting — waiting..."
    flock 9
  }

  if [ -f "$MARKER_FILE" ]; then
    # ── Not first boot: key MUST exist ──────────────────────────────────
    if [ ! -f "$KEY_PATH" ]; then
      echo "════════════════════════════════════════════════════════════════"
      echo "  FATAL: Ed25519 key file missing at ${KEY_PATH}"
      echo ""
      echo "  This gateway has booted before (marker: ${MARKER_FILE})."
      echo "  The key file has been lost — likely a removed volume."
      echo "  Starting with a new key would INVALIDATE ALL ACTIVE EVARs."
      echo ""
      echo "  To recover:"
      echo "    1. Restore the key from backup:"
      echo "       cp /backups/sentry_ed25519.key ${KEY_PATH}"
      echo ""
      echo "    2. Or intentionally reset (burns all agent sessions):"
      echo "       Set ALLOW_KEY_REGEN=true and restart."
      echo "════════════════════════════════════════════════════════════════"
      exit 1
    fi

    # ── Key exists: validate it's not corrupt (non-empty, correct size) ──
    KEY_SIZE=$(wc -c < "$KEY_PATH" 2>/dev/null || echo 0)
    if [ "$KEY_SIZE" -lt 64 ]; then
      echo "════════════════════════════════════════════════════════════════"
      echo "  FATAL: Ed25519 key file at ${KEY_PATH} appears corrupt"
      echo "  (size: ${KEY_SIZE} bytes — expected >= 64 for PEM-encoded seed)"
      echo ""
      echo "  Restore from backup or set ALLOW_KEY_REGEN=true to regenerate."
      echo "════════════════════════════════════════════════════════════════"
      exit 1
    fi
  fi

  # First boot (no marker) — the Go binary will generate the key.
  # Marker is created AFTER successful startup below.

) 9>"$LOCK_FILE"

# ── Start the gateway binary ──────────────────────────────────────────────
# On successful startup, the Go binary creates/loads the key.
# We touch the marker after to confirm a complete boot.
exec sh -c "./cicada-sentry \"\$@\" & GW_PID=\$!; sleep 2 && touch ${MARKER_FILE} && wait \$GW_PID" -- "$@"
