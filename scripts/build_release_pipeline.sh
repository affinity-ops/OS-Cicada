#!/bin/bash
# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Automates the building and PQC cryptographic signing of Cicada platform binaries.

set -e

# Configuration
VERSION="v1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$ROOT_DIR/dist"
LICENSING_DIR="$ROOT_DIR/Licensing_Authority"
SENTRY_DIR="$ROOT_DIR/Sentry_Gateway"

echo "=========================================================="
echo " Cicada Automated Binary Release Pipeline (PQC Secured)"
echo "=========================================================="
echo "Version: $VERSION"
echo "Output Directory: $DIST_DIR"

# Ensure clean state
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# 1. Build the Signing Tool
echo ""
echo "[*] Compiling PQC Binary Signer..."
cd "$LICENSING_DIR"
go build -o "$DIST_DIR/sign_binary" ./cmd/sign_binary
SIGNER_BIN="$DIST_DIR/sign_binary"

if [ ! -f "$SIGNER_BIN" ]; then
    echo "FAILED: Could not compile signing tool."
    exit 1
fi

# 2. Build and Sign Sentry Gateway
echo ""
echo "[*] Building Sentry Gateway (Linux amd64)..."
cd "$SENTRY_DIR"
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/sentry-linux-amd64" ./cmd/sentry
echo "[+] Sentry Gateway built successfully."

echo "[*] Signing Sentry Gateway (PQC Hybrid Signature)..."
cd "$LICENSING_DIR"
"$SIGNER_BIN" --binary "$DIST_DIR/sentry-linux-amd64" --version "$VERSION" --keys "master_keys.json" --output "$DIST_DIR"

# 3. Build and Sign EAKF Daemon
echo ""
echo "[*] Building EAKF Daemon (Linux amd64)..."
cd "$SENTRY_DIR"
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/eakfd-linux-amd64" ./cmd/eakfd
echo "[+] EAKF Daemon built successfully."

echo "[*] Signing EAKF Daemon (PQC Hybrid Signature)..."
cd "$LICENSING_DIR"
"$SIGNER_BIN" --binary "$DIST_DIR/eakfd-linux-amd64" --version "$VERSION" --keys "master_keys.json" --output "$DIST_DIR"

echo ""
echo "=========================================================="
echo " Pipeline Complete."
echo " Artifacts and cryptographic manifests are in: $DIST_DIR/"
ls -la "$DIST_DIR/"
