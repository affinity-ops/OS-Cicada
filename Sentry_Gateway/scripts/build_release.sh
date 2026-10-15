#!/bin/bash
# Cicada Sentry Node - Go Native Release Pipeline

echo "=========================================================="
echo "    CICADA SENTRY DISTRIBUTION PIPELINE"
echo "=========================================================="

echo "[1/4] Preparing sterile release directory..."
mkdir -p ../release/payload

echo "[2/4] Executing Cross-Compilation for Linux (Bare-Metal) target..."
# CGO_ENABLED=0 guarantees a massively portable static binary not reliant on local dynamic C-libraries
# -ldflags="-s -w" strips the DWARF debugging symbols, radically decreasing file size for Edge deployment
if env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../release/payload/cicada-sentry ../cmd/sentry/main.go; then
    echo "[✔] Static binary compiled successfully."
else
    echo "[!] Compilation failed."
    exit 1
fi

echo "[3/4] Scaffolding configurations & systemic installer scripts..."
# Copy the config and installer into the payload staging ground
cp ../release/config.yaml ../release/payload/ 2>/dev/null || echo "[WARN] config.yaml not found in ../release/"
cp ../release/setup.sh ../release/payload/ 2>/dev/null || echo "[WARN] setup.sh not found in ../release/"

# Ensure the installer script is functionally executable prior to TAR
chmod +x ../release/payload/setup.sh

echo "[4/4] Generating Zero-Dependency Archive Tarball..."
cd ../release/payload || exit
tar -czvf ../cicada-sentry-release-v1.tar.gz *

echo "=========================================================="
echo "    RELEASE COMPLETE: cicada-sentry-release-v1.tar.gz"
echo "=========================================================="
echo "Hand this package directly to CISO SysAdmins for raw network integration."
