#!/bin/bash
# =========================================================================
# Cicada Sentry Node - Enterprise Bare-Metal Installer
# Note: Must be executed as Root or via Sudo context.
# =========================================================================

# Step 1: Validate privileges
if [ "$EUID" -ne 0 ]
  then echo "Please run as root (or sudo)."
  exit
fi

echo "Deploying Cicada Sentry Gateway natively to Linux Host..."

# Step 2: Ensure secure service account (CISO Refinement)
# Creates a dedicated system user specifically designed around running cicada natively
echo "-> Creating dedicated non-root security user (cicada)..."
if id "cicada" &>/dev/null; then
    echo "   User 'cicada' already exists."
else
    useradd -r -s /bin/false cicada
fi

# Step 3: Scaffold absolute directories mapped to binary
echo "-> Configuring /opt/cicada structure..."
mkdir -p /opt/cicada/bin
mkdir -p /etc/cicada

# Step 4: Map binary payloads into systemic root definitions
echo "-> Transferring application binary and config templates..."
cp -f cicada-sentry /opt/cicada/bin/
chmod 755 /opt/cicada/bin/cicada-sentry

if [ ! -f /etc/cicada/config.yaml ]; then
    cp -f config.yaml /etc/cicada/
fi

# Transfer explicit ownership of the directories to the non-root daemon strictly
chown -R cicada:cicada /opt/cicada
chown -R cicada:cicada /etc/cicada

# Step 5: Construct the SystemD Auto-Restart configuration
echo "-> Generating strict systemd Daemon configuration..."
cat << EOF > /etc/systemd/system/cicada-sentry.service
[Unit]
Description=Cicada Sentry Null-Latency Reverse Proxy Server
After=network.target

[Service]
Type=simple
User=cicada
Group=cicada
WorkingDirectory=/opt/cicada
ExecStart=/opt/cicada/bin/cicada-sentry -config /etc/cicada/config.yaml
Restart=on-failure
RestartSec=5
# Security hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# Step 6: SystemD Integration Enable
echo "-> Reloading systemctl configurations..."
systemctl daemon-reload
systemctl enable cicada-sentry
systemctl start cicada-sentry

echo "====================================================================="
echo "    CICADA DEPLOYMENT COMPLETE "
echo "====================================================================="
echo "The Network node is now online and listening under the 'cicada' user."
echo "Verify execution: systemctl status cicada-sentry"
echo "Check tail logs: journalctl -u cicada-sentry -f"
