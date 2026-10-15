# Licensing Authority Roadmap & Verification Ledger

This document serves as the authoritative map of the Licensing Authority's capabilities. 
Status is strictly mapped to the codebase: **VERIFIED COMPLETE** or **GAP / PENDING**.

---

## 1. Core Cryptographic Engine (Status: GAP / PENDING)
*Objective: Generate and verify secure, time-bound cryptographic licenses.*
- **Master Key Generation:** **VERIFIED COMPLETE.** Ed25519 and ML-DSA-65 keys are generated via `internal/crypto/keys.go` using the shared PQC library and securely persisted.
- **License Minting (`.lic`):** **VERIFIED COMPLETE.** `internal/crypto/mint.go` constructs a JSON payload with `TenantID` and `MaxAgents`, generating a PQC hybrid dual-signature.
- **Revocation List (CRL):** **MISSING.** Need to maintain a ledger of revoked licenses.

## 2. Operator CLI / API (Status: IN PROGRESS)
*Objective: Allow Cicada administrators to securely mint licenses.*
- **CLI Tool:** **VERIFIED COMPLETE.** `cmd/mint/main.go` provides a command-line interface for offline generation (`go run cmd/mint/main.go --tenant=tenant_prod_001 --agents=50`).
- **Internal API:** **MISSING.** Need a secure, local-only HTTP API for potential future integration with an internal admin dashboard.

## 3. Sentry Gateway Integration (Status: VERIFIED COMPLETE)
*Objective: Ensure the Sentry Gateway binary strictly enforces the license.*
- **Boot Validation:** **VERIFIED COMPLETE.** `internal/license/enforcer.go` strictly verifies the Ed25519 and ML-DSA-65 signatures against hardcoded public keys. `cmd/sentry/main.go` halts fatally if the `--license` flag is missing or invalid.
- **Telemetry Bridge:** **VERIFIED COMPLETE.** The Gateway's `heartbeat.Worker` securely extracts `TenantID`, `Tier`, and `MaxAgents` from the verified PQC Hybrid license and automatically injects them into the `/v1/gateway/heartbeat` payload. The Core API reads this to instantly map self-hosted enterprise gateways to their billing tenant.

---
*End of Ledger.*
