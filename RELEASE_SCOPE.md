# Cicada Open-Source Release Scope: Implemented vs. Designed Matrix

This document provides an engineering breakdown of what is **implemented and tested in code** in this repository versus what is **deployment-supplied or architectural design** from the June 2026 Matthews Enforcement Framework (MEF) specification.

---

## 1. Reconciliation: 15-Stage Gateway Lifecycle vs. 9-Layer Admission Pipeline

The documentation and codebase refer to two complementary numbers that operate at different scopes:

1. **The 15-Stage Gateway Lifecycle (`Sentry_Gateway/cmd/sentry/main.go`):**
   Covers the complete end-to-end HTTP request/response lifecycle across the proxy data plane:
   - **Pre-Admission Perimeter (Stages 1 – 4):**
     1. Cryptographic Admission (Ed25519 EVAR / 15-minute JIT Session JWT + RFC 9449 DPoP proof + RFC 8693 ID-JAG human context)
     2. Certification & Data Residency Gate (`certified` / `pending_review` provisional mode / region pinning)
     3. Tier-1 SSRF & DNS-Rebinding Guard (`internal/ssrf`, HTTPS enforcement, RFC 1918 & `169.254.169.254` IMDSv2 block)
     4. ASI07 Inter-Agent Cryptographic Hop Chain (`internal/chain`) & Skill JSON Schema Contract (`internal/agentcache/schema_validator.go`)
     5. Lock-Free P2P Gossip Quarantine Check (`internal/gossip`, `sync/atomic.Pointer` `O(1)` lookup)
     6. Ghost Mode Deception Router (`internal/ghostmode`, diverts flagged agents to `Shadow_Sandbox`)
     7. Multi-Encoding Canary Honeytoken Trap (`internal/canary`, raw/Base64/Hex/URL/SHA-256 `CICADA_CANARY_*` detection + instant mesh quarantine)
     8. Fine-Grained Resource Policy (`internal/fga`, URL glob & HTTP method allowlist)
   - **Unified 9-Layer Deterministic Admission Pipeline (`internal/pipeline/pipeline.go`):**
     9. **Layer 1 (`injection_scan`):** 7-stage recursive deobfuscation (`NFKC`, URL, HTML entities, Hex/Unicode, Base64) + 36 regex patterns + hidden CSS/HTML DOM scanner (`internal/injection`)
     10. **Layer 2 (`semantic_intent`):** Deterministic lexical taxonomy & read-vs-mutation verb contradiction engine (`internal/semantic`)
     11. **Layer 3 (`velocity`):** Redis sliding-window & impact-weighted circuit breaker (`internal/velocity`)
     12. **Layer 4 (`drift_guard`):** Non-self-poisoning sliding-window cosine similarity context shift detector (`internal/drift`)
     13. **Layer 5 (`prerequisite`):** Fail-closed Forward-Saga prerequisite verification (`internal/prerequisite`)
     14. **Layer 6 (`tool_scope`):** Server-side tool manifest & parameter constraint enforcement (`internal/toolscope`, `internal/agentcache`)
     15. **Layer 7 (`blast_radius`):** Destructive SQL (`WHERE 1=1`, `DROP`, `TRUNCATE`), bulk record cap estimator (`internal/blastradius`), and destructive-action classification (`internal/hitl.ClassifyDestructiveAction` — including non-DELETE verbs such as `lifecycle_policy`, `suspend_backup`, `delete_snapshot`)
     16. **Layer 8 (`tx_profile`):** Multivariate Z-score financial anomaly profiler & deontic rule evaluator (`internal/txprofile`)
     17. **Layer 9 (`camel_taint`):** CaMeL-style session taint tracking & Rule-of-Two capability revocation (`internal/taint`)
   - **Post-Admission Execution & Egress/Ingress Auditing:**
     - In-Memory OPA Rego evaluation (`internal/policy`), Tiered HITL & length-prefixed SHA-256 CIBA biometric sign-off (`internal/hitl`, `internal/ciba`), EAKF code sandbox interception (`internal/plugin`, `cmd/eakfd`), Vault-aware & Shannon entropy outbound DLP (`internal/output`), ASI08 cascade detection (`internal/cascade`), BYOK KMS key injection (`internal/auth`), inbound response / reasoning trace scanning (`internal/llmproxy`), and SHA-256 hash-chained SQLite Edge Ledger persistence (`internal/ledger`).

---

## 2. Handler Enforcement Parity Matrix

Four request handlers run the 9-layer pipeline. `handleGhostProxy` is a deception sink for agents already flagged and does not re-run admission. The production MCP control plane (`POST /v1/mcp`, `internal/mcpserver`) is an operator interface rather than agent traffic: it requires `CICADA_AEGIS_TOKEN`, and its release/rollback/activate-policy tools need server-side human approval (`CICADA_OPERATOR_APPROVAL_TOKEN`).

| Handler | Endpoint | Auth & Quarantine | SSRF & Canary Trap | Server-Side Tool Manifest (`ResolveToolForRequest`) | 9-Layer `pipeline.Evaluate` | Taint Tracking (`internal/taint`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`handleAgentRequest`** | `POST /v1/agent/proxy` | EVAR / Session + DPoP + Gossip | Enforced | Enforced (Fail-closed) | All 9 layers + OPA + CIBA + EAKF + DLP | Selective `GET` taint (untrusted/external only) + provenance |
| **`handleSimulatedRequest`** | `POST /v1/agent/proxy` (Sim mode) | Optional token + Gossip | Enforced | Enforced (Fail-closed) | All 9 layers + OPA + DLP | Selective `GET` taint (untrusted/external only) + provenance |
| **`handleMCPExecution`** | `POST /v1/aegis/mcp/execute` (legacy) | Loopback IP + Aegis Bearer token | Enforced via pipeline | Enforced (Fail-closed) | All 9 layers | Marks quarantined target tainted; records completed tool |
| **`handleLLMProxy`** | `POST /v1/llm/proxy` | EVAR / Session + Gossip | Enforced | Enforced (Fail-closed) | All 9 layers + per-message injection & SimHash memory isolation | Taints session on `role: "tool"` / `"function"`, untrusted provenance, or cross-agent contamination |
| **`handleGhostProxy`** | Internal diversion from `handleAgentRequest` | Invoked post-admission | Isolated honeypot | N/A (Deception sink) | Invoked after admission/ghost flag | Immediately marks agent session tainted (`ghost_sandbox:*`) and records SHA-256 payload hash |

---

## 3. Implemented vs. Designed Component Table

| Subsystem / Artifact | Status | Implemented in Repository | Deployment-Supplied or Architectural Design |
| :--- | :--- | :--- | :--- |
| **EAKF Daemon (`cmd/eakfd`)** | **Implemented (Subprocess + State Sieve)** | Go gRPC daemon over UNIX Domain Socket (`cmd/eakfd/main.go`), timeout & tmpfs isolation, sanitised environment, 3-pass Deterministic State Sieve (`internal/eakfd/scrub/scrub.go` scrubbing 11 secret types, RFC 1918/IMDS IPs, and `.tfstate` blocks), server-side manifest enforcement (`req.EAKFEnabled`), fail-closed `503` when unreachable, `network_mode: "none"` in Compose, and default-deny Kubernetes `NetworkPolicy` (`deploy/k8s/eakfd-networkpolicy.yaml`). | Kernel syscall isolation (`runtime: runsc` for **gVisor** or `runtimeClassName: kata` for **Kata Containers**) is supplied by the host container runtime. Direct `/dev/kvm` Firecracker microVM snapshot orchestration described in `docs/EPHEMERAL_AGENT_KERNEL_FIREWALL.md` §7.3 is a design specification, not built into `cmd/eakfd`. |
| **Network Lockdown Perimeter** | **Implemented (Manifests)** | `deploy/k8s/eakfd-networkpolicy.yaml` provides `eakfd-default-deny-all` (zero ingress/egress for `eakfd`) and `cicada-agent-egress-lockdown` (forcing `cicada.io/managed-agent: "true"` pods to route all traffic exclusively through `sentry-gateway:8080`). | Operators must run a Kubernetes CNI plugin that enforces `NetworkPolicy` (Calico, Cilium, etc.) or host `iptables`/`nftables` egress rules so agents cannot dial upstream APIs directly. |
| **CIBA Cryptographic Binding** | **Implemented** | Length-prefixed `SHA-256` payload commitment (`internal/ciba/ciba.go`), constant-time hash verification on poll response, `Core_API` persistence (`CibaController.php`), Gateway mobile batch verification (`internal/mobile/handlers_lifecycle.go`), and Flutter `DecisionBloc` length-prefixed signing & `hold_payload_hash` echo (`Ciba_Flutter_App`). | Live Apple App Attest / Google Play Integrity hardware attestation verification requires production cloud credentials and `CICADA_ENFORCE_ATTESTATION=true`. |
| **Tiered HITL Single-Signal Policy** | **Implemented + Shadow Telemetry** | Compound signals (`>= 0.60`) escalate to Tier 2 human webhook immediately. Single-signal writes (`0.30 <= score < 0.60`) auto-approve by default to avoid payment keyword noise while recording `ShadowWouldEscalate=true` and atomic counters (`hitl.ShadowStats()`). Operators can enforce single-signal human review via `HITL_SINGLE_SIGNAL_MODE=enforce`. | Production threshold tuning should be performed after observing `[HITL-SHADOW]` log volume per tenant. |
| **k6 Load Test Corpus** | **Implemented (Scripts Included)** | Load test scripts included at `Sentry_Gateway/tests/load/proxy_load.js` and `tests/k6/sentry_gateway_load.js` along with the runner script `tests/k6/run_n5_load_test.sh`. | Historical raw JSON output dumps (`tests/k6/results/*.json`) from local Colima benchmark runs are summarised in `docs/Security_Audit_Test_Results.md` and omitted from git to keep repository size small. |
| **June 2026 Paper Differences** | **Documented** | Post-June architectural upgrades implemented in code: (1) Meta's **Agents Rule of Two** (`[ABC]` trifecta block at policy registration in `internal/policy/sanitizer.go` and runtime escalation in `internal/taint`), (2) **CaMeL-style session taint tracking** with selective `GET` domain trust (`internal/taint`), (3) **Server-side tool manifest resolution** (`ResolveToolForRequest` in `internal/agentcache`), and (4) **9-layer unified admission** (`internal/pipeline`) replacing the earlier 4-layer pipeline. | Earlier iterations in `docs/Security_Audit_Test_Results.md` (Iterations 1–30) reflect historical point-in-time snapshots prior to the 9-layer pipeline unification. |

---

## 4. Verification Record (`go test ./...` & `govulncheck ./...`)

### `go test -count=1 ./...` Output (`Sentry_Gateway`, uncached, 2026-11-07)

Run with `CICADA_SIMULATION_MODE=true CICADA_DEV_MODE=true go test -count=1 ./...`. Packages with no test files are omitted. Several suites start local `httptest` servers, so they need loopback networking; in a network-restricted sandbox they fail with `connect: operation not permitted`.

```text
ok  	github.com/asai/cicada/sentry/cmd/sentry	1.334s
ok  	github.com/asai/cicada/sentry/internal/agentcache	1.974s
ok  	github.com/asai/cicada/sentry/internal/auth	2.729s
ok  	github.com/asai/cicada/sentry/internal/blastradius	3.192s
ok  	github.com/asai/cicada/sentry/internal/caep	2.903s
ok  	github.com/asai/cicada/sentry/internal/canary	2.751s
ok  	github.com/asai/cicada/sentry/internal/cascade	4.624s
ok  	github.com/asai/cicada/sentry/internal/chain	2.438s
ok  	github.com/asai/cicada/sentry/internal/drift	2.383s
ok  	github.com/asai/cicada/sentry/internal/eakfd/scrub	2.884s
ok  	github.com/asai/cicada/sentry/internal/federation	2.655s
ok  	github.com/asai/cicada/sentry/internal/fga	2.623s
ok  	github.com/asai/cicada/sentry/internal/gossip	2.365s
ok  	github.com/asai/cicada/sentry/internal/hitl	2.832s
ok  	github.com/asai/cicada/sentry/internal/injection	2.916s
ok  	github.com/asai/cicada/sentry/internal/ledger	3.343s
ok  	github.com/asai/cicada/sentry/internal/license	2.695s
ok  	github.com/asai/cicada/sentry/internal/llmproxy	2.661s
ok  	github.com/asai/cicada/sentry/internal/mcpserver	2.195s
ok  	github.com/asai/cicada/sentry/internal/output	1.678s
ok  	github.com/asai/cicada/sentry/internal/pipeline	2.352s
ok  	github.com/asai/cicada/sentry/internal/plugin	2.742s
ok  	github.com/asai/cicada/sentry/internal/policy	2.864s
ok  	github.com/asai/cicada/sentry/internal/prerequisite	2.828s
ok  	github.com/asai/cicada/sentry/internal/rolemapping	2.595s
ok  	github.com/asai/cicada/sentry/internal/roles	2.147s
ok  	github.com/asai/cicada/sentry/internal/rotation	2.085s
ok  	github.com/asai/cicada/sentry/internal/saga	2.221s
ok  	github.com/asai/cicada/sentry/internal/scim	2.413s
ok  	github.com/asai/cicada/sentry/internal/secrets	2.514s
ok  	github.com/asai/cicada/sentry/internal/semantic	2.236s
ok  	github.com/asai/cicada/sentry/internal/session	2.069s
ok  	github.com/asai/cicada/sentry/internal/shadow	2.099s
ok  	github.com/asai/cicada/sentry/internal/slm	2.134s
ok  	github.com/asai/cicada/sentry/internal/slogger	2.014s
ok  	github.com/asai/cicada/sentry/internal/ssrf	2.109s
ok  	github.com/asai/cicada/sentry/internal/taint	2.152s
ok  	github.com/asai/cicada/sentry/internal/threatintel	1.968s
ok  	github.com/asai/cicada/sentry/internal/toolscope	2.177s
ok  	github.com/asai/cicada/sentry/internal/tracing	1.548s
ok  	github.com/asai/cicada/sentry/internal/txprofile	2.066s
ok  	github.com/asai/cicada/sentry/internal/velocity	1.940s
ok  	github.com/asai/cicada/sentry/pkg/pqc	1.978s
ok  	github.com/asai/cicada/sentry/tests/integration	1.555s
```

### `govulncheck ./...` Output (`Sentry_Gateway`)

```text
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
```


---

## 5. Production-Path Verification (2026-11-07)

First end-to-end run of the real request path (simulation off) against PostgreSQL 15, Redis and the Core API, with `CICADA_INTERNAL_KEY` set. `scripts/e2e_production.sh`: **19/19 checks passed**.

| Check | Result |
| :--- | :--- |
| Health: gateway's own Postgres pool, Redis, Core API | pass |
| Provisioned agent registers and receives an EVAR | pass (201) |
| Unknown agent refused | pass (404) |
| Agent requesting unprovisioned scopes refused | pass (403) |
| Registration without `X-Gateway-Secret` refused | pass (401) |
| EVAR exchanged for a JIT session token | pass (200) |
| Benign proxied request admitted | pass (200) |
| Prompt injection / SSRF to metadata / credential exfiltration | pass (403 each) |
| Request without credentials | pass (401) |
| Anonymous calls to 6 admin routes (federation, devices, rotate, shadow, test-push, sandbox report) | pass (401 each) |

Header spoofing (`X-Real-IP`) and gossip authentication cannot be tested from localhost; they are covered by `TestTrustedRealIP` and `TestAuthenticateBatch`.

## 6. Not Implemented / Known Limitations

| Item | Status |
| :--- | :--- |
| SSO federation (OIDC/SAML role mapping) | Routes exist and are now authenticated, but `federation_providers` / `role_mappings` tables are not created by `active_migrations/`, so the feature does not work on a fresh install. |
| License tier limits (`GetMaxAgents`, `MeshAllowed`, `GetMeshTier`) | Not enforced; only the license signature is verified. |
| Canary token issuing (`canary.Issue` / `Revoke`) | Not wired; detection of `CICADA_CANARY_*` works. |
| Firecracker microVM orchestration | Design only. |
| Full UI fleet and mobile approval round trip | Not tested end to end against this release. |
| Independent security review | Not performed. |

Run `scripts/verify_release.sh` to reproduce the build, test, vulnerability-scan and quickstart results.
