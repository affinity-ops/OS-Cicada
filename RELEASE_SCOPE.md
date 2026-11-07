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
     4. ASI07 Inter-Agent Cryptographic Hop Chain (`internal/chain`) & Skill JSON Schema Contract (`internal/skill`)
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
     15. **Layer 7 (`blast_radius`):** Destructive SQL (`WHERE 1=1`, `DROP`, `TRUNCATE`) & bulk record cap estimator (`internal/blastradius`)
     16. **Layer 8 (`tx_profile`):** Multivariate Z-score financial anomaly profiler & deontic rule evaluator (`internal/txprofile`)
     17. **Layer 9 (`camel_taint`):** CaMeL-style session taint tracking & Rule-of-Two capability revocation (`internal/taint`)
   - **Post-Admission Execution & Egress/Ingress Auditing:**
     - In-Memory OPA Rego evaluation (`internal/policy`), Tiered HITL & length-prefixed SHA-256 CIBA biometric sign-off (`internal/hitl`, `internal/ciba`), EAKF code sandbox interception (`internal/plugin`, `cmd/eakfd`), Vault-aware & Shannon entropy outbound DLP (`internal/output`), ASI08 cascade detection (`internal/cascade`), BYOK KMS key injection (`internal/auth`), inbound response / reasoning trace scanning (`internal/llmproxy`), and SHA-256 hash-chained SQLite Edge Ledger persistence (`internal/ledger`).

---

## 2. Handler Enforcement Parity Matrix

All five agent-facing handlers in `Sentry_Gateway/cmd/sentry/main.go` are wired to the deterministic security controls:

| Handler | Endpoint | Auth & Quarantine | SSRF & Canary Trap | Server-Side Tool Manifest (`ResolveToolForRequest`) | 9-Layer `pipeline.Evaluate` | Taint Tracking (`internal/taint`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`handleAgentRequest`** | `POST /v1/agent/proxy` | EVAR / Session + DPoP + Gossip | Enforced | Enforced (Fail-closed) | All 9 layers + OPA + CIBA + EAKF + DLP | Selective `GET` taint (untrusted/external only) + provenance |
| **`handleSimulatedRequest`** | `POST /v1/agent/proxy` (Sim mode) | Optional token + Gossip | Enforced | Enforced (Fail-closed) | All 9 layers + OPA + DLP | Selective `GET` taint (untrusted/external only) + provenance |
| **`handleMCPExecution`** | `POST /v1/mcp/execute` | Loopback IP + Aegis Bearer token | Enforced via pipeline | Enforced (Fail-closed) | All 9 layers | Marks quarantined target tainted; records completed tool |
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

### `go test ./...` Output (`Sentry_Gateway`)

```text
?   	github.com/asai/cicada/sentry/cmd/eakfd	[no test files]
?   	github.com/asai/cicada/sentry/cmd/mint_test_evar	[no test files]
ok  	github.com/asai/cicada/sentry/cmd/sentry	1.363s
?   	github.com/asai/cicada/sentry/cmd/sidecar	[no test files]
?   	github.com/asai/cicada/sentry/cmd/sim_handshake	[no test files]
ok  	github.com/asai/cicada/sentry/internal/agentcache	0.412s
ok  	github.com/asai/cicada/sentry/internal/auth	2.416s
?   	github.com/asai/cicada/sentry/internal/billing	[no test files]
ok  	github.com/asai/cicada/sentry/internal/blastradius	0.388s
ok  	github.com/asai/cicada/sentry/internal/caep	0.395s
ok  	github.com/asai/cicada/sentry/internal/canary	0.421s
ok  	github.com/asai/cicada/sentry/internal/cascade	0.402s
ok  	github.com/asai/cicada/sentry/internal/chain	0.419s
?   	github.com/asai/cicada/sentry/internal/ciba	[no test files]
ok  	github.com/asai/cicada/sentry/internal/drift	0.440s
ok  	github.com/asai/cicada/sentry/internal/eakfd/scrub	0.415s
?   	github.com/asai/cicada/sentry/internal/fcm	[no test files]
ok  	github.com/asai/cicada/sentry/internal/federation	0.901s
ok  	github.com/asai/cicada/sentry/internal/fga	0.390s
?   	github.com/asai/cicada/sentry/internal/ghostmode	[no test files]
ok  	github.com/asai/cicada/sentry/internal/gossip	0.451s
?   	github.com/asai/cicada/sentry/internal/heartbeat	[no test files]
ok  	github.com/asai/cicada/sentry/internal/hitl	5.255s
ok  	github.com/asai/cicada/sentry/internal/injection	0.489s
ok  	github.com/asai/cicada/sentry/internal/ledger	0.612s
ok  	github.com/asai/cicada/sentry/internal/license	0.405s
ok  	github.com/asai/cicada/sentry/internal/llmproxy	0.431s
ok  	github.com/asai/cicada/sentry/internal/mcpserver	0.448s
?   	github.com/asai/cicada/sentry/internal/memory	[no test files]
?   	github.com/asai/cicada/sentry/internal/mobile	[no test files]
ok  	github.com/asai/cicada/sentry/internal/output	5.501s
ok  	github.com/asai/cicada/sentry/internal/pipeline	1.999s
ok  	github.com/asai/cicada/sentry/internal/plugin	2.932s
ok  	github.com/asai/cicada/sentry/internal/policy	0.824s
?   	github.com/asai/cicada/sentry/internal/policystore	[no test files]
ok  	github.com/asai/cicada/sentry/internal/prerequisite	0.408s
?   	github.com/asai/cicada/sentry/internal/queue	[no test files]
ok  	github.com/asai/cicada/sentry/internal/rolemapping	0.392s
ok  	github.com/asai/cicada/sentry/internal/roles	0.387s
ok  	github.com/asai/cicada/sentry/internal/rotation	0.401s
ok  	github.com/asai/cicada/sentry/internal/saga	5.407s
ok  	github.com/asai/cicada/sentry/internal/scim	0.419s
ok  	github.com/asai/cicada/sentry/internal/secrets	0.460s
ok  	github.com/asai/cicada/sentry/internal/semantic	0.472s
ok  	github.com/asai/cicada/sentry/internal/session	0.415s
ok  	github.com/asai/cicada/sentry/internal/shadow	0.488s
ok  	github.com/asai/cicada/sentry/internal/slm	4.402s
ok  	github.com/asai/cicada/sentry/internal/slogger	0.410s
ok  	github.com/asai/cicada/sentry/internal/ssrf	5.535s
?   	github.com/asai/cicada/sentry/internal/store	[no test files]
ok  	github.com/asai/cicada/sentry/internal/taint	0.436s
ok  	github.com/asai/cicada/sentry/internal/threatintel	0.412s
ok  	github.com/asai/cicada/sentry/internal/toolscope	0.409s
ok  	github.com/asai/cicada/sentry/internal/tracing	3.951s
ok  	github.com/asai/cicada/sentry/internal/txprofile	0.445s
ok  	github.com/asai/cicada/sentry/internal/velocity	0.450s
?   	github.com/asai/cicada/sentry/pkg/eakf/v1	[no test files]
ok  	github.com/asai/cicada/sentry/pkg/pqc	0.512s
ok  	github.com/asai/cicada/sentry/tests/integration	5.204s
```

### `govulncheck ./...` Output (`Sentry_Gateway`)

```text
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
```

