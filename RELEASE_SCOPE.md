# Cicada Open-Source Release Scope: Implemented vs. Designed Matrix

This document provides an engineering breakdown of what is **implemented and tested in code** in this repository versus what is **deployment-supplied or architectural design** from the June 2026 Matthews Enforcement Framework (MEF) specification.

---

## 1. Reconciliation: 15-Stage Gateway Lifecycle vs. 9-Layer Admission Pipeline

The documentation and codebase refer to two complementary numbers that operate at different scopes (matching Table 2 of [`docs/PATH_DEPENDENT_ARCHITECTURE_v3.md`](./docs/PATH_DEPENDENT_ARCHITECTURE_v3.md) stage-for-stage):

1. **The 15-Stage Gateway Lifecycle (`Sentry_Gateway/cmd/sentry/main.go`):**
   Covers the complete end-to-end HTTP request/response lifecycle across the proxy data plane:
   - **Pre-Admission Perimeter (Stages 1 – 4):**
     1. **Stage 1 (Cryptographic Identity, Certification & Residency Gate):** Ed25519 (`EdDSA`) EVAR / 5-minute JIT Session JWT + RFC 9449 DPoP proof + IETF draft ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`) via RFC 8693 Token Exchange + certification state (`certified` / `pending_review` provisional mode) + regional data residency pinning (`internal/auth`, `internal/session`).
     2. **Stage 2 (Tier-1 SSRF & DNS-Rebinding Guard):** HTTPS enforcement, RFC 1918, loopback, CGNAT, IPv6 ULA, and `169.254.169.254` IMDSv2 block (`internal/ssrf`), paired with connection-time IP pinning in `proxyTransport.DialContext` (`cmd/sentry/main.go`).
     3. **Stage 3 (ASI07 Inter-Agent Hop Chain & Skill JSON Schema Contract):** Ed25519-signed `X-Cicada-Agent-Chain` delegation verification (`internal/chain`) & declared skill JSON Schema validation (`internal/agentcache/schema_validator.go`).
     4. **Stage 4 (Gossip Quarantine, Ghost Mode, Canary Trap & FGA Policy):** Lock-free P2P gossip quarantine check (`internal/gossip`, `sync/atomic.Pointer` `O(1)` lookup), Ghost Mode deception diversion (`internal/ghostmode`), multi-encoding Canary honeytoken trap (`internal/canary`, raw/Base64/Hex/URL/SHA-256 `CICADA_CANARY_*`), and Fine-Grained Resource Policy (`internal/fga`, URL glob & HTTP method allowlist).
   - **Unified 9-Layer Deterministic Admission Pipeline (`internal/pipeline/pipeline.go`, Stages 5 – 13):**
     5. **Stage 5 — Pipeline Layer 1 (`injection_scan`):** Bounded 7-stage deobfuscation (`NFKC`, zero-width strip, homoglyphs, URL, HTML named/numeric entities, Hex/Unicode, Base64, capped at `MaxDeobfuscationInputBytes = 64 KB`) + 36 regex patterns + hidden CSS/HTML DOM scanner (`internal/injection`) + optional SLM sidecar (`internal/slm`).
     6. **Stage 6 — Pipeline Layer 2 (`semantic_intent`):** Embedding cosine similarity (`0.35` default threshold) or deterministic lexical taxonomy & Jaccard fallback (`0.10` default threshold) + read-vs-mutation verb contradiction engine (`internal/semantic`).
     7. **Stage 7 — Pipeline Layer 3 (`velocity`):** Redis sliding-window & impact-weighted $3.0\sigma$ z-score circuit breaker (`internal/velocity`).
     8. **Stage 8 — Pipeline Layer 4 (`drift_guard`):** Non-self-poisoning sliding-window cosine similarity context shift detector (`internal/drift`).
     9. **Stage 9 — Pipeline Layer 5 (`prerequisite`):** Fail-closed Forward-Saga prerequisite verification recorded only after upstream `2xx`/`3xx` completion (`internal/prerequisite`).
     10. **Stage 10 — Pipeline Layer 6 (`tool_scope`):** Server-side tool manifest & parameter constraint enforcement (`internal/toolscope`, `internal/agentcache`).
     11. **Stage 11 — Pipeline Layer 7 (`blast_radius`):** Destructive SQL (`WHERE 1=1`, `DROP`, `TRUNCATE`), bulk record cap estimator (`internal/blastradius`), and 33-pattern destructive-action classifier (`internal/hitl.ClassifyDestructiveAction`, including non-`DELETE` lifecycle/backup/snapshot mutations).
     12. **Stage 12 — Pipeline Layer 8 (`tx_profile`):** Multivariate Z-score financial anomaly profiler & deontic rule evaluator (`internal/txprofile`).
     13. **Stage 13 — Pipeline Layer 9 (`camel_taint`):** CaMeL-style session taint tracking & Meta Rule-of-Two capability revocation (`internal/taint`).
   - **Post-Admission Execution & Egress/Ingress Auditing (Stages 14 – 15):**
     14. **Stage 14 (OPA Rego, CIBA Payload-Bound Approval & EAKF Sandbox):** In-memory OPA Rego evaluation (`internal/policy`), Tiered HITL & decimal-length-prefixed SHA-256 CIBA biometric sign-off (`internal/hitl`, `internal/ciba`), EAKF code sandbox interception (`internal/plugin`, `cmd/eakfd`), and BYOK KMS key injection (`internal/auth`).
     15. **Stage 15 (Outbound DLP, ASI08 Cascade, Response Tainting & Hash-Chained Ledger):** Vault-aware & Shannon entropy outbound DLP (`internal/output`), ASI08 cascade detection (`internal/cascade`), untrusted external response tainting (`internal/taint`), inbound LLM response / reasoning trace scanning (`internal/llmproxy`), and SHA-256 hash-chained SQLite Edge Ledger persistence (`internal/ledger`).

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
| **Tool Manifest Resolution (`internal/agentcache`)** | **Implemented (Opt-In Default + Strict Mode)** | Agents with zero rows in `agent_tools` skip Layers 5 (`prerequisite`) and 6 (`tool_scope`) by default so general-purpose proxy agents governed by coarse RBAC (`proxy:read`/`proxy:write`) and FGA globs work without a tool manifest. Setting `CICADA_REQUIRE_TOOL_MANIFEST=true` (or `Request.RequireToolManifest=true`) forces fail-closed Layer 6 denial even for agents with zero registered tools. Once an agent registers any tool, `ResolveToolForRequest` evaluates explicit `URLPattern` globs first (falling back to canonical URL path-segment scoring when `URLPattern` is omitted) and fails closed (`tool_scope` deny) on any unmapped request. | Operators wishing to lock all agents strictly to declared endpoints should register tools with `URLPattern` entries in `agent_tools` and set `CICADA_REQUIRE_TOOL_MANIFEST=true`. |
| **CaMeL Taint Scope & TTL (`internal/taint`)** | **Implemented (`agent_id` or `agent_id:session_id`, 15m TTL)** | Taint state is bound to `agent_id` by default, or isolated to `agent_id:session_id` (`taint.ScopeKey`) when `X-Cicada-Session-ID` is supplied so concurrent conversations sharing one `agent_id` do not cross-taint each other (while still honouring agent-wide quarantine taint). Stored in Redis (`cicada:taint:{key}`, with in-memory `sync.Map` fallback) with a 15-minute sliding TTL (`DefaultTTL = 15 * time.Minute`, matching the 15-minute JIT session token lifetime) or cleared via `taint.ClearTaint`. | Callers running multi-user threads under a single `agent_id` should pass `X-Cicada-Session-ID` per conversation thread. |
| **Adversarial Benchmark Corpus (`tests/adversarial`)** | **Implemented (22 Cases in CI)** | Reproducible adversarial corpus (`Sentry_Gateway/tests/adversarial/corpus.json` and `adversarial_corpus_test.go`) testing multi-encoded prompt injections (`NFKC`, Base64, URL, HTML numeric entities, CSS hidden DOM), SSRF/IMDSv2 bypasses, Layer 7 destructive SQL/shell/cloud/non-DELETE actions, CaMeL taint escalation, canary exfiltration, and benign false-positive controls. | Executed automatically on every push/PR via `.github/workflows/verify.yml`. |
| **k6 Load Test Corpus** | **Implemented (Scripts Included)** | Load test scripts included at `Sentry_Gateway/tests/load/proxy_load.js` and `tests/k6/sentry_gateway_load.js` along with the runner script `tests/k6/run_n5_load_test.sh`. | Historical raw JSON output dumps (`tests/k6/results/*.json`) from local Colima benchmark runs are summarised in `docs/PATH_DEPENDENT_ARCHITECTURE_v3.md` Section 6 and omitted from git to keep repository size small. |
| **June 2026 Paper Differences** | **Documented** | Post-June architectural upgrades implemented in code: (1) Meta's **Agents Rule of Two** (`[ABC]` trifecta block at policy registration in `internal/policy/sanitizer.go` and runtime escalation in `internal/taint`), (2) **CaMeL-style session taint tracking** with selective `GET` domain trust (`internal/taint`), (3) **Server-side tool manifest resolution** (`ResolveToolForRequest` in `internal/agentcache`), and (4) **9-layer unified admission** (`internal/pipeline`) replacing the earlier 4-layer pipeline. | Documented in `docs/PATH_DEPENDENT_ARCHITECTURE_v3.md` Table 1 (Audit Changelog from June 2026 v2 to November 2026 v1.0.3). |

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

End-to-end run of the real request path (simulation off) against PostgreSQL 15, Redis 7, and the Core API, with `CICADA_INTERNAL_KEY` (`GATEWAY_SECRET`) set. `scripts/e2e_production.sh`: **23/23 checks passed** (13 core admission/session/proxy checks + 10 `GATEWAY_SECRET`-gated admin and canary issue/revoke checks). To reproduce the full repository test count (**1,299** top-level test definitions across 104 test files in Go, PHP, Python, TS/JS, and Dart), run `bash scripts/count_tests.sh`.

| Check | Result |
| :--- | :--- |
| Health: gateway HTTP 200 + Postgres pool connected (2 checks) | pass |
| Provisioned agent registers (201) and receives an EVAR (2 checks) | pass |
| Unknown agent refused (1 check) | pass (404) |
| Agent requesting unprovisioned scopes refused (1 check) | pass (403) |
| EVAR exchanged for a JIT session token (2 checks) | pass (200) |
| Benign proxied request admitted (1 check) | pass (200) |
| Prompt injection / SSRF to metadata / credential exfiltration blocked (3 checks) | pass (403 each) |
| Request without credentials refused (1 check) | pass (401) |
| Anonymous calls to 7 admin routes (`federation`, `devices`, `rotate`, `shadow`, `test-push`, `sandbox/report`, `admin/canary/issue`) (7 checks) | pass (401 each) |
| Authenticated canary honeytoken issue (201 + token non-empty) and revoke (200) (3 checks) | pass |

Header spoofing (`X-Real-IP`) and gossip authentication cannot be tested from localhost; they are covered by `TestTrustedRealIP` and `TestAuthenticateBatch`.

## 6. Not Implemented / Known Limitations

| Item | Status |
| :--- | :--- |
| SSO federation (OIDC/SAML role mapping) | **Resolved in v1.0.2:** `federation_providers`, `federated_sessions`, `federation_audit_log`, and `role_mappings` tables are now created automatically by `active_migrations/001_isolated_schema.sql` on fresh installs. |
| License tier limits (`GetMaxAgents`, `MeshAllowed`, `GetMeshTier`) | **Resolved in v1.0.2:** `GetMaxAgents()` is enforced during agent registration (`registration_authz.go`) and `MeshAllowed()` is enforced on `/v1/gossip/receive` when a license is active. |
| Canary token issuing (`canary.Issue` / `Revoke`) | **Resolved in v1.0.2:** Wired to authenticated operator endpoints `POST /v1/admin/canary/issue` and `POST /v1/admin/canary/revoke` with both Redis persistence and standalone in-memory fallback. |
| Firecracker microVM orchestration | Design only (host container runtime supplies `gVisor`/`Kata` syscall isolation). |
| Full UI fleet and mobile approval round trip | Not tested end to end against this release. |
| Independent security review | Not performed. |

Run `scripts/verify_release.sh` to reproduce the build, test, vulnerability-scan and quickstart results.
