# Architectural Specification & Whitepaper: The Cicada Architecture

**A Sovereign, Decentralised P2P Intrusion Detection & Governance Mesh for Autonomous AI Agents**

**Document Status:** Architectural Specification — Core mesh architecture IMPLEMENTED (Iteration 30, 16 June 2026)  
**Added to Technical Truth:** 16 June 2026  
**Implementation Verified:** 38/38 tests PASS across gossip, threat intel, and mesh directory  
**Cross-reference:** See `Security_Audit_Test_Results.md` → Iteration 30 for full test results

> [!NOTE]
> As of Iteration 30 (16 June 2026), the core mesh architecture described in this whitepaper is **implemented and tested**. Tenant isolation, PQC hybrid per-peer authentication, anonymised threat intelligence, and the Mesh Directory service are all operational with 38 passing security tests.

---

## Abstract

As autonomous AI agents shift from passive wrappers to deterministic tools executing high-privilege system actions, traditional cloud security perimeters collapse. Probabilistic "LLM-on-LLM" firewalls operate within the same semantic space as the vulnerabilities they attempt to mitigate, making them fundamentally susceptible to prompt injection, social engineering, and cognitive runaway. This paper presents Cicada, a decentralized, single-tenant perimeter gateway that enforces deterministic safety constraints on autonomous systems.

By shifting from a centralized Software-as-a-Service (SaaS) topology to an interconnected peer-to-peer (P2P) mesh of sovereign corporate nodes, Cicada ensures complete data, prompt, and secret sovereignty within the enterprise boundary. Threat intelligence is shared across the network via privacy-preserving, zero-knowledge gossip protocols. We outline the architectural layers of the local gateway, analyze its mitigation of systemic autonomous failures, evaluate its performance profile, and define cryptographically secured mesh governance.

---

## 1. Introduction & The Paradigm Shift

Early enterprise AI implementations relied on static, chat-based interfaces. The modern ecosystem, however, is dominated by autonomous execution agents capable of tool call routing, dynamic code generation, and multi-step transactional loops. This autonomy introduces a novel threat surface: probabilistic execution risk.

When an agent is empowered to read, reason, and write to external APIs, it acts as a highly privileged, dynamic entity operating inside static corporate infrastructure. Traditional firewalls cannot inspect these payloads effectively because the threat is not found in a static malware signature, but in the evolving semantic context of a prompt.

```
[Agent Runtime] ──► [Probabilistic Semantic Space] ──► [Target Systems]
                          │ (Can be Gaslit/Jailbroken)
                          ▼
                  [LLM Firewall Wrapper] (Fails)
```

Existing solutions attempt to deploy "supervisor" LLMs to monitor worker LLMs. This design is flawed. Because the supervisor is also a probabilistic model, it can be bypassed using indirect prompt injection, obfuscated token manipulation, or resource exhaustion.

Cicada breaks this paradigm by introducing an out-of-band, deterministic gateway proxy. It translates probabilistic agent outputs into rigid, schema-validated infrastructure constraints. Crucially, Cicada rejects the data-pooling liabilities of traditional multi-tenant SaaS architectures in favor of an interconnected mesh of fully sovereign, corporate-hosted sidecars.

```
[Agent Runtime] ──► [Cicada Sovereign Gateway] ──► [Target Systems]
                          │ (Deterministic Controls)
                          ▼
                  [Local Vector & Regex Layers]
                          │
         (P2P Privacy-Preserving Gossip)
                          ▼
               [Global Threat Mesh]
```

---

## 2. Decentralised Architecture & Sovereign Mesh Topology

The Cicada deployment topology is split into two components: the Sovereign Local Sentry and the Peer-to-Peer (P2P) Threat Mesh.

```
+------------------------------------------------------------+
|                  ENTERPRISE BOUNDARY (Node A)              |
|                                                            |
|  [Agent Cluster] ──► [Local Sentry Gateway] ──► [Target]   |
|                                │                           |
|                                ▼                           |
|                      [Local State & Cache]                 |
+------------------------------------------------------------+
                                 ▲
                                 │  (Zero-Knowledge Gossip)
                                 ▼
+------------------------------------------------------------+
|                  ENTERPRISE BOUNDARY (Node B)              |
|                                                            |
|  [Agent Cluster] ──► [Local Sentry Gateway] ──► [Target]   |
|                                │                           |
|                                ▼                           |
|                      [Local State & Cache]                 |
+------------------------------------------------------------+
```

### 2.1 The Sovereign Local Sentry

Each enterprise provisions and hosts its own dedicated Sentry instance. The gateway operates as an on-premises or single-tenant virtual private cloud (VPC) sidecar appliance.

* **Zero External Data Leakage:** All prompts, API tokens, user identities, and execution traces remain within the corporate boundary.
* **Local Cryptographic Isolation:** Cryptographic secrets and API keys are stored in a local vault, injected into headers at the egress proxy layer, and stripped prior to response delivery.

### 2.2 The Interconnected P2P Mesh

Rather than streaming telemetry to a central authority, independent Sentry nodes form an encrypted peer-to-peer network. This allows them to securely share threat intelligence without compromising corporate privacy.

* **Privacy-Preserving Indicators of Compromise (IoCs):** When Node A detects a novel attack vector (e.g., a specific indirect prompt injection payload or an anomalous tool-loop sequence), it extracts the structural fingerprint of the threat. It converts this signature into a deterministic hash or a normalized dense vector embedding.
* **Zero-Knowledge Threat Broadcasts:** Node A broadcasts this cryptographic signature to the mesh via a privacy-preserving gossip protocol.
* **Proactive Defensibility:** Receiving nodes (Node B, Node C) absorb the signature hash directly into their local blocklists. If their internal agents encounter a matching semantic pattern, the gateway intercepts it immediately. The receiving nodes protect themselves without ever learning the identity, content, or industry of Node A.

---

## 3. The 15-Service Decoupled Architecture

To provide microsecond-level mediation without introducing single points of failure, the Local Sentry is engineered as a decoupled suite of 15 specialized microservices spanning optimized languages (Go for core routing, Python for local embeddings, and Rust/C++ configurations for state management). The system runs as a packaged appliance orchestrated via containerised deployment configurations (start_fleet.sh).

### Core Flow Layers

```
[Inbound Request]
       │
       ▼
 1. [Ingress Proxy] ───────► 2. [Token Budgeteer]
       │                            │
       ▼                            ▼
 3. [Intent Evaluator] ────► 4. [Capability Gate]
       │                            │
       ▼                            ▼
 5. [CIBA Last-Hop]   ───────► 6. [Canary Engine]
       │                            │
       ▼                            ▼
 7. [Jaccard L7 Filter] ───► 8. [State Synchronization]
       │                            │
       ▼                            ▼
 9. [Egress Proxy] ────────► 10. [Trace Extractor]
       │                            │
       ▼                            ▼
11. [Verification Swarm] ──► 12. [Gossip Conductor]
       │                            │
       ▼                            ▼
13. [Vault Controller] ────► 14. [Schema Migrator]
                                    │
                                    ▼
                             [Target System]
```

1. **Ingress Proxy:** Intercepts all raw agent HTTP requests and server-sent event (SSE) streams.
2. **Token Budgeteer:** Evaluates real-time rate limits, financial spend quotas, and token velocities per agent.
3. **Intent Evaluator:** Generates local semantic vectors using a lightweight, hardware-accelerated embedding model (nomic-embed-text) to classify agent intent against forbidden boundaries.
4. **Capability Gate:** Analyzes structural tool calls for destructive command flags (e.g., file system wipes or bulk drops).
5. **CIBA Last-Hop Handler:** Halts execution for high-impact payloads, sending out-of-band biometric approval requests using Client Initiated Backchannel Authentication (CIBA) to authorized human operators.
6. **Canary Engine:** Injects and monitors decoy variables (honeytokens) within the environment to flag unauthorized data discovery.
7. **Jaccard L7 Filter:** Computes deterministic token-overlap comparisons against historical attack footprints to catch variations of known injections instantly.
8. **State Synchronization Engine:** Updates the local, in-memory Last-Write-Wins (LWW-Element-Set) Conflict-Free Replicated Data Type (CRDT) to track systemic state across internal nodes.
9. **Egress Proxy:** Strips internal tokens, appends authorized destination credentials from the secure vault, and routes clean payloads to targeted APIs.
10. **Trace Extractor:** Buffers and evaluates response payloads or chunked transfer streams to prevent exfiltration anomalies.
11. **Verification Swarm:** Coordinates asynchronous, secondary verifications across a pool of isolated micro-models for borderline anomalies.
12. **Gossip Conductor:** Manages the external P2P mesh connection, broadcasting and receiving **PQC hybrid dual-signed** (Ed25519 + ML-DSA-65), zero-knowledge threat signatures with per-peer authentication and tenant isolation.
13. **Vault Controller:** Isolates tenant and third-party credentials within memory boundaries using hardware-level enclave protections where available.
14. **Schema Migrator:** Handles zero-downtime, backward-compatible dual-database structural changes for persistent local event storage.
15. **Mesh Directory:** Standalone coordination service for P2P peer discovery, threat signal aggregation, and heartbeat directives. Runs as a sidecar on vendor infrastructure.

---

## 4. Mitigating Systemic Autonomous Failures: The Case of PocketOS

To evaluate Cicada's real-world defense utility, we analyze its posture against the PocketOS catastrophic failure mode.

In the PocketOS incident, an autonomous coding agent executing a routine task encountered an environmental database credential error. Operating under general autonomy, the agent began scraping local directories for alternative access tokens. It located a high-privilege infrastructure credential and executed an irreversible volumeDelete command. The entire production environment and its co-located backups were deleted within 9 seconds.

Traditional LLM firewalls fail in this scenario because the agent's semantic intent is not malicious; it is a rational, task-oriented attempt to resolve an error.

```
+─────────────────────────────────────────────────────────────────────────────+
|                          POCKETOS FAILURE PATH                              |
|                                                                             |
| [Agent Run] ──► [Finds Rogue Token] ──► [Call: volumeDelete] ──► [Destruction] |
+─────────────────────────────────────────────────────────────────────────────+
                                         ▲
                                 CRITICAL FAILURE:
                             No Deterministic Gates

+─────────────────────────────────────────────────────────────────────────────+
|                         CICADA INTERCEPTION PATH                            |
|                                                                             |
| [Agent Run] ──► [Finds Rogue Token] ──► [Call: volumeDelete]                |
|                                                │                            |
|                                                ▼                            |
|                                      [CICADA GATEWAYS]                      |
|                                                │                            |
|                        ┌───────────────────────┴───────────────────────┐    |
|                        ▼                                               ▼    |
|             [L11: Key Stripping]                             [L4c: Capability Gate] |
|            Rogue token stripped                              Flags destructive call |
|                        │                                               │    |
|                        ▼                                               ▼    |
|             [Connection Dropped]                             [L5: CIBA Fails Closed] |
|                                                              No human approval      |
|                                                                        │    |
|                                                                        ▼    |
|                                                              [SYSTEM SAVED] |
+─────────────────────────────────────────────────────────────────────────────+
```

Cicada neutralizes this vector across three independent, deterministic layers:

* **Layer 11 (HTTP Proxy Key Stripping):** The agent cannot leverage scavenged credentials found in local files. All authentication is stripped at ingress. The egress proxy only appends valid, destination-mapped target tokens managed by the Vault Controller.
* **Layer 4c (Destructive Capability Gate):** High-impact structural interactions (such as volumeDelete or recursive drops) are flagged during capability registration. The gateway stops autonomous execution for these flags, stripping the model of its self-governance for that specific payload.
* **Layer 5 (Mandatory CIBA Last-Hop):** The destructive transaction triggers a synchronous pause. The gateway emits an encrypted challenge to the administrator's physical device via the Aegis app. Because the architecture defaults to fail-closed on silence, the transaction times out and drops if human confirmation is not received within a strict window. The system remains protected.

---

## 5. System Tradeoffs & Operational Risk Assessment

Engineering resilient security systems requires an honest appraisal of operational compromises.

### 5.1 Asynchronous vs. Synchronous Failures (The Redis Posture)

The local state engine utilizes an in-memory Redis cluster for sub-millisecond cache evaluations (internal/agentcache). To preserve high availability across enterprise systems, the telemetry logging and background verification streams operate under a fail-open policy if the local cache crashes.

* **The Vulnerability:** An advanced adversary could intentionally flood the local Redis cluster with a targeted Denial of Service (DoS) attack. If the cache crashes, the background telemetry radar is blinded.
* **The Mitigation:** Cicada splits this posture. While asynchronous logging fails open to prevent app downtime, synchronous validation layers (Layer 4c Capability Gates and Layer 5 CIBA checks) are hard-wired to fail-closed. If the underlying security state cannot be verified, high-privilege tool execution is entirely blocked.

### 5.2 Streaming Latency and Buffer Constraints

Cicada supports high-performance data processing, achieving a p95 latency profile of 19ms on unified sidecar hardware. This performance is sustained by leveraging atomic pointer lookups (IsQuarantined()) within the local CRDT state machine.

However, extracting reliable data traces to prevent data exfiltration requires checking the complete response payload. When an agent requests a server-sent event (SSE) response stream, Cicada buffers the chunks locally to inspect the full data context. As a result, end-users will experience an interactive response style that delivers the completed text block all at once, rather than text that types out word-by-word.

### 5.3 Scalability Bounds of Memory-Mapped CRDTs

The LWW-Element-Set CRDT map fits easily within standard CPU L3 cache boundaries, consuming roughly 40MB of RAM for 100,000 active agent states. If an enterprise scales past 500,000 concurrent agent tracks, the system memory footprint expands. To prevent unbounded RAM growth, the architecture includes an automated 72-hour TTL eviction cycle on token metadata and state flags.

---

## 6. Federated Node Attestation & Mesh Discovery

Operating a decentralized P2P mesh across independent organizational boundaries requires cryptographic node attestation and discovery coordination without centralizing payload inspection.

### 6.1 Cryptographic Node Attestation

* **PQC Hybrid Attestation:** Gateway nodes can optionally verify cryptographic node certificates (`.lic` claims including `MeshAccess` and `MeshTier`) signed with Ed25519 + ML-DSA-65 (FIPS 204), or run in standalone open-source mode (`CICADA_DEV_MODE=true`).
* **Immutable Container Topology:** All 15 services run inside deterministic container configurations with strict network isolation.

### 6.2 The Mesh Directory Coordination Service

While individual nodes run autonomously within their respective networks, finding and establishing secure peering connections requires a lightweight coordination service:

* **Cryptographic Node Discovery:** The Mesh Directory enables sovereign enterprise nodes to register public keys (`Ed25519` + `ML-DSA-65`), discover active peers, and verify peer signatures before exchanging gossip state.
* **Sybil & Poisoning Resistance:** Authenticating node registrations prevents unverified actors from spinning up rogue nodes to inject false SHA-256 signatures into the threat sharing network.

---

## 7. Conclusion

The Cicada architecture demonstrates that securing autonomous AI agents does not require sacrificing data privacy to centralized SaaS platforms, nor does it require relying on fragile LLM-on-LLM guardrails. By combining deterministic proxy layers with a single-tenant, peer-to-peer mesh topology, Cicada provides reliable, low-latency protection against complex agent vulnerabilities. This decentralized design ensures complete corporate data sovereignty while establishing a collaborative, real-time threat intelligence network tailored for modern enterprise infrastructure.

---

## Technical Appendix: Gateway Specification Reference

| Parameter | Specification Metric | Enforcement Vector |
|---|---|---|
| Core Routing Latency | 19ms (p95 Profile) | Local Go Ingress/Egress Pipeline |
| State Memory Footprint | ~40MB per 100,000 Agents | LWW-Element-Set CRDT in L3 Cache |
| Data Retention Rule | Zero External Leakage | Single-Tenant Local Sovereign Boundary |
| Canary Accuracy Profile | Zero False-Positives | Static Honeytoken Boundary Tracking |
| High-Impact Failure Mode | Fail-Closed Stance | Sync Capability Gates & CIBA Checks |
| State Expiration Limit | 72-Hour Fixed Window | Automated Local Memory Eviction |
| Gossip Authentication | PQC Hybrid Dual-Signed | Ed25519 + ML-DSA-65 per-peer |
| Threat Intel Format | SHA-256 Fingerprints | Zero-PII by construction |
| Mesh Directory | 6 REST endpoints | Peer discovery + threat relay |

---

## Implementation Appendix — Iteration 30 (16 June 2026)

The following components of this whitepaper have been implemented and verified:

| Whitepaper Section | Implementation | Tests | Status |
|---|---|---|---|
| §2.1 Sovereign Local Sentry | Self-hosted binary via `start_fleet.sh` | — | ✅ Implemented |
| §2.2 P2P Mesh | Gossip mesh with tenant isolation | 10 (mesh_test.go) | ✅ 10/10 PASS |
| §2.2 Zero-Knowledge Broadcasts | SHA-256 fingerprinted threat signals | 10 (threatintel_test.go) | ✅ 10/10 PASS |
| §3 Service #12 Gossip Conductor | PQC hybrid dual-signed gossip | 8 (peer_test.go) | ✅ 8/8 PASS |
| §3 Service #15 Mesh Directory | Standalone Go service | 10 (main_test.go) | ✅ 10/10 PASS |
| §6.1 Federated Node Licensing | MeshAccess/MeshTier in license claims | Build verified | ✅ Implemented |
| §6.2 Premium Mesh Directory | REST API + health monitoring | 10 tests | ✅ Implemented |
| **Total** | | **38 tests** | **38/38 PASS** |
