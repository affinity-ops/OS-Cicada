# The Matthews Enforcement Framework: A Prospective, Path-Dependent Architecture for Runtime AI Agent Governance

**Author:** Patrick Matthews (Affinity Ops / Affinity Smart AI — `info@affinitysmartai.co.uk`)  
**Originally Published:** 4 June 2026 (Conceptual 10-Layer Specification)  
**Updated for Open-Source Release (`v1.0.3`):** 7 November 2026

> [!IMPORTANT]
> **Relationship to the Version 3 Architecture Paper & `RELEASE_SCOPE.md`:**
> This document preserves the foundational **10-Layer Conceptual Specification** of the Matthews Enforcement Framework (MEF) originally formulated in June 2026. For the complete, code-verified open-source reference implementation (`v1.0.3`), see **[`docs/PATH_DEPENDENT_ARCHITECTURE_v3.md`](./PATH_DEPENDENT_ARCHITECTURE_v3.md)** and **[`RELEASE_SCOPE.md`](../RELEASE_SCOPE.md)**, which map these 10 conceptual layers 1-for-1 onto the **15-Stage Gateway Request Lifecycle** (`cmd/sentry/main.go`) and the **9-Layer Deterministic Admission Pipeline** (`internal/pipeline/pipeline.go`).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement-why-reactive-and-identity-only-security-models-fail-autonomous-ai-agents)
3. [Theoretical Foundations](#3-theoretical-foundations-path-dependent-governance-and-the-four-pillars-of-ai-agent-control)
4. [The Matthews Enforcement Framework: Architecture and Core Thesis](#4-the-matthews-enforcement-framework-architecture-and-core-thesis)
5. [The Ten-Layer Defence-in-Depth Enforcement Pipeline](#5-the-ten-layer-defence-in-depth-enforcement-pipeline)
6. [Post-Quantum Cryptographic Identity and Governance Assurance](#6-post-quantum-cryptographic-identity-and-governance-assurance)
7. [Empirical Validation and Regulatory Relevance](#7-empirical-validation-and-regulatory-relevance)
8. [Relationship to Contemporary Frameworks and the Cicada Reference Implementation](#8-relationship-to-contemporary-frameworks-and-the-cicada-reference-implementation)

---

## 1. Executive Summary

The Matthews Enforcement Framework is a prospective, path-dependent architecture designed to govern runtime AI agents. As the autonomous AI landscape continues to evolve, the need for robust governance models has become increasingly pressing. Existing reactive and identity-only security models are insufficient, failing to address the complex challenges posed by autonomous AI agents. This whitepaper presents the Matthews Enforcement Framework, a novel approach to AI agent governance that prioritizes a path-dependent, multi-layered defence-in-depth strategy.

---

## 2. Problem Statement: Why Reactive and Identity-Only Security Models Fail Autonomous AI Agents

Reactive security models rely on detective and reactive controls, focusing on incident response and breach containment. However, these approaches are inadequate for autonomous AI agents, which operate in real-time and make decisions independently. The complexity and speed of AI-driven systems require a proactive, preventative approach to governance.

Identity-only security models, on the other hand, focus solely on agent identity and authentication. While identity management is crucial, it is insufficient to ensure the secure operation of autonomous AI agents. These models fail to address the nuances of AI decision-making, neglecting the action sequence, untrusted data provenance (taint), and behavioural aspects of agent interactions.

As codified in the **OWASP Top 10 for Agentic Applications (December 2025)** and the **NIST AI Agent Standards Initiative (17 February 2026)**, tool-using agents introduce path-dependent risks (`ASI01`–`ASI10`) that stateless API gateways cannot evaluate. Furthermore, the **EU Artificial Intelligence Act (Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744)** establishes strict risk management, record-keeping, and human-oversight obligations for high-risk AI providers and deployers.

---

## 3. Theoretical Foundations: Path-Dependent Governance and the Four Pillars of AI Agent Control

Path-dependent governance recognizes that AI agent decision-making is inherently linked to its preceding actions and environmental context. This perspective acknowledges that agent interactions are influenced by their history, environment, and intent, necessitating a governance model that accounts for these factors.

The four pillars of AI agent control provide a foundational framework for governance:

1. **Identity**: Agent identification and authentication
2. **Intention**: Understanding and aligning with the agent's goals and objectives
3. **Behaviour**: Monitoring and controlling agent actions and decision-making
4. **Context**: Considering the environmental and situational factors influencing agent interactions

These pillars form the basis of the Matthews Enforcement Framework, providing a comprehensive structure for governing autonomous AI agents.

---

## 4. The Matthews Enforcement Framework: Architecture and Core Thesis

The Matthews Enforcement Framework is a prospective, path-dependent architecture designed to govern runtime AI agents. The framework consists of a ten-layer defence-in-depth enforcement pipeline, built upon the four pillars of AI agent control.

The core thesis of the Matthews Enforcement Framework is that robust governance requires a multi-layered, path-dependent approach, incorporating identity, intention, behaviour, and context. By integrating these elements, the framework enables proactive, real-time governance of autonomous AI agents.

The architecture of the Matthews Enforcement Framework is comprised of the following components:

- **Agent Certification Lifecycle**: A post-quantum cryptographic identity management system, utilizing Ed25519 + ML-DSA-65 for secure agent identification and certification
- **Skills Routing Capability Grid**: A deterministic, out-of-band state machine that enforces skill-level contracts declared in the agent's policy manifest (`cicada.yaml`). The Gateway validates that each tool invocation matches its declared schema, upstream lineage, and criticality classification before execution — preventing agents from invoking undeclared capabilities or receiving delegated work from unauthorised peers
- **Context Rot Prevention**: A gateway-to-SDK feedback loop that signals the calling SDK to flush its local memory window when a security boundary is breached (injection detection, skill boundary violation, or high-criticality transition), preventing poisoned context fragments from accumulating across calls
- **Human-in-the-Loop Authorization**: A biometric cryptographic approval process, ensuring semantic intent alignment and behavioural baseline deviation detection
- **Immutable Audit Trail**: A tamper-evident log, providing a complete and immutable record of agent interactions
- **Kaptein Runtime Governance Policies**: A set of policies and rules, governing agent actions and decision-making based on path-dependent context

---

## 5. The Ten-Layer Defence-in-Depth Enforcement Pipeline

The Matthews Enforcement Framework runtime AI agent governance architecture achieves its prospective enforcement mandate not through a single control mechanism but through a sequentially ordered, ten-layer defence-in-depth pipeline that intercepts agent actions at every structurally distinct point between intent formation and execution.

This pipeline architecture reflects a foundational design principle: that no single control, however sophisticated, can provide adequate assurance against the full spectrum of failure modes characteristic of autonomous AI agents operating in complex, multi-tool environments. Each layer addresses a categorically different class of risk, and the path-dependent nature of MEF means that signals accumulated across earlier layers actively inform the policy decisions made in later ones.

### Layers 1–3: Structural Defence Perimeter

**Layer 1: Structural Injection Scanning.** Prompt injection represents one of the most consequential attack vectors in autonomous agent systems, as extensively documented in the OWASP Top 10 for Large Language Model Applications. MEF Layer 1 implements a multi-pattern structural injection scanner that evaluates all inputs — whether originating from users, external APIs, retrieved documents, or inter-agent messages — against a curated and continuously updated signature library. Critically, this layer operates prior to any LLM inference, ensuring that injection payloads cannot influence the agent's reasoning process even in principle.

**Layer 2: Input Sanitisation.** Layer 2 applies normalisation and sanitisation transformations to all inputs that have passed Layer 1's signature scan. Input sanitisation removes or neutralises structurally anomalous content — including anomalous Unicode sequences, homoglyph substitutions, zero-width characters, and encoding-layer obfuscations — that may be invisible at the surface level but designed to manipulate tokenisation or attention patterns in downstream model inference.

**Layer 3: Schema Validation.** All agent inputs and proposed action outputs in MEF-governed systems are bound to formally specified schemas. Layer 3 validates that every data structure conforms to its declared schema before processing continues. Schema validation enforces that proposed actions conform to the typed interface specifications of the tools they target.

**Layer 3b: Skills Routing and Contract Enforcement.** Layer 3b extends schema validation to the level of individual agent skills. Each agent declares its permissible skills (tools) in a policy-as-code manifest (`cicada.yaml`), specifying for each skill: a criticality classification (`low`, `medium`, `high`), an upstream lineage whitelist (`allowed_upstreams`), and a JSON Schema payload contract (`input_schema`). At runtime, when an agent targets a specific skill, the Gateway deterministically enforces all three contract dimensions: (1) the skill must be declared in the manifest (ASI01 Governance Violation if undeclared), (2) the calling agent or its upstream orchestrator must appear in the skill's allowed upstream list (ASI04 Delegation Violation if unauthorised), and (3) the request payload must conform to the declared input schema (structural deviation if non-conformant). High-criticality skills additionally arm CIBA escalation at Layer 10 and trigger an anti-rot context flush via `X-Cicada-Memory-Action: flush`, instructing the SDK to purge its local context window. This prevents poisoned context fragments — the residue of failed injections or stale cross-skill state — from propagating across skill transitions. Every enforcement decision is written to the immutable audit trail as a typed record (`skill_blocked`, `skill_delegation_blocked`, `skill_schema_violation`, or `memory_flush`).

### Layers 4–6: Semantic Defence Perimeter

**Layer 4: Semantic Intent Alignment.** Semantic intent alignment evaluates whether the semantic content of a proposed agent action is coherent with the declared objective of the current task. The agent's proposed action is semantically encoded and compared against both the declared task intent and a policy-defined permissibility space. This layer is critical for detecting goal substitution attacks.

**Layer 5: Behavioural Baseline Deviation Detection.** MEF maintains continuously updated statistical models of agent behaviour during authorised operation, capturing distributions over action types, tool invocation sequences, resource access patterns, timing characteristics, and inter-action intervals. Deviation scores above a configurable threshold trigger elevated policy scrutiny.

**Layer 6: Contextual Risk Scoring.** Layer 6 synthesises signals from all preceding layers into a unified, real-time contextual risk score. This composite score is a weighted function that accounts for the correlational structure between signals, reflecting the empirical observation that simultaneous moderate deviations across multiple independent dimensions are more indicative of genuine compromise than a single large deviation on one dimension. Layer 6's composite score gates the decision logic in Layers 7–10.

### Layers 7–9: Policy Enforcement and Cryptographic Assurance

**Layer 7: Policy Evaluation Against Path History.** This layer represents MEF's most distinctive technical contribution. Layer 7 evaluates the proposed action not merely against static policy rules but against the entire sequence of actions taken by the agent within the current session — the action path. Path-dependent policy evaluation enables governance constraints that cannot be expressed in any single-action policy language. The formal apparatus underlying this layer is closely related to the path-dependent policy framework independently formalised by Kaptein et al. (arXiv:2603.16586, March 2026), though MEF's implementation was conceived and deployed in production code prior to that theoretical formalisation.

**Layer 8: Cryptographically Verified Action Authorisation & Outbound DLP.** For actions that pass all preceding layers, Layer 8 verifies the caller's cryptographic session token (compact 64-byte classical `Ed25519` for per-request 24h EVARs and 5m JIT session JWTs), strips client `Authorization`/`X-Cicada-*` headers, injects decrypted BYOK vault credentials over a DNS-pinned socket (`proxyTransport.DialContext`), and inspects outbound/inbound payloads for credential or PII exfiltration (`internal/output`).

**Layer 9: Immutable Audit Trail Generation.** Every action evaluated by the MEF pipeline generates a tamper-evident audit record appended to the agent's SHA-256 hash-chained audit trail (`internal/ledger`): each audit record incorporates the cryptographic SHA-256 hash of the preceding record.

### Layer 10: Mandatory Human-in-the-Loop Authorization (CIBA)

Layer 10 is architecturally distinct from all preceding layers in that it is not an automated computational gate but a mandatory human decision point. For actions whose contextual risk score exceeds a policy-defined threshold—or when triggered by destructive classification (Layer 7), behavioural drift (Layer 5), or CaMeL session taint (Layer 7)—MEF requires explicit out-of-band human authorisation via Client-Initiated Backchannel Authentication (`internal/ciba`). The human operator inspects the full untruncated request payload, authenticates via hardware biometrics, and signs the approval decision bound to the decimal length-prefixed SHA-256 hash of the HTTP method, canonicalised URL, and body bytes (`approved_payload_hash`) plus the hold `TraceID` nonce using hybrid `Ed25519 + ML-DSA-65` signatures.

---

## 6. Post-Quantum Cryptographic Identity and Governance Assurance

### Classical `Ed25519` for Ephemeral Session Tokens vs. Hybrid `Ed25519 + ML-DSA-65` for Governance Boundaries

In the open-source reference implementation (`Sentry_Gateway`), cryptographic primitives are matched to the lifetime and header constraints of each boundary:

- **Per-Request Agent Tokens (`Ed25519` / `EdDSA`):** 24-hour Enterprise Verified Agent Records (`internal/auth/evar_minter.go`) and 5-minute Just-In-Time (JIT) session JWTs (`internal/session/session.go`) use compact 64-byte classical **Ed25519** signatures to avoid adding a 3,309-byte ML-DSA-65 signature to every HTTP request header.
- **High-Consequence Governance Boundaries (`Ed25519 + ML-DSA-65`, NIST FIPS 204):** Hybrid classical + post-quantum dual signatures (`pkg/pqc/mldsa.go` via `cloudflare/circl/sign/mldsa/mldsa65`) are wired at three long-lived governance and control-plane boundaries where multi-year audit non-repudiation is required:
  1. **Mobile CIBA Human Approval Decisions** (`internal/mobile/handlers_lifecycle.go`)
  2. **Inter-Gateway P2P Gossip Quarantine Broadcasts** (`internal/gossip/peer.go`)
  3. **Platform Entitlement & Vendor Authentication Envelopes** (`internal/license/enforcer.go`)

### The Certification Lifecycle

MEF treats agent registrations as first-class governance artefacts with four phases:

1. **Issuance**: Provisional registration (`pending_review` forced into read-only shadow observation) promoted to `certified` upon operator approval, binding public keys, tool manifests (`agent_tools`), and permitted scopes.
2. **Rotation**: Periodic key and JIT session token renewal (`internal/rotation`, `internal/session`).
3. **Revocation**: Immediate local and P2P gossip quarantine (`internal/gossip`) and CAEP revocation (`internal/caep`).
4. **Audit**: Immutable `certification_events` and SHA-256 hash-chained `action_ledger` records (`internal/ledger`).

---

## 7. Empirical Validation and Regulatory Relevance

### Reproducible Test Suite Verification (`scripts/count_tests.sh`)

In release `v1.0.3`, the open-source repository includes a deterministic test-counting script ([`scripts/count_tests.sh`](../scripts/count_tests.sh), executed on every GitHub Actions CI run) verifying **1,299 top-level test definitions across 104 test files**, plus **23 live production-path E2E checks** ([`scripts/e2e_production.sh`](../scripts/e2e_production.sh)):

| Language | Component Directory | Test Files | Top-Level Test Count |
|----------|---------------------|-----------:|---------------------:|
| Go (Gateway) | `Sentry_Gateway` (plus 40 `t.Run`, 22 corpus cases, 15 benchmarks) | 65 | 760 |
| Go (Companion) | `Shadow_Sandbox`, `Mesh_Directory`, `Licensing_Authority` | 4 | 50 |
| PHP | `Core_API/tests` | 9 | 82 |
| Python | `Cicada_SDK/python/tests`, `Verification_Swarm`, `Saga_Executor` | 8 | 174 |
| TypeScript/JS | `Developer_Portal/src`, `dashboard/src`, `Cicada_SDK/node/src` | 14 | 179 |
| Dart/Flutter | `Ciba_Flutter_App/test` (42 `test` + 12 `testWidgets`) | 4 | 54 |
| **Total** | **All Open-Source Test Files (`bash ./scripts/count_tests.sh`)** | **104** | **1,299** |

### EU AI Act Technical Relevance (Regulation (EU) 2024/1689 & Regulation (EU) 2026/1744)

Following the EU Digital Omnibus on AI (**Regulation (EU) 2026/1744**), high-risk obligations apply from **2 December 2027** (Annex III) and **2 August 2028** (Annex I). The table below illustrates how MEF's technical controls support provider (Articles 9–15) and deployer (Article 26) compliance engineering (technical support only, not legal conformity certification):

| EU AI Act Article | Role | Requirement | MEF / Cicada Technical Mechanism |
|---|---|---|---|
| Article 9 | Provider | Risk management system | 9-layer `pipeline.Evaluate` admission pipeline + session taint tracking |
| Article 10 | Provider | Data governance | Layer 1/2 deobfuscation, Rule-of-Two registration sanitiser, JSON Schema validation |
| Article 11 | Provider | Technical documentation | Immutable `certification_events` and versioned `agent_tools` manifests |
| Article 12 | Provider | Automatic event logging | Stage 15 SHA-256 hash-chained audit ledger (`internal/ledger`) |
| Article 13 | Provider | Transparency | Deterministic rejection reason codes and `[HITL-SHADOW]` telemetry |
| Article 14 | Provider | Human oversight | Mandatory CIBA approval bound to `SHA-256(Method, CanonicalURL, Body)` + `TraceID` |
| Article 15 | Provider | Accuracy, robustness, cybersecurity | Server-side tool scoping, CaMeL taint escalation, `DialContext` IP-pinned SSRF guard |
| Article 26 | Deployer | Deployer human oversight & log retention | Self-hosted gateway policy enforcement, CIBA operator assignment, local audit retention |

---

## 8. Relationship to Contemporary Frameworks and the Cicada Reference Implementation

| Framework / Literature | Focus Area | How Cicada / MEF Operationalises or Complements It |
|---|---|---|
| **OWASP Agentic Top 10 (Dec 2025)** | Taxonomy of 10 agentic failure modes (`ASI01`–`ASI10`) | Direct enforcement modules in `Sentry_Gateway/internal/` across all 10 categories |
| **CaMeL (Debenedetti et al., 2025)** | Provenance and control/data-flow separation | Network-layer session taint tracking (`internal/taint`) across all untrusted external responses |
| **Meta AI's Agents Rule of Two (2025)** | Bounding the `[ABC]` autonomy trifecta | Registration-time `RULE_OF_TWO_TRIFECTA` gate (`sanitizer.go`) + runtime taint CIBA escalation |
| **Kaptein et al. (March 2026)** | Formal path-dependent policy predicates | Redis-backed forward-saga prerequisite verification (`internal/prerequisite`) recorded post-`2xx`/`3xx` |
| **Nasr et al. ("The Attacker Moves Second", 2025)** | Adaptive bypasses of classifier defences | Motivates positioning regex/semantic scanners as baseline filters while relying on deterministic tool scope, prerequisites, taint, and CIBA hash binding as the primary security boundary |

For the complete component-by-component **Implemented vs. Designed Matrix**, **Fail-Open vs. Fail-Closed Defaults Table**, micro/macro-benchmarks, and twelve operational limitations, see **[`docs/PATH_DEPENDENT_ARCHITECTURE_v3.md`](./PATH_DEPENDENT_ARCHITECTURE_v3.md)** and **[`RELEASE_SCOPE.md`](../RELEASE_SCOPE.md)**.

---

## References

- OWASP Foundation. (December 2025). *OWASP Top 10 for Agentic Applications (ASI01–ASI10)*. `https://genai.owasp.org/`
- National Institute of Standards and Technology (NIST). (17 February 2026). *NIST AI Agent Standards Initiative (CAISI)*.
- Nasr, M., Carlini, N., Sitawarin, C., et al. (2025). *The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections*.
- Debenedetti, E., Shumailov, I., Fan, T., et al. (2025). *Defending LLM Agents against Prompt Injection with CaMeL*. `arXiv:2503.18813`.
- Meta AI Security. (2025). *The Agents Rule of Two*.
- Regulation (EU) 2024/1689 & Regulation (EU) 2026/1744 (Digital Omnibus on AI).
- Kaptein, M., Khan, V.-J., & Podstavnychy, A. (2026). *Runtime governance for AI agents: Policies on paths*. `arXiv:2603.16586`.
- Mazzocchetti, A. M. (2026). *Cryptographic runtime governance for autonomous AI systems*. `DOI: 10.2139/ssrn.6418638`.
- DeRudder, J. (2026). *Computable Trust Architecture: A Formal Framework for Runtime AI Governance*. `DOI: 10.2139/ssrn.6418638` / `10.2139/ssrn.6583738`.
- Emerson, H. (2026). *THEMIS-xAI: A Unified Architecture for Explainable AI Governance*. `DOI: 10.2139/ssrn.6390878`.
- Marín, G. & Chaudhary, J. (2026). *Governing What You Cannot Observe: Adaptive Runtime Governance*. `arXiv:2604.24686`.
- Sawaf, K. (2026). *The Discrete Judgment Intermediate: An Externalization Infrastructure for AI Governance*. University of Edinburgh Preprint.
- NIST. (August 2024). *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
- NIST. (2023). *AI Risk Management Framework (AI RMF 1.0)*. NIST AI 100-1.

---

*Matthews Enforcement Framework © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI — `info@affinitysmartai.co.uk`)*
