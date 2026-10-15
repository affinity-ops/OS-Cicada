# The Matthews Enforcement Framework: A Prospective, Path-Dependent Architecture for Runtime AI Agent Governance

**Author:** Patrick Matthews, Affinity Ops Ltd
**Published:** 4 June 2026
**Status:** White Paper (Part 1 & 2)

> **Note:** This document is the in-repository copy of the MEF white paper, originally published externally. It is the foundational governance thesis upon which the Cicada platform is built. All references to MEF in the Buyer's Deployment Guide, Engineering Assessment Response, and Technical Truth documentation trace back to this document.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Theoretical Foundations](#3-theoretical-foundations)
4. [The Matthews Enforcement Framework: Architecture and Core Thesis](#4-the-matthews-enforcement-framework-architecture-and-core-thesis)
5. [The Ten-Layer Defence-in-Depth Enforcement Pipeline](#5-the-ten-layer-defence-in-depth-enforcement-pipeline)
6. [Post-Quantum Cryptographic Identity and the Agent Certification Lifecycle](#6-post-quantum-cryptographic-identity-and-the-agent-certification-lifecycle)
7. [Empirical Validation and Regulatory Alignment in Q2 2026](#7-empirical-validation-and-regulatory-alignment-in-q2-2026)
8. [MEF as a Category-Defining Standard: Cicada as the Sole Production Reference Implementation](#8-mef-as-a-category-defining-standard)

---

## 1. Executive Summary

The Matthews Enforcement Framework is a prospective, path-dependent architecture designed to govern runtime AI agents. As the autonomous AI landscape continues to evolve, the need for robust governance models has become increasingly pressing. Existing reactive and identity-only security models are insufficient, failing to address the complex challenges posed by autonomous AI agents. This whitepaper presents the Matthews Enforcement Framework, a novel approach to AI agent governance that prioritizes a path-dependent, multi-layered defence-in-depth strategy.

---

## 2. Problem Statement: Why Reactive and Identity-Only Security Models Fail Autonomous AI Agents

Reactive security models rely on detective and reactive controls, focusing on incident response and breach containment. However, these approaches are inadequate for autonomous AI agents, which operate in real-time and make decisions independently. The complexity and speed of AI-driven systems require a proactive, preventative approach to governance.

Identity-only security models, on the other hand, focus solely on agent identity and authentication. While identity management is crucial, it is insufficient to ensure the secure operation of autonomous AI agents. These models fail to address the nuances of AI decision-making, neglecting the context, intent, and behavioural aspects of agent interactions.

According to a report by Boston Consulting Group, only 1.3% of organizations have implemented effective enterprise agents, highlighting the need for a more comprehensive approach to AI agent governance (Boston Consulting Group, 2022). The EU AI Act, set to take effect in 2024, will introduce strict regulations on AI development and deployment, further emphasizing the imperative for robust governance models (European Union, 2021).

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

**Layer 8: Cryptographically Signed Action Authorisation.** For actions that pass all preceding layers, Layer 8 generates a cryptographically signed authorisation token. This token is signed using the post-quantum hybrid signature scheme — Ed25519 combined with ML-DSA-65 — providing both classical and quantum-resistant authenticity guarantees.

**Layer 9: Immutable Audit Trail Generation.** Every action evaluated by the MEF pipeline generates a tamper-evident audit record appended to the agent's immutable audit trail. Immutability is achieved through a hash-chaining mechanism: each audit record incorporates the cryptographic hash of the preceding record.

### Layer 10: Mandatory Human-in-the-Loop Authorization

Layer 10 is architecturally distinct from all preceding layers in that it is not an automated computational gate but a mandatory human decision point. For actions whose contextual risk score exceeds a policy-defined threshold, MEF requires explicit human authorisation through a cryptographically signed biometric approval: the authorising human presents a biometric credential that is bound to their identity certificate, and the resulting approval is digitally signed under the same post-quantum hybrid scheme.

---

## 6. Post-Quantum Cryptographic Identity and the Agent Certification Lifecycle

### Ed25519 and ML-DSA-65 as Quantum-Resistant Primitives

The cryptographic primitives at the core of MEF's identity architecture are Ed25519 and ML-DSA-65, deployed in a hybrid signature scheme that simultaneously satisfies classical and post-quantum security requirements.

- **Ed25519**: Elliptic curve digital signature algorithm over Curve25519, offering 128-bit classical security with compact signatures and high-performance operations.
- **ML-DSA-65**: Lattice-based digital signature algorithm standardised by NIST, offering Security Level 3. Its security derives from the hardness of the Module Learning With Errors problem, which is not susceptible to Shor's algorithm.

The hybrid scheme requires both signatures to verify successfully, meaning breaking the token requires simultaneously breaking both schemes.

### The Certification Lifecycle

MEF treats agent identity certificates as first-class governance artefacts with four phases:

1. **Issuance**: Certificate issued upon successful provenance verification, encoding public keys, policy binding, permitted action classes, and validity period.
2. **Rotation**: Periodic key renewal at policy-defined intervals with non-disruptive overlap periods.
3. **Revocation**: Soft revocation (grace period for in-flight actions) and hard revocation (immediate termination for incident response).
4. **Audit**: Continuous monitoring of certificate state with structured reports on issuance, rotation compliance, and anomalies.

---

## 7. Empirical Validation and Regulatory Alignment in Q2 2026

### Test Suite Verification

MEF's validation suite comprises **1,143 automated tests** (exceeding the originally published figure of 1,052) executed across the following languages and components:

| Language | Component | Test Count |
|----------|-----------|----------:|
| Go | Sentry Gateway (52 test files) | 684 |
| Dart | Aegis Mobile App | 42 |
| PHP | Core API | 71 |
| Python | SDK, Verification Swarm, Saga Executor | 181 |
| TypeScript/TSX | Operator Dashboard, Developer Portal | 163 |
| Go | Licensing Authority | 2 |
| **Total** | | **1,143** |

Zero failures recorded across the complete test run. The test suite is executed in its entirety with each code change, ensuring the zero-failure benchmark is preserved.

### EU AI Act Alignment

The EU Artificial Intelligence Act (Regulation (EU) 2024/1689) provisions map directly to MEF's architecture:

| EU AI Act Article | Requirement | MEF Layer |
|---|---|---|
| Article 9 | Risk management system | Layers 1–6 (continuous risk assessment) |
| Article 10 | Data governance | Layer 2 (input sanitisation) + Layer 3 (schema validation) |
| Article 11 | Technical documentation | Certification lifecycle audit records |
| Article 12 | Automatic event logging | Layer 9 (immutable audit trail) |
| Article 13 | Transparency | Certification audit function |
| Article 14 | Human oversight | Layer 10 (biometric HITL) |
| Article 15 | Accuracy, robustness, cybersecurity | Layer 3b (skill contract enforcement, anti-rot flush) |
| Articles 43–46 | Conformity assessment | Agent certification lifecycle |

---

## 8. MEF as a Category-Defining Standard

### Competitive Landscape (Q2 2026)

| Framework | Strengths | What MEF Adds |
|---|---|---|
| Microsoft Agent Governance Toolkit | Azure IAM integration, policy binding | Multi-layer semantic/behavioural analysis (L4–7), PQC identity |
| GaaS (Gaurav et al., 2025) | Modular policy enforcement | Production implementation, path-dependent evaluation, 1,143-test validation |
| FINOS/Tetrate AI Governance | Open-source, financial services compliance | Internal reasoning/planning pathology detection (L4–6) |
| Kaptein et al. (2026) | Rigorous path-dependent formal framework | Production implementation predating the theoretical formalisation |
| Governance-in-the-Loop | Continuous policy enforcement loop | Cryptographic identity, PQC assurance, empirical validation at scale |

### Cicada: The Production Reference Implementation

Cicada is the production reference implementation of MEF — the software system in which MEF's ten-layer enforcement pipeline, post-quantum cryptographic identity architecture, agent certification lifecycle, and immutable audit trail are implemented as deployable, production-grade components.

Cicada's architecture is designed for deployment as a **governance sidecar** — a component that operates alongside agent systems without requiring modification to the agents' internal architecture or model weights.

**Verified codebase statistics (12 June 2026):**

| Component | Language | Lines of Code |
|---|---|---:|
| Sentry Gateway | Go | 36,025 |
| Core API | PHP | 22,689 |
| Operator Dashboard + Portals | TypeScript/TSX | 25,529 |
| Verification Swarm + Saga + SDK | Python | 10,555 |
| Aegis + Sentinel Mobile | Dart | 6,798 |
| **Total** | | **101,596** |

---

## References

- Boston Consulting Group. (2022). Enterprise AI Agent Deployment Report.
- European Union. (2021). Proposal for a Regulation laying down harmonised rules on Artificial Intelligence (AI Act).
- Regulation (EU) 2024/1689 — Artificial Intelligence Act.
- Kaptein, M., Khan, V.-J., & Podstavnychy, A. (2026). Runtime governance for AI agents: Policies on paths. arXiv:2603.16586.
- Mazzocchetti, A. M. (2026). Cryptographic runtime governance for autonomous AI systems: The Aegis architecture. DOI: 10.2139/ssrn.6418638.
- DeRudder. (2026). Computable Trust Architecture: A Formal Framework for Runtime AI Governance. DOI: 10.2139/ssrn.6583738.
- Emerson. (2026). THEMIS-xAI: A Unified Architecture for Explainable AI Governance. DOI: 10.2139/ssrn.6390878.
- Marín, G. & Chaudhary, J. (2026). Governing What You Cannot Observe: Adaptive Runtime Governance. arXiv:2604.24686.
- Sawaf, K. (2026). The Discrete Judgment Intermediate: An Externalization Infrastructure for AI Governance. University of Edinburgh Preprint.
- World Economic Forum. (2025). AI Agents in Action: Foundations for Evaluation and Governance.
- OWASP. Top 10 for Large Language Model Applications.
- NIST. AI Risk Management Framework (AI RMF 1.0). NIST AI 100-1.

---

*Matthews Enforcement Framework © 2026 Affinity Ops Ltd. All rights reserved.*
