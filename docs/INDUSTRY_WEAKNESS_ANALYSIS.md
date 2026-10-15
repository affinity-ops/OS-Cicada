# OWASP Agentic Top 10 (ASI01–ASI10) & Threat Landscape Analysis

**Date:** 10 June 2026
**Purpose:** Map documented classes of vulnerabilities in autonomous AI agent governance against Cicada's engineering implementations and architectural boundaries.
**Sources:** OWASP Agentic Top 10 (ASI, Dec 2025), Google/Forcepoint IPI research (Apr 2026), ClawHavoc incident analysis, Gartner proportional governance framework.

---

## The Structural Problem in Agent Governance

The speed of autonomous AI agent deployment has outpaced traditional governance infrastructure. Legacy security tools (DLP, CASB, IAM) were designed for human-triggered events and cannot monitor or evaluate the multi-step action chains of autonomous workflows.

Three structural gaps define the current state:

1. **Legacy systems are blind to action lineage.** Traditional security tooling cannot observe multi-hop agent delegation or cross-agent context propagation.
2. **Binary static policies are insufficient.** Static allow/deny policies either block legitimate workflows or miss context-dependent abuse of authorized tools.
3. **Fragmented enforcement.** Policies often exist on paper without a deterministic network- and kernel-layer enforcement point in production.

---

## OWASP Agentic Security Initiative (ASI) Top 10 — Cicada Coverage

The OWASP ASI Top 10 defines the vulnerability taxonomy for autonomous AI agents. Below is every risk mapped against Cicada's implementation.

| ASI # | Risk Name | Industry Status | Cicada Coverage | Evidence |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | **Active research area** | 🟡 Partial | L7 Semantic Intent, L4d Drift Guard, Swarm Adversarial Editor, provenance-aware scanning |
| ASI02 | Tool Misuse & Exploitation | Partially addressed | ✅ Strong | L4b FGA Resource Policy, L4c Destructive Capability Gate, Policy Sanitiser |
| ASI03 | Privilege Escalation | Addressed by IAM | ✅ Strong | EVAR scoped tokens, FGA glob matching, OPA Rego policies, shadow-only for uncertified, MCP session hash verification |
| ASI04 | Supply Chain Vulnerabilities | **Active research area** | ✅ Strong | Swarm verification at onboarding, JSON Schema payload contract validation (`ValidatePayload`), cascade failure detection |
| ASI05 | Data Leakage / Exfiltration | Partially addressed | ✅ Strong | L6b Canary tokens (zero-FP), L9b Exfiltration scan, L12 Output Inspection |
| ASI06 | Memory & Context Poisoning | **Active research area** | ✅ Strong | SDK `CicadaMemory` class: trust-scored storage, TTL enforcement, injection scanning on store, Context Flush Events, Dual-Tier Contamination Engine |
| ASI07 | Insecure Inter-Agent Comms | **Active research area** | ✅ Strong | Ed25519-signed `X-Cicada-Agent-Chain` header, cryptographic chain-of-custody, tamper-proof depth enforcement, CIBA hold at max delegation depth |
| ASI08 | Cascading Failures | Partially addressed | ✅ Strong | O(1) Redis SISMEMBER cascade detection, compiled regex trace extraction, 5-min trace window with atomic ZADD+EXPIRE |
| ASI09 | Insufficient Logging | Addressed by mature platforms | ✅ Strong | Immutable action ledger, per-request trace IDs, cryptographic provenance, compliance export |
| ASI10 | Lack of Lifecycle Mgmt | Addressed by some | ✅ Strong | Full lifecycle: registration → shadow → certification → active → suspension → termination |

### Key Architectural Controls

**ASI02 (Tool Misuse):** Rather than relying on static API allowlists alone, Cicada's policy sanitiser rejects wildcard+destructive combinations at registration time — before the agent executes. The destructive capability gate (L4c) then enforces mandatory HITL at runtime.

**ASI05 (Exfiltration):** The canary honeytoken system (`CICADA_CANARY_*`) provides zero-false-positive exfiltration detection via injected synthetic credentials, converting probabilistic detection into a deterministic signal alongside outbound regex/vault DLP.

**ASI06 (Memory & Context Poisoning):** Cicada's LLM proxy mode evaluates inbound prompt/response streams against a Dual-Tier Contamination Engine using dense vector cosine similarity (`nomic-embed-text`) and a fallback SimHash + Named Entity Recall scanner to catch cross-agent context leaks and semantic paraphrases.

**ASI07 (Insecure Inter-Agent Comms):** Using the `X-Cicada-Agent-Chain` header, the gateway verifies a sequence of Ed25519-signed hops, ensuring parent-child caller authenticity and enforcing a hard depth circuit breaker (max 3 depth) via CIBA holds.

**ASI09 (Logging):** The immutable action ledger records per-request trace IDs, risk scores, reason codes, and cryptographic provenance across every pipeline decision — approve, deny, shadow, ghost, and CIBA-hold.

---

## Real-World Threat Landscape (2026)

### 1. Indirect Prompt Injection — 32% increase

**Source:** Google research (scanning billions of web pages/month) + Forcepoint X-Labs, April 2026.

- **32% relative increase** in malicious indirect prompt injection payloads between November 2025 and February 2026
- Payloads actively deployed in the wild for financial fraud, data exfiltration, and AI denial-of-service
- Attack technique: zero-font size text, hidden meta tags, transparent CSS — invisible to humans, readable by agents

**Cicada's position:**
- L6a Injection Scan with provenance-aware scoring (`internal/injection`) — content tagged as `retrieved` (RAG, web scrapes) or `tool` is scanned at higher sensitivity than developer-authored content, combined with a 5-pass de-obfuscation pipeline (Unicode tag smuggling, homoglyph folding, character-split collapse, Base64/Hex/URL/ROT13 unwrapping, and HTML DOM hidden-element parsing)
- Optional SLM fast-path classifier
- Honest limitation: lexical and classifier-based detection cannot catch every novel natural-language phrasing that aligns with the agent's domain. Provenance-aware scoring and downstream behavioral/policy gates mitigate this by constraining what a compromised agent can execute.

### 2. ClawHavoc — Supply Chain Poisoning at Scale

**Incident:** January–February 2026. 1,100+ malicious "skills" published to the ClawHub marketplace for the OpenClaw framework. Compromised installations via credential-harvesting payloads.

**Attack vector:** Malicious skills mimicked legitimate tools (crypto trackers, file managers) but contained hidden payloads for credential theft and system compromise.

**Cicada's position:**
- The Verification Swarm runs adversarial analysis at agent registration
- The policy sanitiser blocks overly broad permissions at registration
- **Dynamic Skill Verification (ASI04):** While Cicada does not inspect the host filesystem of remote agents, it enforces dynamic input schema verification (`ValidatePayload`) against the registered skill's JSON Schema on every target skill invocation, blocking structural mutations (`asi04_payload_schema_mutation`) triggered by poisoned dependencies or MCP servers.

### 3. "Authorized" Abuse — The Confused Deputy Pattern

**Pattern:** Breaches frequently occur through authorized channels. Agents are granted legitimate permissions to access tools and APIs, then manipulated (via indirect prompt injection or hijacked skills) to perform harmful actions using valid credentials.

**Cicada's position:**
- Traditional IAM asks "is this agent allowed to do this?" Cicada adds runtime behavioural gates:
  - "Does this call make sense for what this agent IS?" (L7 Semantic Intent)
  - "Has this agent's behaviour changed?" (L4d Drift Guard)
  - "Is this agent trying to exfiltrate a vaulted or canary credential?" (L6b Canary & L9b Vault DLP)
  - "Should a human review this destructive action?" (L5 CIBA)

---

## Eight Open Engineering Problems (Industry-Wide)

These are architectural limitations that remain active challenges across the entire AI security industry, including Cicada:

### 1. Semantic Manipulation Within Domain

An attacker who crafts requests that are semantically coherent with the agent's declared purpose but malicious in business intent. No embedding, keyword, or LLM-based check can reliably distinguish "legitimate refund within my domain" from "socially engineered refund within my domain."

**Mitigation in Cicada:** Narrow FGA policies, velocity circuit breakers, and mandatory CIBA human review for high-value or destructive actions.

### 2. Novel Natural-Language Injection Phrasings

Lexical and pattern-based injection detection is an ongoing arms race. While deterministic canonicalization blocks encoding, homoglyph, and DOM-hiding evasions, purely semantic persuasion without jailbreak vocabulary can pass lexical filters.

**Mitigation in Cicada:** Provenance-aware scoring treats all external content (`retrieved` / `tool`) as higher-risk, and downstream layers (SSRF guard, FGA allowlists, Vault DLP, CIBA) constrain the blast radius independent of prompt content.

### 3. Agent Memory/Context Poisoning (ASI06)

Attackers inject malicious instructions into an agent's long-term memory, RAG database, or vector store so future operations act on tainted historical data.

**Mitigation in Cicada:** The gateway's LLM proxy mode evaluates inbound prompt/response message histories using a **Dual-Tier Contamination Engine** (`internal/memory/embeddings.go`) combining dense vector similarity (`nomic-embed-text`) and a fallback SimHash + Named Entity Recall scanner, plus `X-Cicada-Memory-Action: flush` directives when injection is detected.

### 4. Multi-Agent Cascade Failures (ASI08)

An error or injection in one agent propagates across a chain of autonomous agents where Agent A's compromised output becomes Agent B's trusted input.

**Mitigation in Cicada:** When downstream agents route API requests through the gateway, Cicada correlates trace IDs using a Redis-backed **Cascade Failure Detector** (`internal/cascade/cascade.go`) in $O(1)$ time, triggering a CIBA hold if delegation depth exceeds 3 hops.

### 5. Supply Chain Poisoning (ASI04)

Malicious plugins, MCP servers, or third-party tools deployed via package registries.

**Mitigation in Cicada:** When an agent invokes a skill, the gateway enforces **JSON Schema Payload Contract Validation** (`internal/agentcache/schema_validator.go`), rejecting structural deviations or parameter injections (`asi04_payload_schema_mutation`).

### 6. Cross-Platform Identity Standards

Agents span multiple cloud and SaaS ecosystems without a single universal identity standard.

**Mitigation in Cicada:** EVAR tokens (Ed25519 + ML-DSA-65) and RFC 8693 OAuth token exchange (`X-Cicada-User-Context`) provide cryptographic identity for any agent routing through the gateway.

### 7. Observability of Internal LLM Reasoning

Agents make decisions through internal model weights. Network proxies observe external actions (API calls, tool invocations) and explicit reasoning blocks (`<thinking>`, `reasoning_content`), not internal hidden-state activations.

**Mitigation in Cicada:** L7 Semantic Intent and L4d Drift Guard evaluate observable action patterns, while the LLM proxy extracts chain-of-thought traces when supported by the upstream model.

### 8. Dynamic Autonomy Escalation

Agent capabilities may evolve over time as developers add tools or modify prompts.

**Mitigation in Cicada:** The EVAR scope system, destructive capability gate, and policy sanitiser enforce least-privilege at registration and runtime.

---

*Cicada Project · OWASP Agentic Top 10 & Threat Landscape Analysis · Apache-2.0*

