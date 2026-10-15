# Technical Specification: Cicada Verified Agent Registry

**Document Information**
* **Document Title:** Cicada Verified Agent Registry – Technical Specification
* **Version:** 1.0
* **Date:** April 15, 2026
* **Status:** Draft for Review
* **Classification:** Confidential
* **Prepared For:** Patrick Matthews, Affinity Smart AI

---

## Executive Summary
The internet's identity infrastructure was built for humans, not autonomous agents. As AI agents increasingly execute transactions, negotiate contracts, and access APIs without human supervision, the industry lacks a universal mechanism to determine which agent is making a request, who is accountable for it, and what it is permitted to do. The result is a landscape where agents cannot reliably trust one another, enterprises cannot safely deploy autonomous systems, and regulators cannot enforce accountability.

The **Cicada Verified Agent Registry** solves this problem. It is a cryptographic Certificate Authority for autonomous AI agents—a secure, searchable directory of agents that have been aggressively audited and mathematically certified by the Cicada multi-agent verification swarm.

---

## 1. Due Diligence: The Existing Agent Registry Landscape
As of April 2026, the market contains no single standard for AI agent identity and verification. Instead, a fragmented landscape of protocols, standards, and proof‑of‑concept implementations has emerged.

### 1.1 Blockchain‑Based Decentralised Registries
* **ERC-8004:** Positions itself as a permissionless, no‑single‑company‑controlled alternative. Registers Identity, Reputation, and Validation on Ethereum.
* **ENSIP-25:** Verifies the association between an ENS name and an agent registered in ERC-8004.
* **BasedAgents / RelAI:** Cryptographic identity and reputation registries where agents build verifiable reputations through peer verification.

### 1.2 DNS‑Anchored Registries
* **GoDaddy ANS:** Anchors every agent identity to a DNS domain name via ACME verification. Issues tiered certificates (Bronze, Silver, Gold). Format: `Protocol://AgentID.Capability.Provider.vX.Y.Z.Extension`.

### 1.3 Federated Hardware‑Anchored Identity
* **IETF Agent Identity Registry (Draft):** Anchors identity to a hardware security component (TPM, secure enclave). Verifies that an agent runs on a specific physical device to provide Sybil resistance.

### 1.4 Payment‑Focused Agent Protocols
* **Visa's Trusted Agent Protocol:** Uses agent‑specific cryptographic signatures to identify trusted agents with commerce intent, distinguishing them from malicious bots.
* **PayPal AP2:** Uses cryptographically signed mandates (Cart Mandates, Intent Mandates) expressed as W3C Verifiable Credentials.

### 1.5 Metadata and "Know Your Agent" Standards
* **AgentFacts:** Defines a metadata standard enabling multi‑authority validation.
* **AAIP:** Standard format for delegating specific permissions via cryptographically signed delegations.

### Summary: The Landscape at a Glance
| Registry / Protocol | Identity | Reputation | Discovery | Active Verification |
|---|---|---|---|---|
| **ERC-8004** | On‑chain | On‑chain | Decentralised | ❌ None |
| **GoDaddy ANS** | DNS‑anchored | ❌ | ✅ | ❌ None |
| **IETF Registry**| Hardware-anchored| ❌ | ❌ | ❌ None |
| **Visa Protocol** | Crypto signatures | ❌ | ❌ | ❌ None |
| **Cicada Registry** | **EVAR-based** | **Swarm-attested** | **API-discoverable** | **✅ ACTIVE ADVERSARIAL SWARM** |

---

## 2. The Gap: What Every Existing Registry Misses
Every existing registry, protocol, and standard addresses some aspect of agent trust, but **none addresses the core problem of active verification before registration**.

1. **Identity Without Verification of Capability:** Knowing who an agent is or what hardware it runs on does not verify what the agent can actually do safely.
2. **Self‑Declaration Without Adversarial Validation:** Existing models check paperwork; they do not actively stress-test the agent's behavior.
3. **Registry Without Reputation Before Harm:** Reputation systems require the agent to operate (and potentially cause harm or "Fake Uber" scenarios) before a score is accumulated.

### The Core Innovation: Active Verification Before Registration
Cicada is the only system that closes this gap. Instead of relying on self‑declaration, Cicada actively tests the agent using its multi‑agent verification swarm:
1. Extracts capability claims.
2. Designs adversarial test cases specifically to break those claims.
3. Executes the agent against edge cases and prompt injections.
4. Issues a cryptographic certificate (CIC) only upon successful completion.

---

## 3. Cicada Architecture & Relationship

### 3.1 Relationship to Cicada Content Integrity Platform
The Cicada Verified Agent Registry is the logical extension of the Content Integrity Platform's verification infrastructure. 

| Component | Role in Content Platform | Role in Agent Registry |
|-----------|--------------------------|-------------------------|
| **Alignment Shield** | Pre‑generation source verification | Pre‑registration capability verification |
| **Adversarial Pass** | Stress‑tests documents for errors | Stress‑tests agent against adversarial inputs|
| **EVAR Identity** | Certified human author identity | Certified agent identity |
| **Signing Server**| Cryptographic document signatures | Cryptographic agent certificates |
| **Public Vault** | Stores verified documents | Stores agent certs & audit trails |

---

## 4. Technical Specification

### 4.1 Agent Identity Schema
Each registered agent receives an EVAR ID for Agents – a cryptographic identifier:
```json
{
  "agent_id": "evar:agent:7F3A9E2B-44C8-4D1A-B8F2-6C9E7D5A1F3B",
  "agent_name": "Legal-Compliance-Agent-v2",
  "developer_evar": "evar:human:EL4-9372-GT7",
  "domain_anchor": "com.example.legal-compliance",
  "capability_declarations": [
    {
      "capability": "contract_analysis",
      "input_schema": "https://schema.cicada.ai/contract/v1",
      "output_schema": "https://schema.cicada.ai/compliance-report/v1"
    }
  ],
  "benchmark_scores": {
    "adversarial_pass_rate": 0.97,
    "tool_use_accuracy": 0.94,
    "prompt_injection_defense": 0.99
  },
  "certificate_hash": "sha256:4a5b...",
  "issued_at": "2026-04-15T10:30:00Z",
  "expires_at": "2026-10-15T10:30:00Z",
  "revocation_status": "active"
}
```

### 4.2 Verification Swarm Architecture
1. **Claim Extraction Agents:** Parse capability boundaries from submitted schemas.
2. **Evidence Retrieval Agents:** Generate malicious inputs and boundary tests (e.g. malformed JSON, recursive prompt injection logic).
3. **Adversarial Agents:** Unbound red-team agents that actively attempt to spoof tool calls, violate spending limits, and bypass restrictions.
4. **Meta‑Cognitive Agent:** Acts as the judge, monitoring for test coverage gaps to prevent adversarial groupthink.

### 4.3 Governance Model
* **Tier 1: Centralised Registry Authority (Affinity Smart AI)** - Operates the verification swarm, sets benchmarks, and issues EVAR IDs. Centralization ensures strict accountability.
* **Tier 2: Open Verification Layer** - Third parties may run their own swarms against registered agents and cross-sign attestations to prevent vendor lock-in.

---

## 5. API Specifications

### 5.1 Registration API
`POST /v1/agent/register`
* **Purpose:** Submit an agent endpoint and capability manifest for Swarm testing.
* **Payload:** Agent endpoint, Human Developer EVAR ID, OpenAPI Schema.

### 5.2 Verification API (Real-Time A2A Commerce Check)
`GET /v1/agent/verify/{agent_id}`
* **Purpose:** Polled by Enterprise systems to verify an incoming agent.
* **Payload Returns:** Active status, CIC hash, capabilities, adversarial pass rates.

### 5.3 Revocation API
`POST /v1/agent/revoke`
* **Purpose:** Triggers immediate termination of an EVAR ID if an agent fails a post-registration continuous audit.

### 5.4 Discovery API
`GET /v1/agent/discover?capability={capability}&min_pass_rate={rate}`
* **Purpose:** Agent Marketplace lookup.

---

## 6. Security & Threat Model

| Threat | Cicada Mitigation |
|--------|-------------------|
| **Sybil Attack (Fake IDs)** | Each registration requires heavy adversarial swarm compute + Human accountability EVAR. |
| **Agent Spoofing** | Cryptographic certificate + API signature checks. |
| **Verification Evasion** | Continuous post‑registration monitoring and behavioural drift checks. |
| **Registry Compromise** | Append‑only Vault with SHA-256 hash chaining. No updates allowed. |

---

## 7. Conclusion
The market is not ready for this today. But the August 2026 EU AI Act deadline is approaching, and the agentic economy is growing at a compound rate that will make trust infrastructure a requirement, not an option, within 18 months. The organizations that adopt Cicada early will define the standards that the rest of the market will be forced to follow.
