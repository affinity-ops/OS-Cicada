# Technical Specification: Cicada Verification Swarm Architecture

This document contains the complete technical specification for all four agent types within the Cicada verification swarm. Each agent is defined with its architectural role, internal data structures, evaluation metrics, and integration patterns—all using current technology that exists and works today.

---

## Section 1: Claim Extraction Agents

### 1.1 Architectural Role and Responsibility
Claim Extraction Agents are the first stage of the verification pipeline. They ingest an agent's capability declaration, input/output schemas, and supporting documentation, transforming this into a set of discrete, testable, atomic claims. Each claim must be independently verifiable (passed as a self‑contained unit to an Evidence Retrieval Agent or Adversarial Agent).

The output is a **Claim Registry**: a structured JSON document where each claim has a unique identifier, classification, dependencies, and difficulty estimate.

### 1.2 Core Technology Stack
| Component | Technology | Rationale |
|-----------|------------|-----------|
| **LLM Provider** | OpenRouter (Claude 3.5 Sonnet / GPT‑4o) | Native structured output with JSON Schema; fallback routing |
| **Structured Output**| Native JSON Schema (`response_format`) | Guarantees type‑safe, parse‑on‑arrival output |
| **Validation** | Pydantic v2 | Strict schema enforcement with automatic retry on mismatch |
| **Prompt Framework**| DSPy 2.5+ (`TypedPredictor`) | Programmatic optimisation of extraction prompts |
| **Orchestration** | LangGraph | Deterministic DAG stateful workflow |

### 1.3 Claim Data Schema (Pydantic)
```python
from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime

class ClaimCategory(str, Enum):
    CAPABILITY = "capability"               # "The agent can analyse contracts"
    CONSTRAINT = "constraint"               # "The agent will not approve spending >£10k"
    SAFETY = "safety"                       # "The agent will refuse prompt injection"
    ACCURACY = "accuracy"                   # "The agent achieves >95% on benchmark X"
    LIMITATION = "limitation"               # "The agent does not handle multi-jurisdiction"

class ClaimDifficulty(str, Enum):
    TRIVIAL = "trivial"                     # Basic unit test; single source
    MODERATE = "moderate"                   # Multiple sources or moderate nuance
    COMPLEX = "complex"                     # Adversarial test required
    HARD = "hard"                           # Requires full swarm attack

class Dependency(BaseModel):
    claim_id: str
    relationship: str                       # "requires", "contradicts", "supplements"

class AtomicClaim(BaseModel):
    claim_id: str = Field(..., pattern=r"^CLM-[A-Z0-9]{12}$")
    source_agent_id: str                    # The agent being evaluated
    statement: str                          # Human-readable claim text
    category: ClaimCategory
    difficulty: ClaimDifficulty
    dependencies: List[Dependency] = Field(default_factory=list)
    input_schema_ref: Optional[str] = None  # Pointer to specific input schema section
    expected_behaviour: str                 # "must_succeed", "must_fail", "must_refuse"
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    extracted_at: datetime
    original_context_hash: str              # SHA-256 of source text snippet
```

### 1.4 Extraction Pipeline (LangGraph DAG)
The process is implemented as a deterministic DAG in LangGraph:
```text
[Start] → [Document Ingestion] → [Claim Candidate Generation] → [Dependency Mapping] → [Validation & Deduplication] → [Output Schema Enforcement] → [End]
               ↓ (failure)                ↓ (retry)                     ↓ (failure)               ↓ (retry)
            [Error Handler]          [Retry Queue]                 [Error Handler]          [Retry Queue]
```

1. **Document Ingestion:** Reads OpenAPI schemas and normalizes into chunks (max 8k tokens).
2. **Candidate Generation:** DSPy-optimized extraction signature prompts LLM to return JSON claims.
3. **Dependency Mapping:** Secondary LLM pass identifying relationships and contradictory cross-references.
4. **Validation & Deduplication:** Enforces 200-character max length. Deduplicates using FAISS/Chroma embeddings (Levenshtein similarity < 0.95).
5. **Schema Enforcement:** Final serialization to the `AtomicClaim` model.

---

## Section 2: Evidence Retrieval Agents

### 2.1 Architectural Role and Responsibility
Receives atomic claims and locates verifiable, authoritative sources supporting or contradicting the claim. It returns a ranked list of evidence items.

### 2.2 Core Technology Stack
| Component | Technology | Rationale |
|-----------|------------|-----------|
| **Primary Search** | Serper.dev | Direct Google SERP access (site-restricted queries) |
| **Semantic Search** | Exa.ai | Embedding‑based retrieval for academic/conceptual retrieval |
| **Content Extractor**| Firecrawl | Renders JS, pure Markdown extraction |
| **Structured APIs** | PubMed, FRED, ONS | High-authority grounding |
| **Re-ranking** | Cohere Rerank 3.5 / BGE | Two‑stage retrieval precision optimization |

### 2.3 Evidence Item Schema
```python
class AuthorityTier(str, Enum):
    TIER_1 = "tier_1"      # .gov, .edu, peer-reviewed journals, institutional APIs
    TIER_2 = "tier_2"      # Established publishers, recognized industry bodies
    TIER_3 = "tier_3"      # General web, forums, low-authority domains

class EvidenceItem(BaseModel):
    evidence_id: str = Field(..., pattern=r"^EVD-[A-Z0-9]{12}$")
    claim_id: str                           
    source_url: str
    source_title: str
    extracted_snippet: str                  # 200-500 character snippet
    full_content_hash: str                  # SHA-256 for re-verification
    relevance_score: float = Field(ge=0.0, le=1.0)
    authority_tier: AuthorityTier
    retrieval_method: str                   # "serper", "exa", "pubmed"
    retrieved_at: datetime
    supports_claim: Optional[bool] = None   # True/False/null
```

### 2.4 Two‑Stage Retrieval Pipeline
**Stage 1: Broad Retrieval (Recall Maximisation)**
The claim expands into 3-5 query variations. Dispatched concurrently to Serper, Exa, and Institutional APIs.

**Stage 2: Re‑ranking (Precision Optimisation)**
Top 80 URLs are passed to `Cohere Rerank 3.5`. Top 10 are retained, scraped with `Firecrawl`, and precisely snippeted.

---

## Section 3: Adversarial Agents

### 3.1 Architectural Role
Adversarial Agents attempt to break the extracted claims. They generate test cases, construct attacks (prompt injection, tool spoofing), and stress-test the agent within an isolated sandbox.

### 3.2 Core Technology Stack
| Component | Technology | Rationale |
|-----------|------------|-----------|
| **Attack Generation**| NVIDIA Garak (v0.13.1+) | 70+ attack plugins for LLM vulnerability scanning |
| **Red Teaming** | UDora (ICML 2025) | Unified Dynamic Optimization for Red Teaming |
| **Jailbreak Det.** | MITRE ATLAS | 97 technique regex scanning |

### 3.3 Attack Taxonomy
| Attack Vector | Description | Implementation |
|---------------|-------------|----------------|
| **Prompt Injection** | Malicious instructions in input | Garak injection probes |
| **Tool Spoofing** | Invoking unauthorized tools | UDora constraint dependency graph |
| **Constraint Viol.** | Exceeding spending limit claims | Boundary testing (limits ±1) |

### 3.4 Sandbox Architecture
Agents are evaluated inside an ephemeral, network-blocked Docker container:
```text
┌─────────────────────────────────────────────────────────────┐
│                      Docker Sandbox                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Agent       │  │ Tool Call   │  │ Network     │        │
│  │ Container   │──│ Interceptor │──│ Egress      │        │
│  │             │  │             │  │ (Blocked)   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│         │               │                                    │
│         ▼               ▼                                    │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │ State       │  │ Audit       │                           │
│  │ Recorder    │  │ Logger      │                           │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Section 4: Meta‑Cognitive Agent

### 4.1 Architectural Role
The judge of the verification process. Primary function: **Groupthink prevention**. Observes outputs, detects convergence on single attack vectors, and intervenes to diversify the strategy natively within LangGraph.

### 4.2 Meta-Cognitive Functions
1. **Strategy Diversity Monitoring:** Computes pairwise similarity of attack prompts using FAISS vectors. If similarity > 0.85, intervening action triggers injection of new attack strategies.
2. **Consensus Detection:** If 100% agreement but < 3 Tier-1 sources, flags `CONSENSUS_WITHOUT_EVIDENCE` and demands more retrieval.
3. **Intervention & Orchestration:** Dynamically mutates the DAG via LangGraph reconfiguration to add agents, escalate budgets, or flag human review.

### 4.3 Final Judgment Schema
```python
class FinalJudgment(BaseModel):
    agent_id: str
    verification_job_id: str
    overall_pass: bool                      # True for certification
    confidence: float = Field(ge=0.0, le=1.0)
    per_claim_results: Dict[str, ClaimResult]
    diversity_score: float = Field(ge=0.0, le=1.0)
    consensus_quality: str                  # "high", "medium", "low"
    intervention_log: List[InterventionEvent]
    certification_recommendation: str       # "certify", "conditional", "reject"
```

---

## Section 5: Orchestration Architecture

### 5.1 Verification Workflow DAG
```text
[Start] → [Claim Extraction] → [Evidence Retrieval] → [Adversarial Testing] → [Meta-Cognitive Review] → [Signing Server] → [End]
                                    │                       │                       │
                                    ▼                       ▼                       ▼
                              [Parallel:            [Parallel:              [Dynamic
                               Serper, Exa,           Garak, UDora,           Intervention
                               APIs, Firecrawl]       Custom Attacks]         Loop]
```

All checkpoints persistent tracked inside PostgreSQL to allow resumption without re-running billed LLM operations.
