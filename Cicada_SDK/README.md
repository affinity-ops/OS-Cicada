# Cicada SDK — Governance-First Agent Development

Build AI agents that are enterprise-compliant **from the first line of code**.

Cicada SDK does not replace your agent framework. It wraps your existing tools — LangChain, CrewAI, AutoGen, raw Python, raw Node.js — in cryptographic identity, deterministic authorization, and immutable audit. You write your agent. Cicada makes it enterprise-ready.

---

## Quick Start

### Python

```bash
pip install cicada-guard
cicada scaffold --framework=langchain --tools=stripe,slack --risk-level=high
```

### Node.js

```bash
npm install @cicada/sdk
```

### What You Get

```
your-agent/
├── cicada.yaml          ← Governance policy (the critical artifact)
├── agent.py             ← Agent code with Cicada SDK imports
├── .env.template        ← Gateway URL, session token, API keys
└── README.md            ← Integration guide
```

---

## The Critical Artifact: `cicada.yaml`

Every scaffolded agent is governed by a `cicada.yaml` file — a declarative policy-as-code file consumed by the Sentry Gateway:

```yaml
apiVersion: cicada/v1
kind: AgentPolicy

identity:
  name: "billing-agent"
  type: autonomous
  role: processor
  owner: finance@acme.com
  criticality: high

tools:
  - name: stripe-api
    url_patterns: ["https://api.stripe.com/v1/*"]
    methods: [GET, POST]
    destructive: false

enforcement:
  velocity:
    max_writes_per_minute: 10
  hitl:
    enabled: true
    auto_deny_on_timeout: true
  shadow_mode: false

provenance:
  content_tagging: true
  audit_retention_days: 730
```

---

## SDK Architecture

```
Your Agent Code
     ↓
Cicada SDK (Python/Node.js)
     ↓ (Ed25519 JWT + X-Cicada-* headers)
Sentry Gateway (7-layer enforcement)
     ↓
Target API (Stripe, Slack, etc.)
     ↓
Action Ledger (PostgreSQL — immutable audit)
     ↓
Operator Dashboard (real-time visibility)
```

**What the SDK does:**
- Authenticates with Ed25519 session tokens
- Routes all HTTP calls through the Sentry Gateway
- Injects `X-Cicada-Content-Provenance` headers for trust-level-aware scanning
- Tags retrieved content for elevated IPI scan sensitivity
- Handles HITL 202 responses (action suspended for human approval)
- Logs enforcement decisions

**What the SDK does NOT do:**
- Replace your LLM provider
- Replace your agent framework
- Store your data
- Make decisions — it enforces policy

---

## CLI Commands

| Command | What It Does |
|---------|-------------|
| `cicada scaffold` | Generate a Cicada-compliant agent project |
| `cicada validate` | Lint `cicada.yaml` against the JSON Schema |
| `cicada register` | Register an agent with the Core API |
| `cicada test` | Spin up a local Shadow Mode gateway |
| `cicada status` | Check agent trust score and violations |

### Scaffold Examples

```bash
# LangChain financial agent with Stripe tools and HITL
cicada scaffold --framework=langchain --tools=stripe --risk-level=high --hitl

# CrewAI research team with web scraping
cicada scaffold --framework=crewai --tools=search --risk-level=medium

# DevOps agent with shell access (mandatory HITL auto-enabled)
cicada scaffold --framework=python --tools=shell,github --destructive

# Node.js notification agent
cicada scaffold --framework=node --tools=sendgrid,slack --risk-level=low

# AutoGen multi-agent orchestrator
cicada scaffold --framework=autogen --risk-level=high --hitl
```

---

## Starter Templates

| Template | Framework | Risk Level | Key Features |
|----------|-----------|-----------|-------------|
| `langchain-financial` | LangChain | High | Stripe tools, HITL mandatory, PCI-DSS |
| `crewai-research` | CrewAI | Medium | Web scraping, content provenance tagging |
| `python-devops` | Raw Python | Critical | Shell access, destructive ops, mandatory HITL |
| `node-notifications` | Node.js | Low | SendGrid/Slack, velocity-limited |
| `autogen-orchestrator` | AutoGen | High | Multi-agent coordination, elevated limits |

---

## Content Provenance (IPI Defence)

The SDK includes provenance tagging helpers for defending against Indirect Prompt Injection:

```python
from cicada_guard.provenance import tag_retrieved, tag_tool_result

# Tag content retrieved from an external source
content, tag = tag_retrieved(scraped_html, source_url="https://example.com")
# The Gateway will apply elevated scan sensitivity to this content

# Tag content from a tool/function call
result, tag = tag_tool_result(api_response, tool_name="search-api")
```

Content tagged as `retrieved` or `tool_result` triggers **lower blocking thresholds** at the Gateway — a medium-confidence injection pattern in a retrieved document is blocked, whereas the same pattern in developer-authored content is logged but allowed.

---

## Framework Adapters

### LangChain

```python
from cicada_guard.adapters.langchain import CicadaToolWrapper, CicadaCallbackHandler

# Wrap LangChain tools for Cicada enforcement
wrapped_tools = [CicadaToolWrapper(tool, client) for tool in tools]

# Add Cicada callback for audit logging
agent = AgentExecutor(tools=wrapped_tools, callbacks=[CicadaCallbackHandler(client)])
```

### CrewAI

```python
from cicada_guard.adapters.crewai import CicadaCrewTool, CicadaWebScrapeTool

# Create Cicada-governed tools
search = CicadaCrewTool(name="search", client=client, target_url="https://api.search.com/v1/search?q={query}")
scraper = CicadaWebScrapeTool(client=client)  # Auto-tags as 'retrieved' provenance
```

---

## Directory Structure

```
Cicada_SDK/
├── schema/
│   └── cicada-policy-v1.json     ← JSON Schema (API contract)
├── python/
│   ├── cicada_guard/
│   │   ├── __init__.py
│   │   ├── client.py             ← Core SDK client
│   │   ├── policy.py             ← cicada.yaml parser
│   │   ├── provenance.py         ← Content provenance helpers
│   │   └── adapters/
│   │       ├── langchain.py      ← LangChain integration
│   │       └── crewai.py         ← CrewAI integration
│   └── pyproject.toml            ← PyPI packaging
├── node/
│   ├── src/
│   │   ├── index.js              ← Entry point
│   │   ├── client.js             ← Core client (native fetch)
│   │   └── policy.js             ← cicada.yaml parser
│   └── package.json              ← npm packaging
├── cli/
│   └── cicada_cli.py             ← CLI tool
└── templates/
    ├── langchain-financial/
    ├── crewai-research/
    ├── python-devops/
    ├── node-notifications/
    └── autogen-orchestrator/
```
