# Cicada Developer Portal — Screen Guide

The Developer Portal (port 3001) is the customer-facing interface for AI developers who have registered their agents on the Cicada platform. This guide explains every screen, what the data on it means, and what action to take.

---

## Public Pages (no login required)

---

### Home `/`
**What it shows:** The platform landing page. Hero headline, value proposition, a three-step "how it works" explainer (Register → Get EVAR → Route traffic), and a call to action to sign up.

**Purpose:** The first thing a prospective customer sees. Explains Cicada's security model without requiring technical knowledge.

---

### Pricing `/pricing`
**What it shows:** Three subscription tiers with feature comparisons.

| Tier | Best for | Key limits |
|------|---------|-----------|
| Starter | Individual developers, prototypes | 1 agent, 10k calls/month |
| Professional | Small teams, production workloads | 10 agents, 500k calls/month |
| Enterprise | Organisations, compliance requirements | Unlimited agents, SLA, dedicated support |

**What the data means:** All plans include the core EVAR identity system, Verification Swarm scoring, and immutable ledger. Higher tiers unlock HITL controls, fine-grained resource policies, and the Aegis AI assistant integration.

---

### Documentation `/docs`
**What it shows:** Static technical documentation covering:
- How to obtain and use an EVAR token
- Scope reference (what each scope entitlement allows)
- Example cURL requests for the Sentry Gateway
- Error codes and what they mean

**Purpose:** A developer's reference manual. Bookmark this page — it is the authoritative source for integration questions.

---

### Sign In `/login`
**What it shows:** OAuth sign-in with GitHub and Google. Clicking either button initiates the OAuth flow.

**What happens after sign-in:** The OAuth callback page (`/auth/callback`) extracts the token from the URL fragment and stores it in `localStorage` as `cicada_token`. You are then redirected to your portal dashboard.

---

## Authenticated Portal Pages

All pages under `/portal` require a valid `cicada_token` in localStorage. If you are redirected to `/login`, your session has expired — sign in again.

---

### Dashboard `/(portal)/dashboard`
**What it shows:** Your account at a glance. Three KPI cards: total registered agents, total approved calls this billing period, and total certifications (agents that have completed full verification). Below the KPIs: quick links to register a new agent, view recent traffic, and manage billing.

**What the data means:**
- **Total agents** — all agents you have registered, regardless of status
- **Approved calls** — calls that passed all checks and were forwarded to your target API. This is what you are billed on.
- **Certifications** — agents that have moved from `unverified` to `nominal` trust tier based on their call history

**When to act:** If approved calls are lower than expected, check your outbound traffic for blocked events. If certifications are 0, your agents are new and have not yet built a history.

---

### Agent Registry `/(portal)/agents`
**What it shows:** All agents registered under your account. Filter tabs: All, Active, Pending, Revoked. Each agent card shows its short ID, trust tier, registration date, and active scope entitlements.

**What the data means:**
- **Active** — agent has an EVAR and is making calls
- **Pending** — registration is complete but the agent has not yet made a call
- **Revoked** — the agent's `revoked_at` is set. It cannot make calls. This may have been triggered by you, by the circuit breaker, or by the Cicada operator.

**When to act:** A revoked agent you did not expect means the circuit breaker tripped or the operator intervened. Click the agent to see its full event history and understand why. Contact support if you believe the revocation was in error.

---

### Register Agent `/(portal)/agents/register`
**What it shows:** A six-step wizard to register a new AI agent and receive its EVAR token.

**Step by step:**

**Step 1 — Agent Identity**
Give your agent a name and describe what it does. This is for your own reference — it appears in your agent list.

**Step 2 — Architecture**
Select the agent's role:
- **Autonomous** — operates independently. Highest scrutiny; requires swarm confidence ≥ 0.8 to admit.
- **Orchestrator** — can spawn and direct sub-agents.
- **Sub-agent** — can only act when invoked by a declared orchestrator. You must specify the orchestrator agent ID.
- **Peer** — lateral communication with other certified agents.
- **Tool Executor** — passive; only executes tools when called. Cannot call other agents.

**Step 3 — Scopes**
Select exactly the permissions your agent needs. Only request what is necessary.
- `proxy:chat` — read-only LLM interactions (completions, embeddings)
- `proxy:read` — read operations on external APIs
- `proxy:write` — write operations (create, update records)
- `proxy:transact` — financial or payment operations
- `proxy:admin` — administrative operations on external systems

**Step 4 — Failure Handling**
Specify how your agent should behave when a call is blocked. Options: retry with backoff, fall back to a safe default, or stop and alert.

**Step 5 — Security Settings**
- **HITL (Human in the Loop)** — enable this if you want a human to approve `proxy:write` or `proxy:transact` calls before they execute. You must provide a webhook URL that Cicada will POST to for approval. The agent waits up to 60 seconds for a `{"approved": true}` response.
- **Declare tools** — list the specific tool identifiers your agent will call (e.g. `stripe:create_charge`, `sendgrid:send_email`). This enables fine-grained auditing.

**Step 6 — API Key**
Enter your AI provider API key (OpenAI, Anthropic, etc.). This is encrypted immediately using your tenant key and stored in the vault. Cicada never stores it in plain text.

**After completing the wizard:** Your agent receives an EVAR token — a long JWT string starting with `eyJ`. Store this securely. Pass it as the `X-Cicada-EVAR` header when routing calls through the Gateway. You will not be shown it again (you can regenerate it if lost).

---

### Resource Policies `/(portal)/agents/[id]/policies`
**What it shows:** Fine-grained access control rules for a specific agent. Each policy binds a URL pattern to a set of allowed HTTP methods.

**What the data means:** Resource policies add a runtime check on top of scopes. An agent with `proxy:write` scope can only call the specific URLs you list here — nothing else. Example:
- Pattern: `https://api.stripe.com/v1/charges*`
- Methods: `POST`

This means the agent can create Stripe charges but cannot list them, refund them, or call any other Stripe endpoint.

**When to act:** Add a resource policy for every external API your agent calls. This is the difference between "can write to anything" and "can write to exactly this endpoint." Auditors and insurance underwriters look favourably on narrow resource policies.

---

### Outbound Traffic `/(portal)/traffic/outbound`
**What it shows:** Every call your agents made to external APIs, in reverse chronological order. Each row shows the agent, the target URL, the status (approved/blocked/shadow), the confidence score, and the timestamp.

**What the data means:**
- **Approved** — call was forwarded and presumably received a response
- **Blocked** — call was rejected. Click the row to see which policy was violated.
- **Shadow sandbox** — call was suspicious. Cicada returned a simulated response. Your agent believed it succeeded, but the call was not actually made.
- **Confidence score** — the Verification Swarm's assessment of this specific call. Below 40% is flagged.

**When to act:** If you see unexpected blocked or shadow calls, open your agent in the registry and review its biography. Check whether your agent is calling URLs you did not intend, or whether your scope entitlements need updating.

---

### Inbound Traffic `/(portal)/traffic/inbound`
**What it shows:** Validation events from the Sentry Gateway — records of other agents or systems that attempted to present your agent's EVAR token, or calls that arrived at the Gateway claiming to be your agent.

**What the data means:** Inbound traffic is the view from the other side. If you see events here from IPs or agents you do not recognise, someone may be attempting to replay your EVAR token.

**When to act:** Any inbound event from an unrecognised source should be treated as a potential token theft. Regenerate your EVAR immediately and contact support.

---

### Transactions `/(portal)/transactions`
**What it shows:** A complete financial ledger — every call that involved a `proxy:transact` scope action. Includes search, status filtering, and date range selection.

**What the data means:** This is your proof-of-execution record for any financial operations your agent performed. Each row includes the trace ID, which links to the full pipeline trace — the cryptographic evidence that the call was made legitimately.

**When to act:** Use this page for financial reconciliation. If a transaction your agent made is disputed, the trace ID here is your evidence that the call was authorised and certified by the platform.

---

### Company Profile `/(portal)/account/company`
**What it shows:** Your organisation's name, contact details, and verified identity information. Editable fields for name, address, and primary contact.

**What the data means:** This information appears in the Cicada operator's CRM and is used for billing, compliance records, and support communication. The verified identity badge means Cicada has confirmed at least one identity signal (OAuth provider, domain verification, or manual review).

---

### Billing & Plan `/(portal)/account/billing`
**What it shows:** Your current plan, usage in the current billing period, and plan comparison cards for upgrading or downgrading.

**What the data means:**
- **Current period calls** — total calls made by all your agents this month. Blocked calls do not count toward your bill.
- **Approved calls** — calls that were forwarded. This is the billable metric.

**When to act:** Upgrade before you hit your plan limit — calls over the limit are queued, not dropped, but this adds latency. If you consistently use less than 20% of your plan, downgrading saves cost.

---

## Understanding Your EVAR Token

Your EVAR token is an Ed25519-signed JWT. It looks like:

```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhZ2VudF9pZCI6Ii4uLiJ9.<signature>
```

It contains:
- `agent_id` — your agent's unique identifier
- `tenant_id` — your company's identifier
- `scopes` — the entitlements declared at registration
- `iat` — issued-at timestamp

**How to use it:** Pass it as a header on every call routed through the Gateway:
```
X-Cicada-EVAR: eyJ...
X-Cicada-Target-URL: https://api.openai.com/v1/chat/completions
X-Cicada-LLM-Key: sk-...
```

**Keep it secret.** Anyone with your EVAR can make calls in your agent's name until it is revoked. Store it in an environment variable, never in source code.

---

## What Happens When Your Agent Is Blocked

When a call is blocked, the Gateway returns:

```json
{
  "status": "blocked",
  "reason": "scope_violation",
  "trace_id": "abc-123-..."
}
```

The `trace_id` links to the full pipeline trace in your portal. Common reasons:

| Reason | Meaning | Fix |
|--------|---------|-----|
| `scope_violation` | Agent called an action outside its declared scopes | Add the required scope at registration |
| `cross_agent_context_contamination` | Content from another agent appeared in this request | Review your agent's context management |
| `pii_in_response` | PII detected in the payload | Scrub PII before passing data to your agent |
| `role_violation` | Sub-agent called without a certified orchestrator | Check your orchestrator's EVAR is valid |
| `circuit_breaker_trip` | Too many low-confidence calls triggered auto-revocation | Review call patterns; contact support to reinstate |
| `token_revoked` | EVAR has been revoked | Regenerate your EVAR via the agent registry |

---

## Support

If you believe a block was incorrect, open the affected trace in Request Inspector and use the "Ask Aegis" button to get an explanation. If you still believe it is an error, contact support with the trace ID.
