# Cicada Operator Dashboard — Screen Guide

The Operator Dashboard (port 3000) is the administrative interface for the Cicada platform owner. It provides complete visibility across every registered agent, every tenant, and every security event. It is not accessible to customers — they use the Developer Portal (port 3001).

---

## Navigation Overview

The left sidebar is divided into three sections:
- **Core monitoring** — live platform state
- **Agent Admin** — audit, compliance, and threat analysis tools
- **Aegis AI Assistant** — conversational security intelligence

---

## Core Monitoring Pages

---

### Overview `/`
**What it shows:** The primary command view. A WebGL globe renders macro-cluster infrastructure geographically. KPI cards across the top show total registered agents, active tenants, verified agents, and quarantined agents — all live from the database.

**What the data means:**
- **Total agents** — every agent ever registered, regardless of status
- **Active tenants** — companies with at least one non-revoked agent
- **Verified agents** — agents whose trust tier is `nominal` or better
- **Quarantined** — agents with `revoked_at` set or trust tier `critical`

**When to act:** If quarantined count spikes unexpectedly, navigate to Agent Biographies or Rogue Registry to identify the cause.

---

### Security Monitor `/compute`
**What it shows:** A live feed of agent activity events as they hit the platform. Each event shows the agent ID, action type, status (approved/blocked/shadow), confidence score, and timestamp. New events appear at the top in real time.

**What the data means:**
- **Green row (approved)** — request passed all checks and was forwarded to the target API
- **Red row (blocked)** — request was rejected. The reason column shows which policy was violated.
- **Yellow row (shadow_sandbox)** — request was suspicious; routed to a sandboxed environment. The agent was not told it was blocked.
- **Confidence score** — the Verification Swarm's assessment. Below 40% is low confidence. A healthy agent should score above 70% consistently.

**When to act:** A run of red rows from a single agent warrants opening its Biography. A sudden drop in confidence scores across multiple agents may indicate a coordinated attack — check Threat Correlation.

---

### Request Inspector `/pipeline`
**What it shows:** The full 10-stage pipeline trace for any individual request. Select a trace from the scrollable list at the top, or navigate here directly from any "Trace" link in the platform. Each pipeline stage shows its pass/fail status, duration, and the specific data evaluated at that stage.

**What the data means:**
- Each of the 10 stages corresponds to a security check (identity, scope, role, FGA, HITL, swarm, memory, circuit breaker, ledger, decision).
- A red stage is where the request was stopped.
- The confidence score bar at the bottom shows how the swarm score evolved as the request moved through the pipeline.

**When to act:** Use this page to understand exactly why a specific request was blocked. The stage-level detail is the ground truth — use it when a developer disputes a block decision.

---

### Agent Registry `/nodes`
**What it shows:** Every registered agent on the platform, grouped by company. Each card shows the agent's trust tier, registration date, scope entitlements, and a link to its biography.

**What the data means:**
- **Trust tier badge colours:** Grey = unverified, Green = nominal, Amber = elevated, Red = critical
- **Scope entitlements** — the categories of action the agent is allowed to take (e.g. `proxy:chat`, `proxy:write`)

**When to act:** Filter by trust tier to quickly surface all elevated or critical agents. Use in combination with Behaviour Baselines.

---

### Security Policies `/security`
**What it shows:** The active policy ruleset that governs what agents can and cannot do. Rules are displayed with syntax highlighting. An exception management section allows temporary policy overrides with expiry dates.

**What the data means:** Policies are evaluated in order. The first matching rule wins. A rule can allow, block, or route to shadow sandbox. The test panel lets you run a hypothetical request against the current ruleset before committing a change.

**When to act:** When a legitimate agent is being incorrectly blocked, check whether a policy rule is too broad. Add an exception with a short TTL rather than modifying the core rule.

---

### Approved Agents `/registry`
**What it shows:** The subset of registered agents whose trust tier is `nominal` or above — the agents the platform actively trusts. Filterable by company and scope.

**What the data means:** An agent appears here only after passing initial verification. New agents start as `unverified` and are promoted automatically when their swarm scores are consistently high.

---

### API Keys `/vault`
**What it shows:** Encrypted API keys stored in the platform (BYOK — bring your own key model). Each entry shows the provider, masked key value, associated agent, and last rotation date.

**What the data means:** Cicada never stores keys in plain text. Keys are encrypted at rest using Laravel's Crypt facade with the `APP_KEY`. The Verification Swarm decrypts keys only at the moment they are needed for a request.

**When to act:** Rotate any key that has not been rotated in over 90 days. If a key appears here for a revoked agent, delete it.

---

### Activity Log `/logs`
**What it shows:** The complete action_ledger table — every event, approved or blocked, in reverse-chronological order. Filterable by status, agent ID, and date range. Exportable as CSV or JSON.

**What the data means:** This is the raw ledger. Every row is a real event that occurred on the platform. The `swarm_confidence_score` column shows the raw float value (0.0–1.0) from the Verification Swarm. The `policy_violations` column is a JSON array — if it is populated, the request was blocked for those specific reasons.

**When to act:** Use this page for raw investigation. For pattern analysis, use Threat Correlation or Behaviour Baselines instead.

---

### Rollback History `/sagas`
**What it shows:** The Saga Executor's record of compensating transactions — actions that were automatically reversed after a block decision. Each row shows the saga ID, the original action, the reversal status, and whether the HMAC verification passed.

**What the data means:** When an agent executes a multi-step workflow and one step is blocked, the Saga Executor fires a compensating call to undo the preceding steps. A `completed` status means the reversal succeeded. A `failed` status means the target API rejected the reversal — requires manual intervention.

**When to act:** Any `failed` saga requires manual follow-up. Contact the tenant whose agent triggered it and coordinate with the target API provider.

---

### Companies `/crm`
**What it shows:** Every company (tenant) registered on the platform. Each row shows the company name, plan tier, number of registered agents, number of blocked events, and account status.

**What the data means:**
- **Plan tier** — Starter, Professional, or Enterprise. Determines rate limits and feature access.
- **Agents** — total agents registered under this tenant
- **Blocked events** — total blocked calls across all this tenant's agents. A high number relative to total calls warrants investigation.

**When to act:** Click any company to open its detail page, which shows its agents, contacts, billing status, and full event history.

---

### Unmanaged Agents `/discovery`
**What it shows:** AI agents that have been detected making calls that bypass Cicada — agents operating without an EVAR token, or calls from IPs with no registered session. These are "shadow AI" instances.

**What the data means:** Every entry here is a potential security gap. The agent exists and is making calls, but it is not governed by the platform. It could be a developer testing without onboarding, a legacy integration, or a genuinely rogue process.

**When to act:** For each entry, choose one of three actions: Monitor (add to watchlist), Block (add IP/agent fingerprint to gateway deny list), or Invite (send the developer a registration link).

---

## Agent Admin Pages

---

### Rogue Registry `/agent-admin/rogue`
**What it shows:** Every event where the Gateway blocked an agent — all time, from the live database. Each row shows the agent, the action it attempted, the specific reason it was blocked, the target API, the risk score, and the exact timestamp.

**What the data means:**
- **Reason column** — the first policy violation from the `policy_violations` array. This is the primary reason the block fired.
- **Risk score** — the swarm confidence score displayed as a percentage. A low score (red) means the swarm was highly suspicious of this call.
- **View link** — opens the full pipeline trace for that event in the Request Inspector.

**When to act:** Look for repeated blocks on the same agent — that is a behavioural pattern, not a one-off. Cross-reference with Behaviour Baselines to see if the circuit breaker should have tripped.

---

### Audit & Export `/agent-admin/audit`
**What it shows:** A configurable export tool. Set a date range and event status filter, then download the matching ledger records as CSV or JSON.

**What the data means:** Every export contains: Trace ID, Agent ID, Action Type, Block Status, Target API, Risk Score, Policy Violations, and Timestamp. This is the data set required by SOC2 auditors, ISO27001 assessors, and insurance underwriters.

**When to act:** Run an export before any compliance review. Use the "Ask Aegis for Report" button to generate a narrative summary that interprets the raw data — suitable for presenting to a board or legal team.

---

### Agent Biographies `/agent-admin/biographies`
**What it shows:** A complete lifecycle record for any individual agent. Select an agent from the left panel to see its full event timeline: registration, every approved call, every block, and every policy violation — in chronological order.

**What the data means:** The timeline reads like a log of everything the agent has ever done on the platform. A biography with many green events and occasional amber blocks is a healthy agent. A biography dominated by red events is an agent in distress — either compromised, misconfigured, or actively malicious.

**When to act:** Open the biography of any agent flagged in Rogue Registry or Behaviour Baselines. The timeline shows whether the problematic behaviour is recent or longstanding. Use "Ask Aegis" to get a plain-English risk assessment for the specific agent.

---

### Alert Rules `/agent-admin/alerts`
**What it shows:** The notification routing configuration. Each rule maps a security event type to a notification channel (email, webhook, or Aegis automated response).

**What the data means:**
- **Email channel** — sends a notification to the specified address when the event fires
- **Webhook channel** — POSTs a JSON payload to the specified URL (compatible with Slack, PagerDuty, or any HTTP endpoint)
- **Aegis channel** — Aegis-0 handles the alert autonomously: it analyses the event, determines severity, and takes or recommends action

**When to act:** Ensure every critical event type (`agent_blocked`, `circuit_breaker_trip`, `rogue_agent_detected`) has at least one active rule. A rule with no destination is silent — the event fires but nobody is notified.

---

### Retention Policy `/agent-admin/retention`
**What it shows:** Controls how long each category of platform data is stored before deletion. Each row has a retention period (in days), an Auto Delete toggle, and an Archive First toggle.

**What the data means:**
- **Action Ledger** — the primary event record. SOC2 requires 12 months minimum.
- **Evidence Chain** — the cryptographic SQLite ledger. Legal hold may require this indefinitely.
- **Session Token Logs** — low-risk, short retention acceptable.
- **Archive First** — if enabled, Cicada exports a signed archive before deleting records. Required for any data subject to litigation hold.

**When to act:** Review this page before any compliance audit. Do not reduce retention periods during an active legal investigation.

---

### Threat Correlation `/agent-admin/correlation`
**What it shows:** Attack patterns computed across the entire fleet. Blocked events are grouped by their violation type into clusters. The signal panel shows how each attack vector is trending (rising/stable/falling) in the last 24 hours versus the previous 24 hours.

**What the data means:**
- **A cluster** represents a single attack pattern affecting multiple agents. If the same violation type appears across many agents, it is more likely a coordinated attack than a configuration issue.
- **Severity** is computed from the number of unique agents affected and how recently the pattern last fired — not manually assigned.
- **Rising trend** means the attack vector is accelerating. Falling means it is subsiding.

**When to act:** Any critical cluster affecting 3+ agents warrants immediate investigation. Use the "Example Trace" link to see a specific instance in the Request Inspector. Use "Ask Aegis" to get a threat analysis for the specific violation pattern.

---

### Behaviour Baselines `/agent-admin/baselines`
**What it shows:** A real-time behavioural deviation score for every registered agent, computed from live ledger data. Three metrics per agent: block ratio (how often it gets blocked), average confidence score (how suspicious the Verification Swarm finds its calls), and call volume in the last hour.

**What the data means:**
- **Block ratio ≥ 30%** — critical deviation. The agent is being blocked for nearly one in three calls.
- **Block ratio ≥ 15%** — elevated risk. Worth monitoring closely.
- **Average confidence < 40%** — critical. The swarm consistently finds this agent's calls suspicious.
- **Average confidence < 55%** — elevated.
- **Insufficient data** — fewer than 5 calls recorded. Score cannot be computed yet.

**When to act:** Any agent marked "Critical Deviation" should be reviewed in its Biography. If the circuit breaker has not already tripped, consider manually revoking the agent token until the root cause is understood.

---

## Aegis AI Assistant `/aegis`
**What it shows:** A three-pane interface. Left pane: reasoning stream — Aegis's visible thought process as it analyses your security state. Centre pane: the conversation interface. Right pane: active alerts and configuration (model selection, operator directives).

**What Aegis can do:**
- Explain any blocked event or policy violation in plain English
- Generate threat briefings and compliance reports
- Recommend changes to alert rules, retention policies, or security policies
- Analyse an agent's biography and assess its risk level
- Be asked to autonomously run audits, send notifications, and configure platform settings

**How to use it effectively:** Navigate to any Agent Admin page and use the contextual "Ask Aegis" button — it pre-fills the conversation with the relevant context (agent ID, violation type, cluster key). You can also ask Aegis free-form questions in the chat pane.

---

## Help & Manual `/help`
**What it shows:** The complete platform documentation, rendered from markdown. Covers architecture, API reference, EVAR token format, scope reference, and this operator guide.

---

## Status Indicators at a Glance

| Colour | Meaning |
|--------|---------|
| Green / Emerald | Healthy, approved, nominal |
| Amber / Orange | Elevated risk, warning, action recommended |
| Red | Blocked, critical, immediate attention required |
| Blue | Informational, Aegis-related, contextual |
| Grey / Neutral | No data, unverified, inactive |

## Confidence Score Reference

| Score | Display | Meaning |
|-------|---------|---------|
| 80–100% | Green | High confidence — request is legitimate |
| 55–79% | Amber | Moderate confidence — admitted with logging |
| 40–54% | Orange | Low-moderate — approaching block threshold |
| 0–39% | Red | Low confidence — blocked or shadow-sandboxed |
