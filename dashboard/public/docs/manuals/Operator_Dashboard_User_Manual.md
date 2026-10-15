# Cicada Operator Dashboard — Complete User Manual

**Version:** 3.0  
**Last Updated:** 12 June 2026  
**Classification:** Internal — Operator Use Only  
**Platform:** Cicada Agent Governance Platform  
**Dashboard URL:** `http://localhost:3000`

---

## Table of Contents

1. [Login & Authentication](#1-login--authentication)
2. [Sidebar Navigation](#2-sidebar-navigation)
3. [Global Command Center](#3-global-command-center)
4. [Security Monitor](#4-security-monitor)
5. [Live Call Inspector](#5-live-call-inspector)
6. [Agent Fleet](#6-agent-fleet)
7. [Security Policies](#7-security-policies)
8. [Governance Registry](#8-governance-registry)
9. [Credential Vault](#9-credential-vault)
10. [Activity Ledger](#10-activity-ledger)
11. [Action Rollbacks](#11-action-rollbacks)
12. [Client Companies (CRM)](#12-client-companies-crm)
13. [Agent Biographies](#13-agent-biographies)
14. [HITL Approval Queue](#14-hitl-approval-queue)
15. [Blocked Agents (Rogue Registry)](#15-blocked-agents-rogue-registry)
16. [Operator Audit Logs](#16-operator-audit-logs)
17. [Compliance Export](#17-compliance-export)
18. [Alert Rules](#18-alert-rules)
19. [Data Retention](#19-data-retention)
20. [Threat Correlation](#20-threat-correlation)
21. [Behaviour Baselines](#21-behaviour-baselines)
22. [Aegis AI Assistant](#22-aegis-ai-assistant)
23. [Shadow Agent Radar](#23-shadow-agent-radar)
24. [Cross-Page Workflows](#24-cross-page-workflows)
25. [ZTNA Trust Posture](#25-ztna-trust-posture)
26. [CIBA Pending Queue](#26-ciba-pending-queue)
27. [Shadow Sandbox](#27-shadow-sandbox)
28. [Health Indicators & Colour Reference](#28-health-indicators--colour-reference)

---

## 1. Login & Authentication

**Route:** `/login`  
**Purpose:** The login page is the zero-trust entry point to the Operator Dashboard. It requires hardware biometric authentication — there is no username/password option. This is a deliberate architectural decision: the operator terminal controls agent quarantine, token revocation, and policy enforcement across the entire platform. Credential-based login would introduce phishing and credential-stuffing attack surfaces that are unacceptable for a governance control plane.

**What you see:** A centred panel on a black background with a pulsing fingerprint icon, titled "Operator Terminal." Below the icon, the text "Hardware Biometric Access Required" confirms that only physical security keys (YubiKey, Passkey, or platform authenticator) are accepted. There are two buttons and an error display area.

**Controls:**

- **Authenticate** — The primary green button. Clicking this initiates a WebAuthn authentication ceremony. The browser will prompt you to insert and tap your YubiKey, or to authenticate with your device's biometric sensor (Touch ID, Windows Hello, etc.). If the cryptographic assertion succeeds, you are redirected to the Global Command Center (`/`). If it fails, a red error banner appears with the exact failure reason — "Hardware Key Denied," "Cryptographic Assertion Failed," or "No Operator Key."
- **Enroll Hardware Key** — The secondary outline button. This registers a new hardware key with the system. Use this the first time you set up the dashboard, or when issuing a replacement key to a new operator. The browser will walk you through the WebAuthn attestation flow. Once complete, the key is enrolled and you may use the Authenticate button.

**What healthy looks like:** You authenticate in under two seconds. The fingerprint icon pulses green momentarily, then you are redirected.

**What danger looks like:** If you see "No Operator Key. Must register a YubiKey or Passkey first," it means no hardware credential has been enrolled — you need to click Enroll Hardware Key. If you see "Hardware Key Denied," the key you tapped does not match any enrolled credential. This could indicate a stolen key attempt if you did not initiate the login.

**Cross-page workflow:** Login → Global Command Center. There is no session cookie — the WebAuthn flow is handled by the Next.js API routes at `/api/webauthn/login/generate` and `/api/webauthn/login/verify`. The credential store is server-side.

---

## 2. Sidebar Navigation

**Component:** `Sidebar.tsx`  
**Purpose:** The sidebar is the primary navigation structure for the entire dashboard. It is always visible on every page (except Login) and organises the platform's 21 screens into logical groups. Understanding the sidebar is essential before using any other page.

**Structure:** The sidebar is divided into four sections, read top to bottom:

1. **Platform Identity** — The Cicada logo and "Admin Panel" label at the top. This is purely decorative and confirms you are in the operator dashboard (not the Developer Portal).

2. **Primary Navigation** — Ten top-level links in order:
   - **Global Overview** (`/`) — The landing page with KPI cards and the 3D gateway globe.
   - **Security Monitor** (`/compute`) — Real-time verification metrics and threat gauges.
   - **Live Call Inspector** (`/pipeline`) — Individual trace-level inspection of every API call.
   - **Agent Fleet** (`/nodes`) — Every agent across every company, with quarantine controls.
   - **Security Policies** (`/security`) — View, test, and manage the rules that govern agent access.
   - **Agent Registry** (`/registry`) — Governance-focused view with trust tier, compliance, and bulk Shadow Mode toggle.
   - **Credential Vault** (`/vault`) — Encrypted API key storage and rotation.
   - **Activity Ledger** (`/logs`) — Chronological log of every call the Gateway processed.
   - **Action Rollbacks** (`/sagas`) — History of reversed, blocked, or auto-stopped actions.
   - **Client Companies** (`/crm`) — Company CRM with contact details, plan, and agent counts.

3. **Agent Admin** — A collapsible submenu (click "Agent Admin" to expand or collapse). Contains ten specialised screens:
   - Agent Biographies, HITL Approval Queue, CIBA Pending Queue, Blocked Agents, Operator Audit Logs, Compliance Export, Alert Rules, Data Retention, Threat Correlation, Behaviour Baselines.

4. **Bottom Section** — Three elements:
   - **Aegis AI Assistant** — Highlighted in blue, this opens the AI security co-pilot.
   - **Help & Manual** — Links to the embedded documentation page.
   - **Shadow Agent Radar** — Under the "SECURITY" header, at the very bottom.
   - **Register Agent** button — A green CTA that opens the Developer Portal's agent registration wizard in a new tab.
   - **Operator Identity** — Shows "System Operator / Admin" with an avatar.

**Collapse/Expand:** The sidebar has a small circular button on its right edge (a chevron arrow). Clicking it collapses the sidebar to icon-only mode (6rem wide) or expands it back to full width (18rem). When collapsed, hovering over any icon shows a tooltip with the page name.

**Active state:** The currently active page is highlighted with an orange background tint and a 4px orange right border. This tells you exactly where you are at all times.

---

## 3. Global Command Center

**Route:** `/`  
**API Endpoints:** `GET /api/v1/dashboard/summary`, `GET /api/v1/admin/gateways`  
**Purpose:** This is the operational command centre — the first screen every operator sees after login. Its job is to answer one question in under three seconds: "Is the platform healthy right now?" It presents the four most critical KPIs, a live incident feed, budget alerts, and a real-time interactive globe showing every deployed Sentry Gateway worldwide.

**What you see:**

**Header:** "Global Command Center" with the subtitle "Operational AI Agent Governance Control Plane. Source of Truth: Central PostgreSQL Ledger." This is not marketing copy — it tells the operator that every number on this page is sourced directly from the central PostgreSQL database, not from cached or computed values.

**KPI Cards (top-left, 2×2 grid):**

- **Total Tenants** — The number of registered companies on the platform. Clicking this card navigates to the CRM page (`/crm`). The secondary colour (blue) indicates this is an informational metric, not a risk signal.
- **Total Agents** — The total number of registered agents across all tenants. Below the number, a trend line shows how many were active in the last 24 hours (e.g., "42 active in last 24h"). A progress bar shows the ratio of active agents to total agents. Clicking navigates to the Governance Registry (`/registry`).
- **Today's Execution** — The combined count of approved and blocked calls today. The trend text breaks this down (e.g., "1,204 allowed / 38 blocked"). The progress bar shows the block ratio — a high block ratio means something is wrong. Clicking navigates to the Live Call Inspector (`/pipeline`).
- **Triage & Quarantines** — The number of quarantined agents. The trend text shows pending HITL approvals (e.g., "3 pending HITL approvals"). If the pending count is greater than zero, the progress bar fills to 100% red — this is an immediate attention signal. Clicking navigates to the HITL Approval Queue (`/agent-admin/hitl`).

**Recent Incidents Feed (below KPIs):** A chronological list of blocked events from the action ledger. Each row shows a red "BLOCKED" badge, the agent name, the target API, the timestamp, and the action type. If this feed is empty, it displays "No recent incidents detected. Ledger is clean." — that is the healthy state. A populated feed means the Gateway is actively blocking threats.

**Budget Alerts (conditional panel):** This panel only appears if any agent has exceeded 80% of its declared monthly budget. Each alert card shows the agent name, a progress bar of budget consumption (amber for warning, red for over-budget), the dollar amounts (estimated cost vs. budget), and the number of calls month-to-date. This is a BYOK cost control — since tenants bring their own API keys, budget overruns indicate either a misconfigured agent or a runaway loop.

**Active Gateway Fleet Globe (right side):** An interactive 3D globe rendered by the `CommandMatrix` component. Each deployed Sentry Gateway is plotted as a dot on the globe based on its registered country. The globe is purely read-only — it provides spatial awareness of your global deployment. Above the globe, the text shows how many persistent gateway installations are being mapped.

**Heartbeat Status Table (below the globe):** A full-width table showing every registered gateway instance with columns for: Status (Online/Degraded/Offline, colour-coded), Company, Location, IP Address, Version, Agents Registered, Load (calls in current window), TLS enabled (✓/✗), mTLS enabled (✓/✗), Canary Tokens Active, and Last Seen. Above the table, three summary badges show the count of Online, Degraded, and Offline gateways.

**What healthy looks like:** All KPIs show positive numbers, the incident feed is empty, no budget alerts are visible, all gateways show "Online" in green, and TLS/mTLS columns show ✓ everywhere.

**What danger looks like:** The Triage & Quarantines KPI is red and shows pending HITL approvals. The incident feed is populated with blocked events. A gateway shows "Degraded" or "Offline." Budget alerts are visible with red "OVER BUDGET" badges.

---

## 4. Security Monitor

**Route:** `/compute`  
**API Endpoint:** `GET /api/v1/compute/metrics`  
**Purpose:** The Security Monitor provides real-time telemetry from the verification engine — the component that scores every API call before allowing or blocking it. While the Global Command Center gives you a high-level health check, this page gives you the operational detail: how many checks ran, what the thread utilisation looks like, and what the current system status is.

**What you see:**

**Header:** "Sentry Monitor" with a live text readout showing the current verification statistics — active threads, checks run, threats blocked, and current latency in milliseconds. This text updates on every data refresh.

**Five KPI Cards (horizontal strip):**

1. **Checks Run (1h)** — Total number of verification checks executed in the last hour. The progress bar shows thread utilisation. This tells you how busy the verification engine is.
2. **Threats Blocked (1h)** — How many calls were denied in the last hour. If this number is unexpectedly high, it may indicate an attack pattern or a misconfigured agent.
3. **Active Threads** — The current number of concurrent verification threads. This indicates system load.
4. **Status** — A simple LIVE indicator in green. If this ever shows anything other than LIVE, the verification engine is down.
5. **Shadow Flags (24h)** — The number of observe-only violations recorded in the last 24 hours. This card has an amber border and uses the visibility icon. Shadow Flags occur when an agent is in Shadow Mode — the Gateway evaluates all policies and records violations to the audit ledger, but allows the call to proceed. A high Shadow Flags count means agents in monitoring mode are generating policy violations. This is expected during initial onboarding; it becomes a concern if the count keeps rising after baselines are established.

**Cross-page workflow:** If the Threats Blocked count is high, navigate to the Activity Ledger (`/logs`) to see exactly which agents are being blocked and why. If Shadow Flags are high, check which agents are in Shadow Mode via the Governance Registry (`/registry`).

---

## 5. Live Call Inspector

**Route:** `/pipeline`  
**API Endpoint:** `GET /api/v1/pipeline/traces`  
**Purpose:** The Live Call Inspector is the trace-level forensics screen. Every single API call that passes through the Sentry Gateway gets a unique trace ID and is recorded here with its full verification pipeline — from initial EVAR token validation through semantic analysis, swarm voting, and the final allow/block decision. This is the screen you use when you need to understand exactly why a specific call was blocked or allowed.

**What you see:**

**Header:** "Live Call Inspector" with a subtitle explaining that all traces are indexed by EVAR Agent Signatures and verified through the Multi-Agent Swarm.

**Filter Controls (top bar):**

- **Search** — A text input for searching by trace ID, agent ID, agent name, tenant name, or target API URL. This is the primary way to find a specific call.
- **Status filter** — A dropdown with options: All, Approved, Blocked, Shadow Sandbox, Shadow Violations. Use "Shadow Violations" to see calls that would have been blocked but were allowed because the agent is in Shadow Mode.
- **Trust Tier filter** — Buttons for All Tiers, Critical, Elevated, Nominal, Unverified. This filters traces by the calling agent's trust tier.
- **Refresh button** — Manually reloads the trace data from the API.

**Trace Table:** Each row represents one API call and shows:
- **Status badge** — Green "APPROVED", red "BLOCKED", amber "SHADOW FLAG", or orange "MONITORED".
- **Agent name** and ID (truncated).
- **Target API** — The destination URL the agent was trying to reach.
- **Trust Score** — The agent's current trust score as a percentage with a coloured progress bar.
- **Swarm Confidence** — The multi-agent verification confidence score. Below 40% is critical (red), below 55% is elevated (orange), above 55% is nominal (green).
- **Policy Violations** — If the call was blocked, the specific violation reason is shown (e.g., "scope_violation", "cross_agent_context_contamination").
- **Timestamp** — When the call occurred.

**Trace Detail Modal:** Clicking any trace row opens a detailed panel showing the complete pipeline execution — every verification stage the call passed through, the swarm voting breakdown, and the final decision with the exact policy that triggered the block. This is the forensic evidence you would export for a SOC2 audit or incident investigation.

**Cross-page workflow:** The Rogue Registry (`/agent-admin/rogue`) links directly to this page with a pre-filled trace ID using the URL parameter `?trace=TRACE_ID`. This means when you see a blocked agent in the Rogue Registry, clicking "View" brings you here with that exact trace loaded.

---

## 6. Agent Fleet

**Route:** `/nodes`  
**API Endpoint:** `GET /api/v1/nodes`  
**Purpose:** The Agent Fleet page is the master registry of every agent across every company on the platform. It serves dual purposes: operational monitoring (which agents are active, which are revoked, what are their trust scores) and emergency response (the Quarantine button). This is different from the Governance Registry — the Fleet page focuses on live operational status, while the Governance Registry focuses on compliance metadata.

**What you see:**

**Header:** "Agent Registry" (this is the fleet-level view) with the subtitle "All registered agents across every company on the platform."

**Live KPI Strip (top-right):** Four inline metrics showing Total agents, Active (green), Revoked (red, if any), and Critical (red, pulsing, if any agents are at critical trust tier). A spinning Refresh button allows manual data reload.

**Filter Toolbar:**

- **Search** — Full-text search across agent name, agent ID, and company name. The search field has a clear (×) button.
- **Trust Tier filter** — A tab bar with All Tiers, Critical, Elevated, Nominal, Unverified. Each option highlights in orange when selected.
- **Status filter** — Tab bar with All Status, Active, Revoked.
- **View Mode toggle** — Two icons for switching between Table View (rows) and Grouped View (cards grouped by company).
- **Results count** — Shows the filtered count, e.g., "42 agents (filtered from 156)." A "Clear filters" link appears when any filter is active.

**Table View:** Sortable columns — Company, Agent, Trust Tier, Trust Score (with progress bar), Total Calls, Blocked (with block percentage), Scopes (first 2 shown, with "+N" for additional), Last Seen, Status (green "Active" or red "Revoked" dot), and Actions.

**Action Buttons per Row:**

- **View** — Opens the Creator Detail Panel, a side-drawer that shows the full company profile and all agents for that company. If you click View on an agent row, the drawer opens with that specific agent pre-selected.
- **Stop** (red, only for Active agents) — This is the **quarantine button**. Clicking it triggers a confirmation dialog: "Hard-stop this agent? This sets revoked_at immediately and cannot be undone from this view." If confirmed, it sends `POST /api/v1/agents/{id}/quarantine` to the API. The agent's token is immediately revoked — it will be denied by the Gateway on its next call. This is an irreversible action from this interface.

**Grouped View:** Agents are displayed as cards grouped under their company heading. Each company section shows the company name, email, agent count, and trust score. Each agent card shows: name, ID, trust tier badge, trust score bar, call statistics (Total / Allowed / Blocked with percentages), last seen date, and the same View and Stop buttons.

**Pagination:** When more than 25 agents match the current filters, a pagination strip appears at the bottom with Previous, page number buttons, and Next.

**Register Agent FAB:** A floating action button in the bottom-right corner that opens the Developer Portal's agent registration wizard (`http://localhost:3001/agents/register`) in a new tab.

**Cross-page workflow:** Use this page to find an agent that is behaving suspiciously → click Stop to quarantine it → navigate to the Rogue Registry to see its blocked events → use the Pipeline Inspector to examine the exact trace that triggered the block.

---

## 7. Security Policies

**Route:** `/security`  
**API Endpoints:** `GET /api/v1/security/policies`, `POST /api/v1/security/policies/{slug}/test`, `POST /api/v1/security/policies/{slug}/exceptions`, `DELETE /api/v1/security/policies/{slug}/exceptions/{agent_id}`  
**Purpose:** This page is the policy enforcement engine's control panel. It lets operators view the rules that govern which agents are allowed to operate, test those rules against live data, and manage exceptions for agents that are legitimately blocked but need to be allowed through. The interface is built to look and feel like a code editor with an integrated terminal — because that is exactly what it is: a live policy debugger.

**What you see:**

**Layout:** A 3-column (12-column grid) layout:
- **Left column (3 cols):** Rule selector, rule details, and exceptions list.
- **Right column (9 cols):** A code editor showing the selected rule's logic, with an integrated test terminal at the bottom.

**Left Panel — Active Rules:** A list of all security policies loaded from the database. Each rule card shows its name (e.g., "Block Untrusted Traffic", "Trust Score Check"), a description, and a coloured left border (orange when selected). A pulsing "Issue detected" indicator appears on rules that currently have a warning status. Click any rule to load it into the code viewer.

**Left Panel — Rule Details:** Shows the selected rule's filename, line count, minimum trust score threshold (if applicable), health status (Healthy in green, Warning in orange), and environment (Production or Staging, with colour-coded badges).

**Left Panel — Approved Exceptions:** Lists agents that have been manually exempted from this rule. Each exception shows the agent name, the reason, and an × button to remove the exception. Removing an exception means that agent will once again be subject to the rule — and may be blocked on its next call.

**Code Viewer (main panel):** A styled code editor showing the rule logic with line numbers, syntax highlighting (keywords in orange, values in blue, comments in grey, DENY actions in red). Hovering over any line highlights it. When an exception is applied, a green overlay line appears in the code showing the agent name that was just added.

**Toolbar (above the code viewer):** Three decorative dots (red, yellow, green — mimicking a terminal window), the current filename, and two action buttons:
- **RUN TEST** — Sends `POST /api/v1/security/policies/{slug}/test` to the API. This picks a random agent from the database and evaluates it against the selected rule. The result appears in the terminal below. During testing, the button shows "TESTING..." and is disabled.
- **ADD EXCEPTION** — Only appears after a test returns "BLOCKED." This button bounces with a green glow to draw attention. Clicking it sends `POST /api/v1/security/policies/{slug}/exceptions` with the blocked agent's ID and adds it to the exceptions list. The terminal updates with a success message, the code viewer shows the new agent in the exceptions list, and the bottom stats change to reflect the resolution.

**Test Terminal (bottom of code viewer):** A black terminal panel that shows timestamped output from the test execution. Each line is colour-coded: orange for system messages, red for BLOCKED results, green for PASS results, cyan for UPDATE messages. If a test blocks an agent, the terminal border turns red. If an exception is applied and the test is resolved, the border turns green.

**Bottom Stats (three cards):** Requests Blocked (count and trend), Response Time (in ms), and Policy Health (percentage). These update dynamically when a test is run and when an exception is applied.

**Status Indicator (top-right):** A status pill showing the current state: "READY" (neutral), "AGENT BLOCKED" (red, pulsing), "EXCEPTION APPLIED" (green), or "ALL CLEAR" (green).

---

## 8. Governance Registry

**Route:** `/registry`  
**API Endpoint:** `GET /api/v1/registry?per_page=100`  
**Purpose:** The Governance Registry is the compliance-focused view of all registered agents. While the Agent Fleet page focuses on operational status and quarantine, this page focuses on identity, governance scores, trust tiers, criticality, data classification, and business unit — the metadata that matters for SOC2, ISO27001, and enterprise RFP compliance. This is also where the bulk Shadow Mode toggle lives.

**What you see:**

**Header:** "Governance Registry" with the subtitle "Global index mapping all core identity, role, and compliance schemas directly from PostgreSQL."

**Toolbar buttons (top-right):**

- **Toggle Shadow Mode (N)** — This amber-coloured button only appears when one or more agents are selected via the checkboxes. N is replaced with the actual count of selected agents. Clicking this button dispatches a Shadow Mode toggle for all selected agents. In Shadow Mode, the Gateway evaluates all policies and records violations to the audit ledger, but allows traffic through. This is the mechanism for staged rollouts — select 5 agents, enable Shadow Mode, monitor their Shadow Flags on the Security Monitor, tune your thresholds, then disable Shadow Mode to activate strict enforcement.
- **Refresh Telemetry** — Standard orange button that reloads the registry data from the API.

**Table columns:** Checkbox (for bulk selection), Identity / Target Name (agent name + company), Role & App Type, Version, Gov Score (governance score), Trust Tier (badge), Criticality, Class (data classification), Business Unit, and Actions.

**Checkboxes:** Each row has a checkbox. The table header has a "select all" checkbox. Selected rows are highlighted with an amber tint. This selection state drives the Toggle Shadow Mode bulk action button.

**Action column:** Each row has a "Biography" link that opens the agent's biography page (`/registry/{id}`).

**Cross-page workflow:** Select agents → Toggle Shadow Mode → Monitor Shadow Flags on Security Monitor → Review violations in Activity Ledger → When satisfied, return here and deselect to exit Shadow Mode.

---

## 9. Credential Vault

**Route:** `/vault`  
**API Endpoints:** `GET /api/v1/vault/keys`, `POST /api/v1/vault/keys/{id}/rotate`  
**Purpose:** The Credential Vault manages the API keys that agents use to connect to AI providers (OpenAI, Anthropic, OpenRouter). Cicada is a BYOK (Bring Your Own Key) platform — every tenant supplies their own API keys, which are encrypted at rest and never displayed in plain text. This page lets operators see which keys are stored, for which tenant, and rotate them if compromised.

**What you see:**

**Header:** "API KEYS" with the subtitle "Manage the API keys your agents use to connect to AI providers. Keys are stored encrypted and never shown in plain text." A KPI card on the right shows the total number of stored keys.

**Aegis AI Key Section (top):** A special blue-bordered card for the Aegis AI Assistant's own API key. This is the key Aegis uses to power its reasoning engine via OpenRouter. It has its own `SecureInput` component — you type the key, it's encrypted and stored server-side. The key is never shown after submission.

**BYOK Input Section:** Two `SecureInput` components for adding Anthropic and OpenAI keys. These are for the operator to provision keys on behalf of tenants.

**Stored Keys Grid:** A grid of cards showing every key stored in the vault. Each card shows:
- **Provider badge** — Orange pill showing "OpenAI", "Anthropic", or "OpenRouter."
- **Tenant name** — Which company owns this key.
- **Key display** — Always shows "██████████████████████████████..." — keys are never revealed.
- **Added date** — When the key was first stored.
- **Rotate Key button** — Clicking this sends `POST /api/v1/vault/keys/{id}/rotate` to the API. The button spins during rotation and shows "Rotating..." A toast notification confirms success. Key rotation generates a new encryption envelope — the old key is no longer valid.

**Key Usage Log (bottom):** A chronological list of key access events showing the action type (e.g., "key accessed", "key rotated"), the tenant name, the status (green "Success" or red failure), and the timestamp. A "View Full Activity Log" link navigates to the Activity Ledger (`/logs`).

**Cross-page workflow:** If you rotate a key, the agent using that key will fail on its next call. Navigate to the Activity Ledger to confirm the rotation took effect, then notify the tenant to update their key in the Developer Portal.

---

## 10. Activity Ledger

**Route:** `/logs`  
**API Endpoint:** `GET /api/v1/logs`  
**Purpose:** The Activity Ledger is the chronological, append-only record of every single API call the Sentry Gateway has processed. This is the primary audit trail. Every call — whether approved, blocked, shadow-flagged, or monitored — appears here with its trace ID, agent identity, target API, verification score, and status. SOC2 auditors will spend most of their time on this page.

**What you see:**

**Header:** "Activity Ledger" with a live paginated table below it.

**Filter Controls:**

- **Search** — Full-text search across trace ID, agent ID, agent name, tenant name, target API.
- **Status dropdown** — Options: All Statuses, Approved, Blocked, **Shadow Violations**, Monitored. The "Shadow Violations" option filters for calls where the status is `shadow_allowed` — these are calls that violated policy but were allowed through because the agent is in Shadow Mode. This is how you audit Shadow Mode behaviour without leaving the logs page.
- **Refresh** — Manual data reload button.

**Log Table:** Each row shows:
- **Status** — Colour-coded text: green "Approved", red "Blocked", **amber "Shadow Flag"**, orange "Monitored", or grey for other states. The amber colour is specifically for `shadow_allowed` status, making Shadow Mode violations instantly recognisable in the log stream.
- **Agent** — Name and company.
- **Target API** — The destination URL.
- **Verification Score** — The swarm confidence score.
- **Policy Violations** — If blocked or shadow-flagged, the specific violation.
- **Timestamp** — When the call occurred.

**What healthy looks like:** A stream of green "Approved" entries with occasional amber "Shadow Flag" entries for agents in Shadow Mode. No red entries.

**What danger looks like:** A sudden burst of red "Blocked" entries from the same agent or tenant. This pattern warrants immediate investigation — navigate to the Live Call Inspector for forensic detail, or to the Threat Correlation page for pattern analysis.

**Cross-page workflow:** Filter by "Shadow Violations" → identify which agents are generating the most shadow flags → navigate to the Governance Registry → consider disabling Shadow Mode and activating strict enforcement for those agents.

---

## 11. Action Rollbacks

**Route:** `/sagas`  
**API Endpoint:** `GET /api/v1/sagas?per_page=100`  
**Purpose:** This page records every action that was automatically reversed, blocked, or flagged for review by the security system. It is the accountability trail for the platform's automated enforcement. When the circuit breaker trips, when an operator manually rejects a HITL call, when a rollback is triggered — the record lands here.

**What you see:**

**Header:** "Rollback History" with the subtitle "A record of every action that was automatically reversed, blocked, or flagged for review by the security system."

**Refresh button** — Reloads rollback data from the API.

**Table columns:** Reference ID (trace ID in orange), Agent, Destination (the target API), Reason, and Result.

**Result states, each with a coloured dot:**
- **AUTO-STOPPED** (red, pulsing) — The circuit breaker tripped automatically. This means the agent exceeded the velocity limits (30 writes / 10 deletes per 60 seconds) and was automatically shut down.
- **REJECTED** (red) — A human operator manually denied the call through the HITL Approval Queue.
- **NEEDS REVIEW** (red, pulsing) — A blocked call that has not yet been reviewed. This warrants attention.
- **REVERSED** (green) — The action was reversed successfully. This is the resolved state.

**Reason column labels:**
- "Auto-stopped" — Circuit breaker trip.
- "Manually rejected" — HITL denial.
- "Action reversed" — Explicit rollback.

**Cross-page workflow:** See an "AUTO-STOPPED" entry → navigate to the Behaviour Baselines page to check that agent's deviation score → navigate to the Agent Fleet page to decide whether to quarantine.

---

## 12. Client Companies (CRM)

**Route:** `/crm`  
**API Endpoint:** `GET /api/v1/crm/companies`  
**Purpose:** The CRM is the operator's view of every company registered on the platform. It provides the commercial context that the technical screens do not — which plan each company is on, who the primary contact is, how many agents they have, and how many are certified. This is the starting point for account-level investigations.

**What you see:**

**Header:** "Company CRM" with a count of total registered companies (e.g., "42 registered companies").

**Filters:**
- **Search bar** — Search by company name or email. Submit with the Search button or Enter key.
- **Plan filter** — Buttons for All Plans, Starter (sky blue), Professional (orange), Enterprise (purple). Each company on the platform is assigned a plan tier.

**Table columns:** Company (name + email), Primary Contact (name + avatar + email), Plan (colour-coded badge), Status (green "Active", red "Suspended", yellow "Pending"), Agents (total count + certified count), Joined date, and a "View →" link.

**View button** — Navigates to `/crm/{id}`, the individual company detail page. This page shows the full company profile including all agents, billing history, and compliance status.

**Pagination:** Previous / Next buttons with page count display for navigating through large company lists.

**Cross-page workflow:** Find a company → click View → see all their agents → identify a problematic agent → navigate to its biography → quarantine if necessary.

---

## 13. Agent Biographies

**Route:** `/agent-admin/biographies`  
**API Endpoint:** `GET /api/v1/agents/biographies`  
**Purpose:** Agent Biographies is a card-based gallery view of every agent on the platform, designed for rapid visual triage. Each card is a compact summary of an agent's identity, lifecycle state, trust tier, scope entitlements, and recent activity. Clicking any card opens the full biography page. This is the screen you use when you need to scan the fleet visually rather than read through table rows.

**What you see:**

**Header:** "Agent Biographies" with the subtitle "Every agent registered on the platform — name, company, lifecycle state, trust tier, last active. Click any card to open the full biography."

**Filters:**
- **Search** — Debounced search (300ms delay) across agent name and company name. Typing immediately begins filtering without pressing Enter.
- **Trust tier dropdown** — All trust tiers, Unverified, Nominal, Elevated, Critical.
- **Agent count** — Shows the total number of agents matching the current filter.

**Agent Cards (responsive grid, 1–4 columns):** Each card shows:
- **Trust Tier badge** — Colour-coded (grey for Unverified, blue for Nominal, yellow for Elevated, red for Critical).
- **Role badge** — If the agent has a non-default role (e.g., "orchestrator", "validator"), it's shown in blue.
- **Lifecycle State** — Top-right of each card: "Active" (green), "Revoked" (red), "Quarantined" (pulsing red), "Elevated" (yellow), "Critical" (red).
- **Agent Name** — Bold, prominent. Unnamed agents show "Unnamed" in grey italic.
- **Company** — The tenant/company this agent belongs to.
- **Last Active** — Relative time (e.g., "5m ago", "2h ago", "Never").
- **Total Calls** — Lifetime call count.
- **Scope badges** — First 3 scope entitlements shown as orange pills, with "+N" for additional scopes.
- **Compliance metadata** — Criticality level, data classification, and business unit badges (when present).
- **Footer** — HITL indicator (purple "HITL" if enabled), agent type, version number, and an → arrow.

**Revoked agent overlay:** If an agent has been revoked, the entire card gets a subtle red overlay, making it instantly visually distinct.

**Clicking a card** navigates to `/registry/{agent_id}` — the full agent biography page with all identity fields, scope details, call history, and governance information.

**Pagination:** Previous / Next buttons with page count for navigating through large agent populations (24 agents per page).

---

## 14. HITL Approval Queue

**Route:** `/agent-admin/hitl`  
**API Endpoints:** `GET /api/v1/admin/hitl/queue`, `POST /api/v1/admin/hitl/{traceId}/approve`, `POST /api/v1/admin/hitl/{traceId}/reject`  
**Purpose:** This is the asynchronous Human-in-the-Loop approval queue. When an agent is configured with HITL enabled, every `proxy:write` or `proxy:transact` call is intercepted by the Sentry Gateway, the payload is encrypted with AES-256-GCM, and the origin service receives a `202 Accepted` immediately — no TCP hold. The trace is placed in a Suspended Saga queue, and this page is where an operator reviews and decides the outcome. If no operator acts within the configured timeout window, the trace is automatically denied.

**What you see:**

**Header:** "HITL Approval Queue" with a pulsing red badge showing the count of pending items (e.g., "3 PENDING"). Below the header, an explanatory paragraph describes the encryption and auto-denial behaviour.

**Lifecycle Legend:** A horizontal strip of seven colour-coded badges representing the complete saga lifecycle:
- **SUSPENDED** (amber) — Awaiting an operator decision.
- **APPROVED** (green) — Operator approved. Saga Executor will dispatch the resume webhook.
- **DENIED** (red) — Operator denied. Denial webhook dispatched.
- **TIMED OUT** (grey) — No operator acted within the timeout window. Auto-denied by cron.
- **DELIVERED** (blue) — The webhook was successfully delivered to the origin service.
- **RETRYING** (orange) — The webhook delivery failed and is being retried.
- **DEAD LETTER** (dark red) — All retry attempts exhausted. The webhook was never delivered.

**Pending Queue Section:** Each pending item is a card with:
- **Saga State badge** — Shows current state (usually "SUSPENDED" for pending items).
- **Agent identity** — Name, trust tier badge, and company name.
- **Target API** — The destination the agent was trying to reach.
- **HTTP method** and **payload size** (in KB) — Structural metadata only. The actual payload is never shown for security reasons.
- **Policy violation details** — If the call triggered a policy violation, the reason is shown in a red panel.
- **Timestamp** — When the call was intercepted.
- **Three action buttons:**
  - **Biography** — Opens the agent's biography in a new tab for context.
  - **Reject** (red) — Denies the call. Sends `POST /api/v1/admin/hitl/{traceId}/reject`. If successful, a toast confirms "Trace denied. Denial webhook dispatched."
  - **Approve** (green) — Approves the call. Sends `POST /api/v1/admin/hitl/{traceId}/approve`. Toast confirms "Trace approved. Saga Executor dispatching webhook."

**409 Conflict Handling:** If another operator has already resolved this trace, the API returns HTTP 409. The toast shows "Resolution already recorded for this trace." — the queue refreshes and the item disappears.

**Auto-refresh:** The queue polls `GET /api/v1/admin/hitl/queue` every 5 seconds automatically. You never need to manually refresh.

**Resolved History Section:** A table showing all recently resolved HITL events with columns: State (badge), Agent, Company, Target, Resolved At, and a Delivery column.

**Expandable Delivery Log:** Clicking the "Log" button on any resolved row expands a delivery telemetry panel showing:
- **Webhook URL** — The URL the Saga Executor dispatched to.
- **Response Code** — The HTTP response (green 200, red for anything else).
- **Retry Count** — How many delivery attempts were made.
- **Payload Hash** — The integrity hash of the encrypted payload.
- **Redispatch button** — Only visible for Dead Letter state traces. Allows manual retry of the webhook dispatch.

---

## 15. Blocked Agents (Rogue Registry)

**Route:** `/agent-admin/rogue`  
**API Endpoint:** `GET /api/v1/logs?status=blocked&per_page=50`  
**Purpose:** The Rogue Registry captures every agent the Gateway has blocked. This is your threat audit trail — every failed authentication, every revoked token attempt, every unauthorised call, every policy violation that resulted in a block. Unlike the Activity Ledger (which shows all calls), this page shows only blocked calls, making it the focused view for incident response.

**What you see:**

**Header:** "Rogue Registry" with the subtitle "Every agent that was blocked by the Gateway — failed authentication, revoked tokens, unauthorised calls, policy violations. This is your audit trail of threats stopped." A red pulsing indicator shows the total count of blocked events.

**Help Panel (blue):** An informational panel explaining how to use the screen: review blocked events, click rows to see pipeline traces, and use the "Ask Aegis" button for AI-powered analysis.

**"Ask Aegis to Analyse" button** — Navigates to the Aegis AI Assistant (` /aegis`) with context pre-loaded for threat analysis.

**Table columns:** Agent / Company, Action Type (badge), Reason (red badge showing the specific violation), Target API, Risk Score (percentage from the swarm confidence score — above 70% is red, above 40% is orange, below is grey), Time, and Trace (clickable "View" link).

**Clicking "View" on any trace** navigates to the Live Call Inspector (`/pipeline?trace={trace_id}`) with that specific trace pre-loaded for forensic examination.

**Cross-page workflow:** See a blocked agent here → click "View" to examine the full pipeline trace → understand why it was blocked → navigate to the Agent Fleet to quarantine if needed → navigate to Threat Correlation to see if this is part of a larger attack pattern.

---

## 16. Operator Audit Logs

**Route:** `/agent-admin/operator-logs`  
**API Endpoint:** `GET /api/v1/admin/audit-logs`  
**Purpose:** This is the SOC2-compliant, immutable audit trail of every state-changing action performed by a human operator. Unlike the Activity Ledger (which records agent calls through the Gateway), this page records what the operators themselves did — who approved a HITL call, who quarantined an agent, who changed a policy exception, who rotated an API key. This table cannot be edited, cleared, or deleted. It is the definitive record of human intervention in the system.

**What you see:**

**Header:** "Operator Audit Logs" with the subtitle "SOC2-compliant, immutable audit trail. Every state-changing action performed by a human operator is recorded here. This table cannot be edited, cleared, or deleted."

**Export buttons (top-right):**
- **Export CSV** — Downloads a CSV file containing all currently filtered records. The CSV includes columns: ID, Timestamp, Operator Email, Action Type, Target Type, Target ID, Justification, and IP Address. Suitable for direct submission to SOC2 auditors.
- **Export JSON** — Downloads a JSON file with the complete record set including `previous_state` and `new_state` objects. Suitable for machine processing or archival.
- **Refresh** — Reloads the audit log from the API.

**Filter Controls:**
- **Action type dropdown** — 12 action types: hitl_approved, hitl_denied, agent_quarantined, agent_unquarantined, policy_exception_created, trust_level_upgraded, security_rule_updated, alert_rule_modified, data_retention_changed, api_key_rotated, aegis_directive_saved, alert_dismissed.
- **Operator search** — Text input to filter by operator email.
- **Date range** — From and To date pickers.
- **Clear Filters** — Resets all filters (only visible when filters are active).

**Table columns:** Timestamp (date + time), Operator (email in orange + IP address), Action (badge), Target (type + ID), Justification (truncated text), and Diff (button or dash).

**JSON Diff Viewer:** If an action has `previous_state` and `new_state` recorded, an "Inspect Diff" button appears. Clicking it opens a modal showing a key-by-key JSON diff with red lines for removed values and green lines for added values. The modal header shows the action type, target type, and target ID. The footer shows the timestamp, operator email, and IP address.

**Footer:** "Immutable Records: N" count and the text "Append-only — no edit or delete operations available."

---

## 17. Compliance Export

**Route:** `/agent-admin/audit`  
**API Endpoint:** `GET /api/v1/admin/compliance-report`  
**Purpose:** This page generates signed audit reports for any time range. While the Operator Audit Logs page shows human actions, this page exports the full action ledger (agent-level events) for compliance, legal review, or insurance requirements.

**What you see:**

**Header:** "Audit & Export" with the subtitle "Generate signed audit reports for any time range. Export for compliance, legal review, or insurance requirements. Every export is timestamped and traceable."

**Help Panel:** Explains the workflow — select a date range, filter by event status, click Export CSV for auditors or Ask Aegis for a narrative summary.

**Configure Export Panel:**
- **From Date** — Date picker (defaults to 7 days ago).
- **To Date** — Date picker (defaults to today).
- **Event Status** — Dropdown: All Events, Blocked Only, Approved Only, Shadow Sandbox.

**Three action buttons:**
- **Export CSV** (orange, primary) — Downloads a CSV with columns: Trace ID, Agent ID, Action Type, Block Status, Target API, Risk Score, Policy Violations, and Timestamp. If the server-side compliance report endpoint fails, a client-side fallback automatically generates the CSV from the logs endpoint.
- **Export JSON** — Secondary button that exports raw JSON.
- **Ask Aegis for Report** (blue) — Navigates to the Aegis AI Assistant to generate a narrative compliance summary.

**Export Confirmation:** A green "Export downloaded successfully" message flashes for 3 seconds after a successful download.

**Fields Included Panel:** A 4×2 grid showing every field included in the export, with green checkmarks: Trace ID, Agent ID, Action Type, Block Status, Target API, Risk Score, Policy Violations, Timestamp.

---

## 18. Alert Rules

**Route:** `/agent-admin/alerts`  
**API Endpoints:** `GET /api/v1/admin/alert-rules`, `POST /api/v1/admin/alert-rules`, `PATCH /api/v1/admin/alert-rules/{id}`, `DELETE /api/v1/admin/alert-rules/{id}`  
**Purpose:** Alert Rules configure who gets notified when critical security events fire. This is the notification routing engine — you define the event type, the delivery channel, and the destination. When the Gateway detects the specified event, the alert is dispatched.

**What you see:**

**Header:** "Alert Rules" with the subtitle "Configure who gets notified when critical security events fire. Email, webhook, or let Aegis handle it automatically."

**Help Panel:** Explains the three channels (email for humans, webhook for Slack/PagerDuty, Aegis for automated response) and links to the Aegis configuration page.

**Active Rules List:** Each rule shows:
- **Toggle switch** — Green when enabled, grey when disabled. Clicking the toggle sends `PATCH /api/v1/admin/alert-rules/{id}` to flip the enabled state. Disabled rules still exist in the database but do not fire.
- **Event type label** — Human-readable name (e.g., "Agent Blocked", "Memory Contamination Detected").
- **Channel and destination** — E.g., "EMAIL → admin@company.com" or "WEBHOOK → https://hooks.slack.com/…"
- **Delete button** (trash icon) — Sends `DELETE /api/v1/admin/alert-rules/{id}`. This is permanent and cannot be undone.

**"Ask Aegis to Configure" button** — Navigates to Aegis to set up automated alert routing.

**Add New Rule Form:**
- **Event Type dropdown** — Six event types: Agent Blocked, Memory Contamination Detected, Circuit Breaker Tripped, Rogue Agent Detected, PII Found in Response, Role Violation.
- **Channel dropdown** — Email, Webhook, or Aegis-0 (Automated).
- **Destination input** — Placeholder changes based on channel: email address, webhook URL, or "Aegis handles automatically."
- **Add Rule button** — Orange, submits the new rule via `POST /api/v1/admin/alert-rules`.

---

## 19. Data Retention

**Route:** `/agent-admin/retention`  
**API Endpoints:** `GET /api/v1/admin/retention-policies`, `PUT /api/v1/admin/retention-policies`  
**Purpose:** Data Retention controls how long each category of platform data is kept. This is a compliance-critical setting — SOC2 and ISO 27001 require at least 12 months for security events, while GDPR may require shorter retention for personal data. This page lets operators configure per-category retention periods, auto-deletion behaviour, and archive-before-delete policies.

**What you see:**

**Header:** "Retention Policy" with regulatory guidance in the subtitle.

**Help Panel:** Detailed instructions for each control, including the "Archive First" requirement for data subject to legal hold.

**Compliance Quick Reference (3 cards):**
- **SOC 2 Type II** — Minimum 12 months.
- **ISO 27001** — Minimum 12 months.
- **NIST AI RMF** — Risk-proportionate.

**Policy Table:** Each row represents one data category and shows:
- **Label and description** — E.g., "Action Ledger — All calls processed by the Gateway."
- **Retain (days)** — A number input. The colour below the input indicates the retention tier: green (<180 days), yellow (180–364), orange (365–729), red (730+).
- **Auto Delete toggle** — When enabled (orange), records are automatically purged when they expire. When disabled, records are kept until manual deletion.
- **Archive First toggle** — When enabled (green), a signed archive is exported before any deletion occurs. This is required for data that may be subject to legal hold.
- **Status badge** — Computed from the toggle states: "Manual only" (green lock), "Archive & delete" (yellow archive icon), "Hard delete" (red delete icon). "Hard delete" without archive is the highest-risk configuration.

**Legal Hold Warning Panel:** An orange panel explaining that auto-delete rules are suspended during active litigation or regulatory investigation. Aegis-0 can flag retention changes made during a hold period.

**Save Policy button** — Sends `PUT /api/v1/admin/retention-policies` with all current settings. Shows "✓ Policy Saved" on success.

**"View Audit Export" link** — Navigates to the Compliance Export page.

---

## 20. Threat Correlation

**Route:** `/agent-admin/correlation`  
**API Endpoints:** `GET /api/v1/logs?status=blocked&per_page=1000`, `GET /api/v1/admin/threat-signals`, `GET /api/v1/admin/violation-trends`  
**Purpose:** Threat Correlation is the intelligence layer. While the Rogue Registry shows individual blocked events, this page groups them into attack clusters. A single attacker probing multiple agents shows up here as one cluster, not dozens of disconnected events. This is where you answer the question: "Is this a coordinated attack or isolated noise?"

**What you see:**

**Header:** "Threat Correlation" with a status badge showing the total count of correlated blocked events (or "No blocked events" in green if the ledger is clean).

**Help Panel:** Explains the clustering algorithm and the signal panel.

**Aegis-0 Threat Vectors Panel (top):** A grid of 10 server-side attack vectors (V01–V10), each with a label and count:
- V01 — Registration Spike
- V02 — Revoked Agent Probe
- V03 — OAuth State Mismatch
- V04 — Swarm HMAC Failure
- V05 — Duplicate Rollback ID
- V06 — Ledger Anomaly
- V07 — Confidence Variance
- V08 — Role Violation
- V09 — Token IP Anomaly
- V10 — Undeclared Tool Call
- Plus a Circuit Breaker Trips counter.

Each count is green if zero, red if non-zero. This panel is computed server-side by the Aegis threat analysis engine.

**Policy Violation Trends Chart (30-day):** A multi-line SVG chart showing daily violation counts by type over the last 30 days. Each violation type gets a distinct colour. When the chart is loaded, Y-axis shows count, X-axis shows dates at weekly intervals. A legend below the chart maps colours to violation type names.

**Layout (below the chart):** A 4/8 column split:

**Left (4 cols) — Attack Vectors (24h):** A ranked list of violation types showing:
- Name and label
- Count in last 24 hours (colour-coded by severity)
- Trend arrow: rising (red ↑), stable (grey →), or falling (green ↓) — compared to the previous 24 hours.
- Last hit timestamp.

Two action buttons:
- **Generate Aegis Briefing** — Computes a shareable threat summary from the live data. The briefing includes: total clusters, highest-severity pattern, affected agent/tenant counts, rising vectors, and a recommended action. The briefing text appears in a blue panel below.
- **Ask Aegis to Investigate** — Navigates to Aegis Chat with threat context pre-loaded.

**Right (8 cols) — Detected Attack Clusters:** Each cluster shows:
- **Severity badge** — Critical (red), High (orange), Medium (yellow), Low (grey). Severity is computed from: number of unique agents affected, how recently the pattern fired, and the total event count.
- **Cluster label** — Human-readable name (e.g., "Cross-Agent Semantic Contamination").
- **Statistics** — Event count, agent count, tenant count, first seen date, last seen date.
- **Raw violation key** — The machine-readable violation identifier.
- **Three action links:** Example Trace (opens Pipeline Inspector), All Events (opens Rogue Registry), Ask Aegis (opens Aegis with this violation pre-loaded as context).

---

## 21. Behaviour Baselines

**Route:** `/agent-admin/baselines`  
**API Endpoints:** `GET /api/v1/registry?per_page=100`, `GET /api/v1/logs?per_page=1000`  
**Purpose:** Behaviour Baselines provides continuous behavioural scoring for every registered agent. It combines three metrics — block ratio, average swarm confidence, and call velocity — into a single deviation signal. This is the anomaly detection layer. An agent that was behaving normally but suddenly starts getting blocked more often will show up here as "Critical Deviation" before the circuit breaker trips.

**What you see:**

**Header:** "Behaviour Baselines" with a subtitle and status badges showing the count of critical and elevated deviations.

**Help Panel:** Explains the three metrics and the deviation thresholds in detail.

**Threshold Reference Cards (3 cards):**
- **Block Ratio** — Critical: ≥ 30%, Elevated: ≥ 15%.
- **Avg Confidence** — Critical: < 0.40, Elevated: < 0.55.
- **Data Requirement** — At least 5 calls required before baseline scoring begins.

**Sort Controls:** Three buttons — Risk Level (default, sorts by deviation severity), Block Rate, Confidence.

**Baseline Table:** Each row shows:
- **Agent** — Name and expected velocity (if declared during registration), with velocity deviation percentage.
- **Status** — Trust tier badge.
- **Calls** — Total call count.
- **Block Rate** — Percentage with a coloured progress bar (green/orange/red based on threshold).
- **Avg Confidence** — Percentage with a coloured progress bar.
- **Last Hour** — Calls in the last 60 minutes (for velocity spike detection).
- **Deviation** — Badge: "Critical Deviation" (red), "Elevated Risk" (orange), "Normal Behaviour" (green), or "Insufficient Data" (grey).
- **Actions** — "History" link to Agent Biographies and "Aegis" link to Aegis with this agent's ID pre-loaded.

**Critical Deviation Warning Panel:** If any agent is at critical deviation, a red panel appears at the bottom warning that the circuit breaker may have already tripped. Two action links: "View Biographies" and "Ask Aegis to Investigate."

**Computation note:** Baselines are computed client-side by cross-referencing the agent registry with the action ledger. The page fetches both datasets and computes deviation scores in the browser. This means the deviation state is always based on the latest available data at page load.

---

## 22. Aegis AI Assistant

**Route:** `/aegis`  
**API Endpoints:** `POST /api/v1/aegis/directives`, `POST /api/v1/aegis/alerts/{id}/release`  
**Purpose:** Aegis is the built-in AI security co-pilot. It monitors all agent activity, analyses threat patterns, and can take automated security actions. This page has three columns: the reasoning stream (showing how Aegis thinks), the action log (showing what Aegis did), and the configuration panel (model selection, API key, and custom instructions).

**What you see:**

**Header:** "Aegis AI Assistant" with a blue "Automated Security Analysis" badge.

**Column 1 — Reasoning Stream (left, 35%):** An amber-bordered panel showing Aegis's chain-of-thought reasoning in monospace text. This is a live feed of how Aegis is analysing the current traffic. Example output: "Reviewing activity on account tnt_gamma_44. Traffic rate: 804 requests/sec — above normal threshold." The reasoning stream is read-only — it shows you what Aegis is thinking before it acts.

**Column 1 — Action Taken (bottom-left):** A cyan-bordered panel showing the exact JSON payload Aegis sent to the Security Gateway and the response it received. This provides full transparency into automated actions. Example: `{"action": "block_account", "target": "tnt_gamma_44"}` with response `{"status": "success", "reference": "TRACE_0x99B"}`.

**Column 2 — Active Alerts Feed (centre):** A list of security actions Aegis has taken. Each alert card shows:
- **Status badge** — "ACTION APPLIED" in green.
- **Description** — E.g., "Account blocked: tnt_gamma_44."
- **Pipeline progress** — Three stages: Analysed (amber) → Action sent (cyan) → Confirmed (green).
- **Dismiss & Release button** (red) — Dismisses the alert and releases the hold. Sends `POST /api/v1/aegis/alerts/{id}/release`. The card animates out with a scale/fade/blur transition.

**Column 3 — Settings (right, 25%):**

- **Connections panel** — Shows connection status for Security Gateway ("Connected" in green) and Key Storage ("Read-Only" in blue).
- **AI Model panel** — A dropdown selector pre-populated with all available models from the OpenRouter API (`https://openrouter.ai/api/v1/models`). Default is `deepseek/deepseek-r1`. Below the dropdown is a `SecureInput` for the Aegis API key (same component used in the Vault).
- **Aegis Instructions panel** — A textarea where operators write the natural-language instructions that govern Aegis's behaviour. Default instructions include threshold monitoring and escalation rules. A "SAVE" button appears on hover, which sends `POST /api/v1/aegis/directives` to persist the instructions.

---

## 23. Shadow Agent Radar

**Route:** `/discovery`  
**API Endpoint:** `GET /api/v1/discovery`  
**Purpose:** The Shadow Agent Radar detects agents operating outside your approved security gateway. These are "ghost agents" — AI systems that are sending requests to your APIs without going through Cicada's governance pipeline. This page is the early warning system for shadow AI usage within an organisation.

**What you see:**

**Header:** "Unmanaged Agents" with the subtitle "Agents detected operating outside your approved security gateway. Review each one and decide whether to monitor, block, or reverse their actions." A pulsing orange beacon shows the total count of detected ghost agents.

**Risk Map (visual):** A large dark panel with a central blue node ("Your Platform") and up to three ghost agent nodes positioned at varying distances. Red nodes indicate high risk (blocked attempts recorded), orange nodes indicate agents under monitoring. A legend in the bottom-left explains the colour coding.

**Take Action Section:** A card grid where each ghost agent gets its own card showing:
- **Risk level badge** — "High Risk" (red) or "Being Monitored" (orange) in the top-right corner.
- **Agent identity** — Name, tenant, intercept count, and "last seen" relative time.
- **Description** — E.g., "This agent is sending requests to api.openai.com without going through your security gateway. 3 attempts have been blocked."
- **Three action buttons:**
  - **Monitor** (neutral) — Places the agent under observation. Sends `POST /api/v1/agents/{id}/monitor`. Calls are logged but not blocked.
  - **Block** (red, glowing) — Immediately revokes the agent's access. Sends `POST /api/v1/agents/{id}/revoke`. This is permanent from this interface.
  - **Reverse** (orange) — Triggers a rollback of the agent's recent actions. Sends `POST /api/v1/agents/{id}/rollback`. Use this when the ghost agent has already performed actions that need to be undone.

**Cross-page workflow:** Discover a ghost agent → Block it → Navigate to the Rogue Registry to see its blocked event history → Navigate to Threat Correlation to check if it's part of a larger pattern → Ask Aegis to investigate the tenant.

---

## 24. Cross-Page Workflows

The following workflows describe the most common multi-page sequences an operator will follow. Each workflow is designed to be executed in order, with each page providing the context needed for the next decision. These workflows are not theoretical — they represent the operational procedures that have been validated against the platform's actual UI and API surface.

### Workflow 1: Incident Response (HITL Escalation)

This workflow is triggered when the Global Command Center's Triage & Quarantines KPI turns red, indicating pending human-in-the-loop approvals that require immediate operator attention.

1. **Global Command Center** (`/`) → Observe the Triage & Quarantines KPI card. If the pending count is greater than zero, the progress bar fills to 100% red. Click the card to navigate directly to the HITL queue.
2. **HITL Approval Queue** (`/agent-admin/hitl`) → Review each pending saga. For each item, check the target API URL (is the destination expected for this agent?), the agent's trust tier badge (is this a trusted agent or an unverified one?), and the policy violation reason (is the violation legitimate or a false positive?).
3. **Agent Biographies** (via the "Biography" button on each HITL card) → This opens the agent's full biography in a new tab. Check the agent's call history, scope entitlements, and whether HITL was expected for this type of call. Check whether the agent has recent blocked events that might indicate a pattern.
4. **Decision:** Return to the HITL page. Click **Approve** (green) to allow the call through — the Saga Executor will dispatch the resume webhook to the origin service. Click **Reject** (red) to deny the call — a denial webhook is dispatched. If you see a 409 toast, another operator already resolved this trace.
5. **Operator Audit Logs** (`/agent-admin/operator-logs`) → Verify that your decision appears in the immutable audit trail. Filter by action type "hitl_approved" or "hitl_denied" and your operator email. The log should show the exact timestamp, trace ID, and your IP address.

### Workflow 2: Shadow Mode Rollout (Staged Enforcement)

This is the recommended approach for onboarding new agents or deploying new security policies without risking false-positive blocks on production traffic. Shadow Mode lets you observe what would be blocked without actually blocking it.

1. **Governance Registry** (`/registry`) → Select the agents you want to place in Shadow Mode using the checkboxes in the leftmost column. You can use the "select all" checkbox in the header to select every agent, or individually pick specific agents. The selection count appears in the amber "Toggle Shadow Mode" button.
2. **Toggle Shadow Mode** → Click the amber button. This sets the `shadow_mode` flag on each selected agent. From this point, the Gateway will evaluate all policies for these agents, compute full semantic scores, and log any violations to the action ledger — but it will proxy the traffic through with an `X-Cicada-Shadow-Flag` header instead of blocking it.
3. **Security Monitor** (`/compute`) → Watch the "Shadow Flags (24h)" KPI card. This count will begin incrementing as shadow violations are recorded. A rising count is expected during the first 24–48 hours of Shadow Mode — it represents the baseline of policy violations the agent naturally generates.
4. **Activity Ledger** (`/logs`) → Filter the status dropdown to "Shadow Violations." This shows every call that would have been blocked under strict enforcement. Review the violation reasons — are they legitimate concerns or expected behaviour for this agent's use case?
5. **Behaviour Baselines** (`/agent-admin/baselines`) → Check the baseline deviation scores for the agents in Shadow Mode. If their block ratios and confidence scores are within the "Nominal" range, they are ready for strict enforcement gating. If they show "Elevated" or "Critical," tune your security policies first before enabling enforcement.
6. **Governance Registry** (`/registry`) → Return, select the same agents, and click Toggle Shadow Mode again to disable it. From this point, the Gateway enforces strict blocking for these agents. Any policy violation will result in an immediate block.

### Workflow 3: Coordinated Threat Investigation

This workflow is used when you suspect a coordinated attack across multiple agents or tenants.

1. **Threat Correlation** (`/agent-admin/correlation`) → Review the Detected Attack Clusters panel. Identify any cluster with "Critical" or "High" severity. Pay particular attention to clusters that affect multiple agents across multiple tenants — this is the signature of a coordinated attack.
2. **Click "Example Trace"** → This opens the Live Call Inspector (`/pipeline?trace={trace_id}`) with the specific trace pre-loaded. Examine the full verification pipeline — which stage blocked the call, what the swarm confidence score was, and what the exact policy violation was.
3. **Rogue Registry** (`/agent-admin/rogue`, via "All Events") → See every blocked event from this attack pattern. Count how many unique agents and tenants are affected. Check whether the events are temporally clustered (many events in a short window) or spread out.
4. **Generate Aegis Briefing** (back on Threat Correlation) → Click the button to generate a shareable threat summary. Copy this text for your incident report.
5. **Aegis AI** (`/aegis`, via "Ask Aegis") → Get a narrative assessment with specific recommended actions. Aegis will analyse the pattern and suggest whether to quarantine agents, escalate to circuit breaker, or contact affected tenants.
6. **Agent Fleet** (`/nodes`) → For each affected agent, use the "Stop" button to quarantine. This immediately revokes the agent's EVAR token — it cannot make any further calls.

### Workflow 4: SOC2 / ISO 27001 Audit Preparation

This workflow generates the complete evidence package required for a compliance audit.

1. **Compliance Export** (`/agent-admin/audit`) → Set the "From Date" to the beginning of the audit period and "To Date" to the end. Select "All Events" to capture the full scope. Click **Export CSV** — this generates a file with columns: Trace ID, Agent ID, Action Type, Block Status, Target API, Risk Score, Policy Violations, and Timestamp. This is the primary evidence of enforcement action.
2. **Operator Audit Logs** (`/agent-admin/operator-logs`) → Click **Export CSV** for the same date range. This provides the human intervention trail — every operator decision, quarantine action, and policy change during the audit period. Together with the compliance export, this demonstrates both automated and human governance.
3. **Data Retention** (`/agent-admin/retention`) → Verify that all categories show retention periods ≥ 365 days (SOC2 / ISO 27001 minimum). Screenshot the page showing each category, retention period, auto-delete status, and archive-first status. Ensure no category is set to "Hard delete" without "Archive First."
4. **Security Policies** (`/security`) → Screenshot each active policy with its health status (should all show "Healthy") and exception list. Document why each exception exists — auditors will ask.
5. **Behaviour Baselines** (`/agent-admin/baselines`) → Screenshot the current deviation status. This demonstrates continuous behavioural monitoring. Highlight any agents that have been at "Critical Deviation" and document the remediation actions taken.

### Workflow 5: Rogue Agent Response (Shadow AI Discovery)

This workflow handles the discovery and remediation of unmanaged AI agents operating outside the governance perimeter.

1. **Shadow Agent Radar** (`/discovery`) → Identify the ghost agent. Note its name, tenant, intercept count, and whether it has been blocked before (risk level: High vs. Being Monitored).
2. **Block** → Click the red Block button on the agent's card. This sends a revocation request. The agent can no longer make calls through any path.
3. **Rogue Registry** (`/agent-admin/rogue`) → Confirm the block event was recorded in the threat audit trail. Verify the timestamp matches your action. 
4. **Threat Correlation** (`/agent-admin/correlation`) → Check whether this ghost agent's activity correlates with any existing attack clusters. If so, the ghost agent may be part of a larger campaign.
5. **Alert Rules** (`/agent-admin/alerts`) → Add a new rule: Event Type = "Rogue Agent Detected," Channel = "Webhook," Destination = your Slack or PagerDuty URL. This ensures you are notified immediately if another ghost agent appears.
6. **Aegis AI** (`/aegis`) → Ask Aegis to generate a narrative report summarising the ghost agent's activity, the remediation actions taken, and recommendations for preventing recurrence. Share this report with the security team and the affected tenant.

### Workflow 6: API Key Compromise Response

This workflow is triggered when you suspect an API key has been compromised or leaked.

1. **Credential Vault** (`/vault`) → Locate the affected key in the Stored Keys grid. Click **Rotate Key**. The button spins during rotation. A toast confirms success.
2. **Activity Ledger** (`/logs`) → Immediately after rotation, monitor the log stream. The old key should start generating "Blocked" events as the agent attempts to use the revoked key. If you see continued "Approved" events with the old key, the rotation may not have propagated — contact your gateway administrator.
3. **CRM** (`/crm`) → Navigate to the affected company's profile. Note the primary contact. Notify them that their key has been rotated and they need to update it in the Developer Portal.
4. **Operator Audit Logs** (`/agent-admin/operator-logs`) → Verify that your key rotation action was recorded with the action type "api_key_rotated" in the immutable log.

### Workflow 7: New Company Onboarding

This workflow guides an operator through the process of onboarding a new client company onto the platform.

1. **CRM** (`/crm`) → Verify the new company appears in the company list. Check their plan (Starter, Professional, or Enterprise), status ("Pending" for new companies), and primary contact details.
2. **Credential Vault** (`/vault`) → If the company needs platform-provisioned keys, add them using the BYOK input section. Most companies will add their own keys through the Developer Portal.
3. **Governance Registry** (`/registry`) → As the company's agents come online through the Developer Portal registration wizard, they will appear here. Consider placing new agents in Shadow Mode initially using the bulk toggle.
4. **Security Monitor** (`/compute`) → Monitor the Shadow Flags KPI as new agents begin making calls. This gives you a baseline of their normal behaviour before enabling strict enforcement.
5. **Behaviour Baselines** (`/agent-admin/baselines`) → After 24–48 hours of Shadow Mode operation, check the deviation scores. Agents at "Nominal" are ready for strict enforcement. Agents at "Elevated" may need policy tuning first.
6. **Alert Rules** (`/agent-admin/alerts`) → Set up notification rules for the new company's agent activity. At minimum, add rules for "Agent Blocked" and "Circuit Breaker Tripped" pointing to the company's security contact email.

### Workflow 8: ZTNA Posture-Driven Incident Response

1. **ZTNA Trust Posture** (`/ztna-posture`) → Check the aggregate posture gauge. If any pillar is below 85%, review the Posture Issues & Remediation panel for specific guidance.
2. **Pillar filter tabs** → Click the failing pillar tab (e.g., "Failing Auth") to isolate the agents dragging the score down.
3. **View button** → Click "View" on any non-compliant agent. This deep-links to `/nodes?agent=ID` and auto-opens their detail panel in the Agent Registry.
4. **Agent Fleet** (`/nodes`) → Review the agent's trust tier, certification status, and gateway activity. Quarantine if necessary.
5. **Return to ZTNA Posture** → Verify the pillar score has improved after remediation.

---

## 25. ZTNA Trust Posture

**Route:** `/ztna-posture`  
**API Endpoints:** `GET /api/v1/dashboard/summary`, `GET /api/v1/admin/gateways`, `GET /api/v1/nodes`, `GET /api/v1/security/policies`  
**Purpose:** The ZTNA Trust Posture dashboard is the platform's single-pane-of-glass view of fleet-wide Zero-Trust compliance. It evaluates every agent against the four ZTNA pillars — Continuous Authentication, Fine-Grained Authorization, Fabric Enforcement, and Cryptographic Containment — and computes an aggregate compliance score. This is the page a CISO uses to answer: "Is our agentic fleet compliant with our zero-trust architecture?"

**What you see:**

**Header:** "ZTNA Trust Posture" with a live data pulse indicator and the subtitle "Real-time Zero-Trust Network Architecture compliance assessment across all four security pillars."

**Aggregate Posture Gauge (left column):**

- A large SVG radial gauge showing the weighted composite score as a 0–100% value.
- The gauge arc colour changes dynamically: green (>85%, Nominal), amber (60–85%, Degraded), red (<60%, Critical).
- A tier label below the gauge shows the current tier: "NOMINAL POSTURE", "DEGRADED POSTURE", or "CRITICAL POSTURE".
- The score is calculated as: `Auth (30%) + Authz (30%) + Fabric (20%) + Containment (20%)`.
- Below the gauge, a summary line shows total agent count, verified count, and quarantined count.

**Four Pillar Cards (right columns, 2×2 grid):**

Each card represents one ZTNA pillar and shows:

1. **Continuous Authentication (blue)** — Shows the authentication percentage (`verified / total agents`), the count of Ed25519 tokens issued, and flags unverified identities. The health percentage badge (top-right) shows what fraction of agents have verified cryptographic identity.
2. **Fine-Grained Authorization (amber)** — Shows the count of active Wasm/OPA policies, how many are healthy, and flags active policy exceptions. Health percentage reflects what fraction of agents have a clean block rate (<5%).
3. **Fabric Enforcement (orange)** — Shows today's total gateway intercepts, the block rate percentage, and the approved/blocked breakdown. Health percentage reflects what fraction of agents have actively routed through the Sentry Gateway.
4. **Cryptographic Containment (red)** — Shows the quarantined agent count, armed canary tokens, and mesh nodes online. Health percentage reflects what fraction of agents are not revoked/quarantined.

Each card has:
- A **health percentage badge** (top-right) — colour-coded green (>85%), amber (60–85%), or red (<60%).
- A **health bar** — a thin progress bar below the metric showing the pillar health visually.
- **Issue/remediation text** — only appears when the pillar is degraded. Shows a warning icon and specific actionable guidance (e.g., "29 agents have no verified Ed25519 identity — certify via Developer Portal or decommission").
- A **red border** on degraded cards to draw immediate visual attention.

**Posture Issues & Remediation Panel (below pillar cards):**

This panel **only appears when there are active compliance issues** — a clean fleet sees nothing here. When visible:

- A red-bordered section titled "Posture Issues & Remediation" with a badge showing the total issue count.
- Issues are grouped by pillar with colour-coded cards (blue for Auth, amber for Authz, orange for Fabric, red for Containment).
- Each issue includes a specific, actionable remediation instruction — not just a metric. For example:
  - Auth: "29 agents have no verified Ed25519 identity — certify via Developer Portal or decommission."
  - Fabric: "27 agents have never routed through the Sentry Gateway — verify SDK integration or decommission."
  - Authz: "3 policy exceptions active — review and reduce attack surface."

**Per-Agent Posture Ledger (bottom section):**

- A full-width table showing every agent's individual compliance across all four pillars.
- **Pillar filter tabs** at the top: All Agents, Failing Auth (count), Failing Authz (count), Failing Fabric (count), Failing Contain (count). Each tab shows the number of non-compliant agents as a red badge.
- **Table columns:** Agent (name + trust tier badge), Tenant, Status (Active/Revoked), Trust Score (with progress bar), four pillar columns each showing ✓ (green, compliant) or ✗ (red, non-compliant), and an Actions column.
- **View button** — Deep-links to the Agent Registry (`/nodes?agent=ID`), auto-opening the specific agent's detail panel. This is the direct remediation path.

**ZTNA Event Timeline (right sidebar of the ledger):**

- A real-time chronological feed of recent platform events classified by their ZTNA pillar.
- Each event shows: a coloured dot (blue/amber/orange/red matching the pillar), the event description, a pillar badge, and a relative timestamp (e.g., "2m ago").
- Events include: blocked calls (Fabric), quarantine actions (Containment), policy violations (Authorization), and identity verification events (Authentication).
- Auto-refreshes with the page data every 10 seconds.

**What healthy looks like:** The gauge shows >85% in green, all four pillar cards show 100% badges with no issue text, the Posture Issues panel is hidden, and the ledger shows all ✓ badges across every agent.

**What danger looks like:** The gauge drops below 60% (red), pillar cards show red borders with remediation instructions, the Posture Issues panel is visible with multiple issues, and the ledger shows clusters of ✗ badges on specific pillars.

**Cross-page workflow:** Use the pillar filter tabs to isolate failing agents → click "View" to deep-link to the Agent Registry → remediate (certify, quarantine, or decommission) → return to this page to verify the score improved.

---

## 26. CIBA Pending Queue

**Route:** `/agent-admin/ciba`  
**API Endpoints:** `GET /api/v1/admin/ciba/pending`, `POST /api/v1/admin/ciba/{traceId}/admin-respond`  
**Purpose:** The CIBA (Client Initiated Backchannel Authentication) Pending Queue is the operator's global view of all pending out-of-band mobile authorization requests. When an agent attempts a high-risk action and the CIBA flow is active, the Sentry Gateway intercepts the request and sends a push notification to the human owner's mobile device (via the Sentinel Flutter companion app). This page shows every request that is currently waiting for that mobile approval — and gives operators the ability to override (force-approve or force-reject) any request.

**What you see:**

**Header:** "CIBA Global Queue" with a pulsing red badge showing the count of pending requests (e.g., "3 PENDING"). If requests are pending, a red crisis_alert icon pulses beside the title.

**Audio Siren:** When CIBA requests are pending, the page plays an audible siren (a 600Hz–1000Hz frequency sweep) to alert operators even when the browser tab is not in focus. A siren control button appears:
- **"Siren Active — Click to Mute"** (red, pulsing) — Click to silence the siren across all tabs. The mute state is synchronized across browser tabs via BroadcastChannel, so muting in one tab mutes all tabs.
- **"Siren Muted"** (grey) — Click to re-enable the siren.

**Red Pulse Overlay:** When requests are pending, the entire page background pulses subtly red (a CSS animation that fades from 0% to 6% red opacity every 2 seconds). This creates an unmistakable visual urgency signal.

**Pending Queue Cards:** Each pending CIBA request is displayed as a full-width card containing:

- **Countdown Badge (left):** Shows "LIVE" with a live countdown timer (e.g., "4m 32s") that updates every second. When the remaining time drops below 60 seconds, the countdown turns red and pulses. When the request expires, the badge shows "EXPIRED" in grey and the card becomes semi-transparent.
- **Agent Identity:** Agent name, full agent UUID, tenant ID (truncated), and the creation timestamp.
- **Risk Score Gauge:** A large numeric percentage (0–100%) with a colour-coded progress bar: green (<50%), amber (50–79%), red (≥80%). A "CRITICAL RISK" badge pulses red when the risk score ≥80%. An "ELEVATED RISK" badge appears in amber for scores 50–79%.
- **Risk Reason:** If the Gateway assigned a risk reason, it's shown in a red-bordered panel explaining why this request was flagged.
- **Action Summary:** A description of what the agent was attempting to do, displayed in a bordered panel.
- **Target API Endpoint:** The specific URL the agent was trying to call.
- **Payload Preview:** A terminal-styled code panel showing the intercepted request body (with decorative red/yellow/green dots mimicking a terminal window).
- **Trace Reference:** The full trace UUID for audit trail linkage.
- **Timeline:** Shows Created, Expires, and Status timestamps.
- **Compliance Note:** An amber-bordered panel stating: "This decision will be permanently recorded in the immutable action ledger. Both the decision and the operator identity are logged for audit traceability."

**Three Action Buttons per Card:**

1. **Biography** — Opens the agent's full biography page (`/registry/{agent_id}`) in a new tab for context before deciding.
2. **Force Reject** (red) — Sends `POST /api/v1/admin/ciba/{traceId}/admin-respond` with `{decision: 'reject'}`. A toast confirms "CIBA request rejected." The audio siren is muted across all tabs after any decision.
3. **Force Approve** (green) — Sends the same endpoint with `{decision: 'approve'}`. A toast confirms "CIBA request approved."

**Auto-refresh:** The queue polls every 5 seconds. You never need to manually refresh.

**Empty state:** When no requests are pending, a green panel shows a mobile_friendly icon with "No CIBA requests pending. Queue auto-refreshes every 5 seconds." This is the healthy state.

**Cross-page workflow:** CIBA request arrives → review the risk score and action summary → click "Biography" to check the agent's identity and history → force-approve if legitimate, force-reject if suspicious → navigate to the Activity Ledger to confirm the decision was logged.

---

## 27. Shadow Sandbox

**Route:** `/sandbox`  
**API Endpoint:** `GET /api/v1/sandbox/events`  
**Purpose:** The Shadow Sandbox is the monitoring station for agents that have been diverted to Ghost Mode. When an agent is placed in Ghost Mode (via the Governance Registry's bulk toggle or the Shadow Agent Radar), its traffic is routed to the Shadow Sandbox service instead of being processed normally. The Shadow Sandbox runs every request through a 7-rule anomaly detection engine and records the results — without blocking the agent. This page gives operators real-time visibility into what shadow-routed agents are doing, what anomalies have been detected, and whether any agents should be quarantined.

**What you see:**

**Header:** "Shadow Sandbox" with a purple "Ghost Mode — Live Agent Observation" badge. This purple branding distinguishes it from the orange-branded operational pages.

**Control Buttons (top-right):**
- **Clear Filter** (purple, only when an agent filter is active) — Removes the per-agent filter to show all events.
- **Refresh** — Manually reloads sandbox data.

**Summary Stat Cards (4-column grid):**

1. **Total Captures** (blue) — The total number of intercepted requests in the sandbox database.
2. **Monitored Agents** (purple) — The count of unique agents currently being observed.
3. **High Risk Events** (orange) — Events with an anomaly score ≥0.70. If non-zero, a decorative orange glow appears behind the card.
4. **Auto-Quarantined** (red) — Agents that have been automatically quarantined by the gossip mesh based on sandbox findings. If non-zero, a red glow appears.

**Activity Timeline Chart:**

- A horizontal bar chart showing event distribution by hour.
- Each bar has two layers: purple (normal events) and red overlay (high-risk events, ≥0.70 anomaly score).
- Hovering a bar shows a tooltip with exact counts: "N events · M high risk".
- A legend below shows the colour key: purple = Normal, red = High Risk (≥0.70).
- Hour labels are shown every 3 bars to avoid crowding.

**Monitored Agents Panel (card grid):**

- Each agent in the sandbox has a card showing:
  - **Severity badge** (top-right): "Auto-Quarantine" (red, critical ≥0.85), "High Risk" (orange, ≥0.70), "Suspicious" (amber, ≥0.40), or "Nominal" (green, <0.40). Cards with critical/high severity have a coloured glow shadow.
  - **Agent identity:** Name, request count, and last seen timestamp.
  - **Target API hostnames:** Extracted and shown as badges (up to 3, with "+N more" for additional).
  - **Peak Anomaly bar:** A colour-coded progress bar showing the highest anomaly score recorded for this agent.
  - **Quarantine button** (red) — Sends `POST /api/v1/shadow-mode` with `{agent_ids: [id], action: 'activate'}` to force-quarantine the agent. Toast confirms "Agent quarantined — routed to sandbox."
  - **Release button** (green) — Sends the same endpoint with `action: 'release'` to return the agent to normal routing. Toast confirms "Agent released — returning to normal routing."
  - **Clicking a card** filters the event feed below to show only that agent's requests.

**Live Intercepted Traffic Table:**

- A full-width table with a pulsing purple dot indicating live data.
- **Header** shows "Live Intercepted Traffic" with the event count. If filtered to a specific agent, the agent name appears in purple.
- **Table columns:** Expand chevron (►), Time, Agent (purple text), Method/Target (with colour-coded HTTP method badges: green GET, blue POST, amber PUT, red DELETE), Anomaly (percentage with severity-coloured badge), Findings (count of triggered rules), Gossip (podcasts icon if reported to gossip mesh, dash if not).
- **Clicking any row** expands a detail panel showing:
  - **Anomaly Findings:** Each triggered rule shown as a colour-coded card with the rule name (e.g., "Destructive SQL", "SQL Injection", "Credential Leak", "Prompt Injection", "Bulk Email Exfil", "Base64 Exfil", "Oversized Body", "HTTP DELETE"), the hit detail, and the per-rule severity score.
  - **Request Metadata:** Trace ID, Agent ID, and Tenant ID.
  - **Body Snapshot:** The raw request body in a monospace code panel for forensic inspection.

**Seven Anomaly Detection Rules:** The sandbox analyzes every intercepted request against these rules:

| Rule | What It Detects |
|---|---|
| `destructive_sql` | DROP, DELETE, TRUNCATE, ALTER SQL statements |
| `sql_injection` | SQL injection patterns (UNION, OR 1=1, etc.) |
| `credential_in_body` | API keys, passwords, tokens in the request body |
| `prompt_injection_in_body` | Prompt injection attempts ("ignore previous instructions", etc.) |
| `bulk_email_extraction` | Bulk email scraping patterns |
| `large_base64_payload` | Base64-encoded data exfiltration attempts |
| `oversized_body` | Abnormally large request bodies |

**What healthy looks like:** All summary cards show zero or low numbers. The timeline chart shows sparse bars with no red overlay. Agent cards show green "Nominal" badges. The traffic table shows "Clean" in the findings column.

**What danger looks like:** High Risk Events count is elevated. Agent cards show red "Auto-Quarantine" or orange "High Risk" badges with glowing borders. The timeline chart shows red-heavy bars. Clicking into event details reveals triggered anomaly rules with high severity scores.

**Cross-page workflow:** Agent placed in Ghost Mode via Governance Registry → observe their behaviour here → if anomaly scores are consistently low, release them back to normal routing → if scores are high, quarantine them → check the Threat Correlation page for broader attack patterns.

---

## 28. Health Indicators & Colour Reference

The dashboard uses a consistent colour language across all pages. Understanding this language lets you assess platform health at a glance without reading any text.

**Status Colours:**
- **Green** — Healthy, approved, operational, nominal. Used for: approved calls, active agents, online gateways, nominal trust tiers, saved confirmations, connected services.
- **Amber / Orange** — Warning, Shadow Mode, elevated risk, needs attention. Used for: shadow violations, elevated trust tiers, pending HITL items, velocity deviations, Shadow Mode badges.
- **Red** — Danger, blocked, critical, quarantined, revoked. Used for: blocked calls, critical trust tiers, revoked agents, high-risk ghost agents, circuit breaker trips, critical deviations.
- **Blue** — Informational, Aegis AI, read-only. Used for: Aegis branding, help panels, informational badges, role indicators.
- **Grey** — Inactive, insufficient data, timed out. Used for: disabled toggles, insufficient baseline data, timed-out HITL items, unknown states.
- **Purple** — HITL-related. Used for: HITL enabled badges on agent cards.

**Pulsing Animations:**
- A **pulsing red dot** indicates an active threat or item requiring immediate attention (blocked events counter, critical agents, circuit breaker trips).
- A **pulsing amber dot** indicates an ongoing monitoring state (Shadow Mode active, agents being observed).
- A **pulsing green dot** indicates live connectivity (gateway online status, verification engine active).

**Progress Bars:**
- Progress bars throughout the dashboard use the green → orange → red gradient to indicate severity. A fully green bar is healthy. A bar that is partially or fully red requires investigation.

**Trust Tier Badges:**
- **Unverified** (grey) — Agent has not completed identity verification.
- **Nominal** (sky blue) — Agent is operating within normal parameters.
- **Elevated** (yellow) — Agent has triggered some policy violations but is not yet blocked.
- **Critical** (red) — Agent is at high risk. Circuit breaker may be active.

**Deviation Badges (Behaviour Baselines):**
- **Normal Behaviour** (green) — All three metrics (block ratio, confidence, velocity) are within thresholds.
- **Elevated Risk** (orange) — One or more metrics have crossed the elevated threshold.
- **Critical Deviation** (red) — One or more metrics have crossed the critical threshold. The circuit breaker may have already tripped.
- **Insufficient Data** (grey) — Fewer than 5 calls recorded. Baseline cannot be computed.

**Saga Lifecycle Badges (HITL Queue):**
- **SUSPENDED** (amber) — Awaiting operator decision.
- **APPROVED** (green) — Operator approved.
- **DENIED** (red) — Operator denied.
- **TIMED OUT** (grey) — Auto-denied by system cron.
- **DELIVERED** (blue) — Webhook successfully dispatched.
- **RETRYING** (orange) — Webhook delivery retry in progress.
- **DEAD LETTER** (dark red) — All retries exhausted.

---

*End of Manual — Version 3.0*
