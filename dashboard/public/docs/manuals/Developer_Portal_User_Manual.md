# Cicada Developer Portal — Complete User Manual

**Version:** 3.0  
**Last Updated:** 12 June 2026  
**Classification:** Customer-Facing  
**Target Audience:** Customer Developers, Technical Leads, API Integrators  
**Portal URL:** `http://localhost:3001`

---

## Table of Contents

1. [Marketing Landing Page](#1-marketing-landing-page)
2. [Pricing Page](#2-pricing-page)
3. [Documentation Page](#3-documentation-page)
4. [Login & Authentication](#4-login--authentication)
5. [OAuth Callback](#5-oauth-callback)
6. [Portal Sidebar Navigation](#6-portal-sidebar-navigation)
7. [Developer Dashboard](#7-developer-dashboard)
8. [Agent Registry](#8-agent-registry)
9. [Agent Registration Wizard](#9-agent-registration-wizard)
10. [Resource Policies](#10-resource-policies)
11. [Outbound Traffic Monitor](#11-outbound-traffic-monitor)
12. [Inbound Traffic Monitor](#12-inbound-traffic-monitor)
13. [Transaction History](#13-transaction-history)
14. [Company & Profile](#14-company--profile)
15. [Billing & Plan](#15-billing--plan)
16. [Cross-Portal Workflows](#16-cross-portal-workflows)
17. [Agent Detail & Biography](#17-agent-detail--biography)
18. [Marketplace](#18-marketplace)
19. [Boilerplate Scaffold](#19-boilerplate-scaffold)
20. [Policy Simulator](#20-policy-simulator)
21. [Mobile Aegis Companion](#21-mobile-aegis-companion)
22. [Enterprise Deploy](#22-enterprise-deploy)

---

## 1. Marketing Landing Page

**Route:** `/` (unauthenticated)  
**Purpose:** The landing page is the first screen any prospective customer sees when they visit the Developer Portal. If a user is already authenticated (has a `cicada_token` in localStorage), they are immediately redirected to the Dashboard — they never see this page once logged in.

**What you see:**

**Navigation Bar (fixed, top):** The Cicada logo (bug icon + "Cicada" text), two links (Pricing, Docs), and two action items — "Sign in" (text link) and "Get started" (orange CTA button). Both the sign-in and Get started buttons navigate to the Login page.

**Hero Section:** A large centred headline reading "The trust layer for AI agents" with "for AI agents" highlighted in the primary colour. Below it, a subtitle: "Register, certify, and monitor your AI agents on the Cicada network. Every agent gets a cryptographically-signed EVAR token — so every company they contact knows exactly who sent them." A pill badge above the headline reads "Ed25519-signed agent identity" — this immediately signals the cryptographic standard to technical visitors. Two CTAs: "Register your agent" (gradient button) and "View pricing" (outline button).

**How It Works Section:** Three cards in a horizontal grid, numbered 01–03:
- **01 Register** — "Create your company account and describe your AI agent — its type, scope, and failure behaviour."
- **02 Get your EVAR** — "Cicada mints a tamper-proof Ed25519 JWT bound to your agent. Embed it in every outbound request."
- **03 Route traffic** — "Every company running Sentry Gateway will validate your EVAR in milliseconds before admitting your agent."

**Trust Chain Callout Section:** A two-column layout. The left column explains the identity chain: "Full traceability — from agent to human." Four bullet points: Ed25519 EVAR tokens, OAuth identity linking, Swarm verification on every call, and cryptographic rollback. The right column shows a styled code block visualising the identity chain: `action_ledger → agent_id → tenant_id → contact_id → oauth_identity → GitHub / Google ✓ verified`. This demonstrates to prospective customers that every agent action can be traced to a verified human identity.

**Final CTA Section:** "Ready to certify your agent?" with a subtitle "Start on the Starter plan — free for your first agent." and a "Sign up with GitHub" button.

**Footer:** Cicada branding, "AI Agent Trust Layer" tagline, and links to Pricing, Docs, and Sign in.

---

## 2. Deployment Tiers & Quota Profiles

**Route:** `/pricing` (unauthenticated)  
**Purpose:** Displays the three tenant quota profiles and deployment modes. This page is publicly accessible — no login required.

**What you see:**

**Header:** "Deployment Tiers & Quota Profiles" with a subtitle "Self-host the standalone gateway under Apache 2.0 or configure multi-node connected mesh quotas."

**Three Tier Cards (horizontal grid):**

**Starter (Standalone Tier — Open Source):**
- Up to 3 registered agents (configurable via policy)
- Ed25519 EVAR tokens
- Inbound & outbound traffic monitoring
- Transaction ledger (30-day retention)
- Community support
- CTA: "Get started" (outline button)

**Professional (Connected Mesh Tier):**
- Up to 25 registered agents
- Verification Swarm confidence scoring
- Shadow Sandbox honeypot routing
- Policy management controls
- Saga rollback for failed transactions
- 90-day ledger retention
- Priority alert routing
- CTA: "Get started" (gradient button, visually prominent)

**Enterprise (Sovereign Cluster Tier):**
- Unlimited agents
- Self-hosted Sentry Gateway cluster
- Custom BYOK encryption keys
- Dedicated swarm nodes
- Unlimited ledger retention
- PQC Hybrid (Ed25519 + ML-DSA-65) node attestation
- Dedicated cluster administration
- CTA: "Configure cluster" (outline button)

**"All Tiers Include" callout:** OAuth identity verification (GitHub/Google), Ed25519 EVAR token minting, immutable action ledger, and access to the Developer Portal.

---

## 3. Documentation Page

**Route:** `/docs` (unauthenticated)  
**Purpose:** A single-page developer reference covering agent registration, EVAR token usage, verification, and scope definitions. This is the technical onboarding resource that developers read before registering their first agent.

**What you see:**

**Layout:** A sidebar on the left (visible on large screens) with section anchors, and the main content on the right. Five documentation sections:

**Overview:** Explains that the Developer Portal is where you register agents and receive EVAR tokens. States that every EVAR is an Ed25519-signed JWT minted by the Sentry Gateway, bound to your verified company account.

**Registering an Agent:** Lists the 5-step summary of the registration wizard: Name & description, Agent type, Scopes, Failure scope, and API credentials.

**Using your EVAR Token:** Provides the exact HTTP header format: `X-Cicada-EVAR: eyJhbGciOiJFZERTQSJ9...` and explains that companies running Sentry Gateway will validate this header before admitting an agent. Missing or invalid EVARs result in 403 rejection.

**Verifying an EVAR (for Gateway Operators):** Shows the curl command for manual verification: `curl https://your-gateway:8080/v1/verify/agent/<evar_token>`. Explains the response structure: agent identity, tenant, scopes, and certification date.

**Scope Reference Table:**

| Scope | Permitted Actions |
|---|---|
| `proxy:read` | Read data from target systems |
| `proxy:chat` | Send conversational messages |
| `proxy:write` | Create or update records |
| `proxy:transact` | Initiate financial or state-changing actions |
| `proxy:notify` | Send notifications (email, webhook) |
| `proxy:search` | Query and search external data sources |

**Need Help callout:** Provides the support email `support@cicada.ai`.

---

## 4. Login & Authentication

**Route:** `/login`  
**API Endpoint:** `GET {CORE_API}/auth/github`, `GET {CORE_API}/auth/google`  
**Purpose:** The login page authenticates developers via OAuth only — there are no passwords in the Cicada system. This is a deliberate security decision: passwords can be phished, but OAuth identity verification through GitHub or Google provides a verified, attested identity that is cryptographically linked to every agent the developer registers.

**What you see:**

**Header:** "Sign in to Cicada" with the tagline "Register your company and AI agents."

**Error Display:** If the URL contains `?error=oauth_failed` or `?error=registration_failed`, a red error banner appears with the appropriate message. This occurs when the OAuth flow fails at the provider level or when the backend registration encounters an error.

**Two OAuth Buttons:**
- **Continue with GitHub** — Dark (GitHub branded) button with the GitHub SVG icon. Clicking this navigates to `{CORE_API}/auth/github`, which initiates the GitHub OAuth flow. The Laravel backend handles the OAuth handshake.
- **Continue with Google** — White button with the Google multi-colour SVG icon. Navigates to `{CORE_API}/auth/google`.

**Legal Notice:** "By signing in you agree that your verified identity will be cryptographically linked to any agents you register on the Cicada network." This is an informed consent notice — developers must understand that their GitHub or Google identity becomes the root of the trust chain for all their agents.

---

## 5. OAuth Callback

**Route:** `/auth/callback`  
**Purpose:** This is a technical page that the developer never interacts with directly. After OAuth completes, Laravel redirects the browser to this URL with the authentication token embedded in the URL fragment (not the query string — fragments never hit server logs, protecting the token from server-side logging).

**What happens:** The URL format is `/auth/callback#token=<value>&tenant=<uuid>&plan=<tier>`. The page extracts the token, tenant ID, and plan from the fragment, stores them in `localStorage` under the keys `cicada_token`, `cicada_tenant`, and `cicada_plan`, and redirects to `/dashboard`. If the token or tenant is missing, the user is redirected to `/login?error=oauth_failed`.

**What you see:** A loading spinner with "Verifying identity..." while the redirect processes. Under normal conditions, this page is visible for less than one second.

---

## 6. Portal Sidebar Navigation

**Component:** `layout.tsx` (portal layout)  
**Purpose:** Once authenticated, every page in the Developer Portal uses a fixed sidebar + main content layout. The sidebar provides navigation and session context.

**Structure (top to bottom):**

1. **Logo:** "CICADA" in primary orange with "Developer Portal" subtitle. This confirms you are in the Developer Portal, not the Gateway Portal or Operator Dashboard.

2. **Navigation Groups:**
   - **OVERVIEW:** Dashboard
   - **AGENTS:** Registry, Register New
   - **TRAFFIC:** Outbound, Inbound
   - **HISTORY:** Transactions
   - **TOOLS:** Marketplace, Scaffold, Simulator
   - **SECURITY:** Aegis Mobile Companion
   - **ENTERPRISE:** Deploy (Enterprise plan only)
   - **ACCOUNT:** Company, Billing

3. **User Panel (bottom):** Shows the authenticated contact's avatar (from GitHub/Google), name, and plan tier (colour-coded: grey for Starter, orange for Professional, purple for Enterprise). A "Sign out" button clears localStorage and redirects to `/login`.

**Active State:** The currently active page is highlighted with a tinted background and the text turns to the primary colour. This is consistent across all pages.

**Session Management:** The layout calls `GET /api/v1/auth/me` on mount with the stored token. If the token is invalid or expired, localStorage is cleared and the user is redirected to Login. This means stale sessions are automatically cleaned up.

---

## 7. Developer Dashboard

**Route:** `/dashboard`  
**API Endpoint:** `GET /api/v1/portal/summary`  
**Purpose:** The dashboard is the first screen authenticated developers see. It provides a snapshot of their account status across six KPI cards and four quick-action links. The greeting is personalised — it shows the developer's first name and company.

**What you see:**

**Header:** "Welcome back, {FirstName}" with the company name below in muted text.

**Six KPI Cards (3×2 grid):**

1. **Total Agents** — The total number of agents registered under this company. Icon: robot.
2. **Certified** — Agents that have passed the Verification Swarm and received their EVAR token. Icon: verified (green). This is the target state for all agents.
3. **Pending Cert.** — Agents awaiting Swarm verification. Icon: pending (yellow). Newly registered agents start here.
4. **Transactions** — Total count of all ledger entries (calls made by this company's agents). Icon: receipt.
5. **Blocked Today** — Number of the company's agent calls that were blocked by any Gateway today. Icon: block (red). If this is non-zero, something is wrong with one or more agents.
6. **Terminated** — Agents that have been revoked. Icon: cancel (grey).

**Quick Actions (2×2 grid):**
- **Register an Agent** → `/agents/register` — "Step-by-step provisioning wizard"
- **View Registry** → `/agents` — "Check certification status"
- **Transaction History** → `/transactions` — "Full ledger of agent actions"
- **Update Company Details** → `/account/company` — "Profile and contact info"

Each quick action card shows an icon, title, and description.

---

## 8. Agent Registry

**Route:** `/agents`  
**API Endpoint:** `GET /api/v1/portal/agents`  
**Purpose:** The Agent Registry lists every agent registered under the current company. It is the primary lifecycle management view — you can see which agents are certified, which are pending, which need recertification, and which have been terminated.

**What you see:**

**Header:** "Agent Registry" with the subtitle "All agents registered under your account." A "Register Agent" button in the top-right navigates to the registration wizard.

**Filter Tabs:** Five pill-style filter buttons — All, Certified, Pending, Needs Recert., Terminated. Only one can be active at a time. The active tab turns orange. These filters operate client-side on the already-loaded data.

**Agent Cards:** Each agent is displayed as a horizontal card showing:
- **Robot icon** — An orange-tinted icon on the left.
- **Agent name** — Bold headline text. Unnamed agents show "Unnamed Agent."
- **Metadata line** — Agent type (reactive, heartbeat, scheduled, autonomous), version number, and lifecycle dates: "Certified {date}", "Recert. due {date}", or "Terminated {date}" depending on the agent's status.
- **EVAR Preview** — A truncated preview of the agent's EVAR token in monospace text. This lets the developer confirm which token maps to which agent without exposing the full token.
- **Status Badge (right side)** — Colour-coded pill:
  - **Certified** (green, verified icon) — The agent has a valid EVAR and is accepted by Gateways.
  - **Pending Cert.** (yellow, pending icon) — Registration complete but Swarm verification has not finished.
  - **Recert. Required** (orange, refresh icon) — The agent's certification has expired and needs renewal.
  - **Terminated** (red, cancel icon) — The agent has been revoked. Its EVAR is no longer valid.

**Empty State:** If no agents exist, a large robot icon and "No agents found" message appear, with a "Register your first agent →" link.

---

## 9. Agent Registration Wizard

**Route:** `/agents/register`  
**API Endpoint:** `POST /api/v1/provision/agent`  
**Purpose:** The registration wizard is the most critical page in the Developer Portal. It is an 8-step guided form that collects every piece of information required to anchor an agent's operational boundaries into the Cicada trust framework. Upon completion, the backend generates an Ed25519 keypair, mints an EVAR token, and the agent is provisioned into the system.

**Step Indicator:** A horizontal strip of 8 numbered steps, each showing an icon and label. Completed steps show a green checkmark. The current step is highlighted in orange. Steps are: Identity, Governance, Architecture, Scope, Tools, Failure, Security, API Key.

**Navigation:** "← Back" button on the left, "Continue →" on the right. Each step has validation — the Continue button is disabled until required fields are filled. On the final step, the button reads "Register & Get EVAR →."

### Step 1: Identity

**Purpose:** Name and describe your agent.

- **Agent Name*** — Required. This is the human-readable name that appears in audit logs, the Operator Dashboard, and Gateway rejection messages. Example: "Acme Invoice Processor."
- **Description** — Optional but recommended. Explains what the agent does and what problem it solves. This is stored as evidence and shown in the agent's biography.
- **Version** — Defaults to "1.0.0." Use semantic versioning. Version changes trigger recertification by the Verification Swarm.

### Step 2: Governance

**Purpose:** Declare ownership, business context, and compliance requirements. This forms the legal evidence trail.

- **Owner Name*** — Required. The human responsible for this agent.
- **Owner Email** — Email of the responsible human.
- **Business Unit** — Department or team (e.g., Finance, Engineering, Ops).
- **Cost Center** — Internal accounting code.
- **Declared Purpose*** — Required. A natural-language statement of the agent's specific business purpose and the decisions it can make autonomously.
- **Registration Purpose Statement** — Formal legal statement of why this agent is being deployed. Stored as immutable evidence.
- **Expected Call Volume (per hour)** — Numeric. Used by the Behaviour Baselines system to detect velocity anomalies. Spikes above this value trigger alerts.
- **Monthly Budget (USD)** — BYOK cost cap. If the agent exceeds this, its root key is throttled.
- **Criticality Level** — Four options presented as cards with descriptions:
  - **Low** (green) — Non-essential. Failure has minimal impact.
  - **Medium** (blue) — Standard business process. Disruptive but recoverable.
  - **High** (orange) — Core workflow. Significant operational or financial impact.
  - **Critical** (red) — Mission-critical. Immediate regulatory, financial, or safety consequences.
- **Data Classification** — Four options: Public, Internal, Confidential, Restricted.
- **Regulatory Frameworks** — Multi-select toggle buttons for: GDPR, HIPAA, SOC 2, ISO 27001, PCI DSS, EU AI Act, CCPA, FCA, DORA.

### Step 3: Architecture

**Purpose:** Define how the agent operates and its role in multi-agent workflows.

**Operation Type** — Four radio-style cards:
- **Reactive** — Responds to direct requests on demand.
- **Heartbeat** — Runs on a regular interval, polling or monitoring.
- **Scheduled** — Triggered at specific times or by a cron.
- **Autonomous** — Self-directed, sets its own sub-tasks and goals.

**Orchestration Role** — Five radio-style cards:
- **Autonomous** — Operates without an orchestrator. Held to highest Swarm confidence (≥0.80).
- **Orchestrator** — Can spawn and direct sub-agents. Requires proxy:write minimum.
- **Sub-agent** — Only acts when invoked by a specific orchestrator (must bind to orchestrator ID).
- **Peer** — Communicates laterally with other certified agents. Cannot spawn sub-agents.
- **Tool Executor** — Passive. Only executes tools when called by another agent.

If "Sub-agent" is selected, an additional field appears: **Orchestrator Agent ID*** — The UUID of the parent orchestrator this sub-agent is bound to.

### Step 4: Scope Entitlements

**Purpose:** Declare every action the agent is permitted to perform. The Sentry Gateway enforces these on every request.

Six checkboxes:
- **Chat Completion** (`proxy:chat`) — Send messages to LLM endpoints.
- **Read Data** (`proxy:read`) — Read from external APIs or databases.
- **Write Data** (`proxy:write`) — Create or update external records.
- **Transact** (`proxy:transact`) — Execute financial or state-changing operations.
- **Send Notifications** (`proxy:notify`) — Email, webhook, or push alerts.
- **Web Search** (`proxy:search`) — Query public search or retrieval endpoints.

At least one scope must be selected to proceed.

### Step 5: Tool Declaration

**Purpose:** List every tool the agent is permitted to call. The Gateway flags any undeclared tool call as a V10 policy violation. Optional but strongly recommended.

**Empty state:** "No tools declared yet. Undeclared tool calls will be flagged as V10 violations by Aegis-0."

**Add Tool button** — Creates a new tool entry with three fields:
- **Tool Name*** — e.g., "send_email"
- **Tool ID** — Auto-generated from the name if left blank.
- **Description** — What the tool does.

Each tool has a delete button. Multiple tools can be added.

### Step 6: Failure Behaviour

**Purpose:** Declare what the agent is permitted to do when blocked or rejected. This is a mandatory declaration.

**Warning panel (yellow):** "The Verification Swarm will specifically red-team your failure paths. Be accurate — declaring a wider failure scope than needed reduces your agent's trust tier."

Four radio-style options:
- **Silent Exit** — Stop immediately, take no further action.
- **Retry Once** — Attempt the same request one more time then stop.
- **Notify Owner** — Fire a webhook to the registered owner endpoint.
- **Queue for Review** — Place the job in a dead-letter queue for manual review.

### Step 7: Security Options

**Purpose:** Configure Shadow Mode and Human-in-the-Loop approval.

**Shadow Mode** — Toggle switch (amber when active):
- Description: "Log violations without blocking traffic. The Gateway will evaluate all policies and record results to the audit ledger, but allow the call to proceed."
- When enabled, an amber info panel appears: "Shadow Mode active — policy violations will be logged but traffic will NOT be blocked. Velocity limits and circuit breakers remain enforced regardless."

**Human-in-the-Loop Approval** — Toggle switch (green when active):
- Description: "When enabled, the Sentry Gateway intercepts any proxy:write or proxy:transact call, encrypts the payload, and immediately returns a 202 Accepted. The trace is held in a Suspended Saga queue while a human reviews it asynchronously."
- When enabled, three additional fields appear:
  - **Info panel (yellow):** Explains the async saga model — no TCP hold, auto-denial on timeout.
  - **Resume Webhook URL*** — Required. The URL the Saga Executor posts the approval/denial decision to. Example: `https://your-system.com/cicada/resume`.
  - **Timeout Hours** — Number input (1–168). Default: 24. If no operator acts within this window, the trace is automatically denied by a background cron.

When HITL is disabled: "Off — calls proceed through Swarm verification only."

### Step 8: API Key Binding

**Purpose:** Bind the tenant's LLM provider API key. BYOK — Cicada never stores the raw key after encryption.

- **LLM Provider** — Dropdown: OpenAI, Anthropic, Google Gemini, Cohere.
- **API Key*** — Password input field. The key is encrypted with AES-256 immediately and stored only in encrypted form.
- **Target Model** — Text input, defaults to "gpt-4o."

**Registration Summary:** A compact summary panel showing every field in two columns: Name, Owner, Type, Role, Criticality, Classification, Scopes (count), Tools (count), Velocity, Budget, and Regulatory Frameworks.

**Submit:** Clicking "Register & Get EVAR →" sends `POST /api/v1/provision/agent` with the complete form payload. On success, the developer is redirected to `/agents?registered=1`. On failure, a red error panel shows the exact error message.

---

## 10. Resource Policies

**Route:** `/agents/{id}/policies`  
**API Endpoints:** `GET /api/v1/portal/agents/{id}/policies`, `POST /api/v1/portal/agents/{id}/policies`, `PATCH /api/v1/portal/agents/{id}/policies/{policyId}`, `DELETE /api/v1/portal/agents/{id}/policies/{policyId}`  
**Purpose:** Resource Policies add fine-grained URL-level access control on top of scope entitlements. An agent with `proxy:write` scope can be restricted to writing only to specific API endpoints. This is the precision layer of the security model.

**What you see:**

**Breadcrumb:** Agents → Resource Policies.

**How It Works panel (green):** Three rules:
1. If no policies are set, the agent is governed by scope entitlements alone.
2. Once any policy is added, every call is checked against this list. Calls to non-matching URLs are denied regardless of scope.
3. Patterns support a trailing wildcard: `https://api.stripe.com/v1/charges*`.

**Add Policy Form:**
- **URL Pattern** — Text input for the URL pattern with wildcard support.
- **Allowed HTTP Methods** — Five toggle buttons: GET, POST, PUT, PATCH, DELETE. Multiple can be selected. At least one is required.
- **Add Policy button** — Sends `POST` to create the policy. Button is disabled until both pattern and at least one method are provided.

**Policy Table:** Each active policy shows:
- **Pattern** — The URL pattern in monospace primary text.
- **Methods** — Pill badges for each allowed method.
- **Status toggle** — A switch to enable/disable the policy. Sends `PATCH` to update. Disabled policies are retained in the database but not enforced by the Gateway.
- **Delete button** — Red trash icon. Sends `DELETE` to permanently remove the policy.

**Empty state:** "No policies yet — agent is governed by scopes only."

---

## 11. Outbound Traffic Monitor

**Route:** `/traffic/outbound`  
**API Endpoint:** `GET /api/v1/portal/traffic/outbound`  
**Purpose:** Shows every call made by your agents that passed through the Sentry Gateway. This is the developer's view of their own agents' activity — unlike the Operator Dashboard's Activity Ledger which shows all tenants, this page is scoped to your company only.

**What you see:**

**Header:** "Outbound Traffic" with a total count.

**Status Filter Tabs:** Five pill buttons — All, Approved, Blocked, Pending Swarm, Shadow Sandbox.

**Traffic Cards:** Each record shows:
- **Arrow-out icon** — Indicates outbound direction.
- **Agent name** — Which of your agents made the call.
- **Target API** — The destination URL.
- **Timestamp** — When the call occurred.
- **Swarm Confidence** — The confidence score from the Verification Swarm (if available), displayed as a percentage.
- **Status badge** — Colour-coded: approved (green), blocked (red), pending swarm (yellow), shadow sandbox (purple).

**Pagination:** Previous/Next buttons with page counter when results exceed one page.

**Empty state:** "No outbound traffic recorded yet. Traffic appears here once your agents start making requests."

---

## 12. Inbound Traffic Monitor

**Route:** `/traffic/inbound`  
**API Endpoint:** `GET /api/v1/portal/traffic/inbound`  
**Purpose:** Shows external agents that have arrived at your Sentry Gateway installation. This page only has data if you have deployed a Gateway (Professional or Enterprise plan). It shows how other companies' agents are interacting with your systems.

**What you see:**

**Header:** "Inbound Traffic" with a subtitle "External agents that have arrived at your Sentry Gateway installation."

**Three States:**

1. **No Gateway Detected:** A large shield icon with "No Gateway Installation Detected." Explains that inbound traffic appears once you install the Sentry Gateway. Includes a "Gateway Installation Guide" link (opens external documentation).

2. **Gateway Installed, No Traffic:** "No inbound agents recorded yet."

3. **Active Traffic:** Each record shows:
   - **Arrow-in icon** — Indicates inbound direction.
   - **Payload hash** — A truncated hash of the encrypted payload (first 16 characters). This is a structural identifier, not the actual payload content.
   - **Target API** — The internal endpoint the external agent was trying to reach.
   - **Timestamp.**
   - **Status badge** — Same colour coding as outbound: approved, blocked, pending swarm, shadow sandbox.

**Total count and pagination** available when records exist.

---

## 13. Transaction History

**Route:** `/transactions`  
**API Endpoint:** `GET /api/v1/portal/transactions`  
**Purpose:** The Transaction History is the developer's full action ledger — every call made by every agent under this company, with complete filtering and search capabilities. While the Outbound Traffic view focuses on direction, this view focuses on forensic detail.

**What you see:**

**Header:** "Transaction History" with a total record count.

**Filters (inline row):**
- **Search** — Text input searching by target API URL.
- **Status dropdown** — All statuses, Approved, Blocked, Pending Swarm, Shadow Sandbox.
- **Date From / Date To** — Date pickers for time-range filtering.
- **Clear filters** — Only visible when filters are active. Resets all filters.

**Table View:** A structured table with columns:
- **Agent** — Which agent made the call.
- **Target API** — Destination URL (truncated with ellipsis for long URLs).
- **Action** — The action type (e.g., proxy:write, proxy:chat).
- **Status** — Colour-coded badge: approved (green), blocked (red), pending swarm (yellow), shadow sandbox (purple).
- **Confidence** — Swarm confidence score as a percentage, or "—" if not yet scored.
- **Time** — Timestamp of the call.

**Pagination:** Previous/Next with page counter.

**Empty state:** "No transactions found." with a receipt icon.

---

## 14. Company & Profile

**Route:** `/account/company`  
**API Endpoints:** `GET /api/v1/portal/company`, `PUT /api/v1/portal/company`  
**Purpose:** View and update your company details and primary contact information. This is also where you see your verified OAuth identities — the identity chain root.

**What you see:**

**Header:** "Company & Profile" with the subtitle "Your organisation details and contact information."

**Company Details Section:**
- **Company Name** — Text input.
- **Company Email** — Email input.
- **Company Phone** — Phone input.
- **Website** — URL input.
- **Registered Address** — Text input (full width).

**Primary Contact Section:**
- **Full Name** — Text input.
- **Phone** — Phone input.
- **Role / Title** — Text input.
- **Verified Identities** — Read-only. Shows each OAuth provider linked to this account as a pill badge with a verified checkmark (e.g., "⚙ GitHub — user@email.com"). These are set by OAuth and cannot be changed from this page. A note explains: "Verified identities are set by OAuth and cannot be changed here. All your agent actions are traceable to these accounts."

**Save Changes button** — Sends `PUT /api/v1/portal/company` with all form fields. Shows "Saving…" during the request and a green "Changes saved successfully" confirmation on success.

---

## 15. Billing & Plan

**Route:** `/account/billing`  
**API Endpoint:** `PUT /api/v1/portal/billing/plan`  
**Purpose:** View your current plan and upgrade or downgrade between plan tiers.

**What you see:**

**Header:** "Billing & Plan" with the current plan name displayed in orange.

**Three Plan Cards (same layout as the Pricing page but with interactive controls):**

Each card shows the plan name, price, feature list, and an action button:
- **Current plan** — Shows a green "Active" badge and a non-interactive "Current Plan" indicator.
- **Available plan** — Shows a "Switch to {Plan}" button. Clicking it sends `PUT /api/v1/portal/billing/plan` with the selected plan. The button shows "Updating…" during the request.
- **Enterprise** — Shows "Contact Sales" linking to `mailto:sales@cicada.io`.
- **Most Popular** badge appears on the Professional plan.

**Plan change confirmation:** A green "Plan updated. Changes take effect immediately." message flashes for 3 seconds after a successful change. The `cicada_plan` value in localStorage is also updated.

**Cancellation Notice:** "Need to cancel? Contact us at support@cicada.io and we will handle it promptly. Your agent data is retained for 30 days after cancellation."

---

## 16. Cross-Portal Workflows

### Workflow 1: First Agent Registration

1. **Landing Page** → Click "Get started" or "Sign up with GitHub."
2. **Login** → Authenticate via GitHub or Google OAuth.
3. **Dashboard** → The KPI cards show all zeros. Click "Register an Agent."
4. **Registration Wizard** → Complete all 8 steps. Pay special attention to Step 4 (Scopes) — only declare what you genuinely need. Step 7 — consider enabling Shadow Mode for your first agent.
5. **Agent Registry** → Your new agent appears with "Pending Cert." status. Once the Swarm verifies it, the status changes to "Certified."
6. **Dashboard** → The "Total Agents" and "Certified" KPIs update.

### Workflow 2: Monitoring Agent Health

1. **Dashboard** → Check the "Blocked Today" KPI. If non-zero, investigate.
2. **Outbound Traffic** → Filter by "Blocked" status. Identify which agent and target API are being blocked.
3. **Transaction History** → Search for the specific target API. Check the Swarm confidence score — below 40% indicates a trust problem.
4. **Agent Registry** → Check the agent's status. Is it "Recert. Required"? If so, the EVAR has expired.
5. **Resource Policies** (if applicable) → Check if the agent has URL-level policies that are restricting access to the target.

### Workflow 3: Adding Fine-Grained Access Control

1. **Agent Registry** → Identify the agent you want to restrict.
2. **Resource Policies** (`/agents/{id}/policies`) → Add a policy with the URL pattern and allowed methods.
3. **Outbound Traffic** → Monitor the agent's next calls. Calls to non-matching URLs will now show "blocked" status.

### Workflow 4: Plan Upgrade

1. **Dashboard** → You've hit the Starter plan's 3-agent limit.
2. **Billing** → Switch to Professional. Changes take effect immediately.
3. **Agent Registry** → You can now register up to 25 agents.
4. **Inbound Traffic** → With Professional, you now have Gateway installation access. Inbound traffic will populate once the Gateway is deployed.

### Workflow 5: Marketplace Template → Agent Registration

1. **Marketplace** (`/marketplace`) → Browse available templates.
2. **Import** → Click "Use Template" on a template card. This creates a pre-filled agent from the template.
3. **Agent Detail** (`/agents/{id}`) → You are redirected to the new agent's biography. Review the pre-filled fields.
4. **Registration Wizard** → If governance fields need updating, click "Update registration details."
5. **Agent Registry** → The new agent appears with "Pending Cert." status.

### Workflow 6: Mobile Device Pairing for HITL

1. **Aegis Companion** (`/aegis`) → Click "Generate Pairing QR Code."
2. **Mobile App** → Open the Aegis app on your phone and scan the QR code.
3. **Device Table** → Your device appears in the Enrolled Devices table with "Active" status.
4. **Agent Registration** → Enable HITL on an agent (Step 7 of registration wizard).
5. **Real-time** → When the agent triggers a HITL call, your phone receives a push notification for approval/rejection.

---

## 17. Agent Detail & Biography

**Route:** `/agents/{id}`  
**API Endpoint:** `GET /api/v1/portal/agents/{id}`  
**Purpose:** The Agent Detail page is the comprehensive biography of a single agent — every identity field, governance declaration, scope entitlement, tool declaration, security setting, and Verification Swarm verdict. This is the page you use to understand the complete posture of one specific agent, manage its lifecycle state, and identify governance gaps that prevent certification.

**How to reach this page:** Click any agent card in the Agent Registry (`/agents`) to navigate here.

**What you see:**

**Navigation:** A "← Back to registry" link at the top returns you to the Agent Registry.

**Header:** The agent name in large bold text, its UUID in monospace below, and three badges on the right:
- **Trust Tier badge** — Colour-coded: Nominal (green), Elevated (orange), Critical (red), Unverified (grey).
- **Swarm Verdict badge** — ALLOW (green) or BLOCK (red). Only appears after the Verification Swarm has evaluated the agent.
- **Status badge** — Shows the current lifecycle state: CERTIFIED, PENDING_REVIEW, SUSPENDED, TERMINATED, ESCALATION_REQUIRED.

**Lifecycle Action Buttons:** Context-sensitive buttons appear based on the current status:
- **Certify** (green) — Appears for agents in `pending_review` or `escalation_required` status. Sends `POST /api/v1/portal/agents/{id}/certify`.
- **Suspend** (orange) — Appears for certified agents. Temporarily revokes the EVAR without termination.
- **Re-Certify** (green) — Appears for suspended agents. Restores certification.
- **Terminate** (red) — Appears for all non-terminated agents. Permanently revokes the EVAR and marks the agent as terminated. Confirmation dialog required.

**Governance Completeness Warning (conditional):**

If any mandatory governance fields are missing, a red-bordered panel titled "Governance Completeness Failure" appears showing:
- A governance score percentage (e.g., "67% complete")
- Each missing field with a ✗ icon, the field name, and an explanation of why it matters (e.g., "Declared Purpose — Swarm cannot verify intent alignment")
- A link: "Update registration details" → navigates to the agent edit form.

The six mandatory fields checked are: Declared Purpose, Owner Name, Owner Email, Business Unit, Expected Velocity, Monthly Budget.

**Identity & Birth Section:**
- Two-column grid showing: Agent Name, Version, Agent Type, Role, Criticality, Data Classification, Target Model, Registered date, Certified date, Recertification Due date.
- Description field (full width).
- **EVAR Token Preview** — The truncated EVAR token in monospace orange text. Shows "Not issued" if the agent hasn't been certified.

**Governance Profile Section:**
- Owner Name, Owner Email, Business Unit, Cost Center (each flagged with ⚠ "Not declared" in red if missing).
- Max Velocity (calls/hr), Monthly Budget Cap (USD).
- Declared Purpose and Registration Purpose Statement.
- **Regulatory Frameworks** — Orange pill badges for each declared framework (e.g., GDPR, SOC 2, HIPAA).

**Scope Declaration Section:**
- If scopes are declared: Pill badges for each scope (e.g., `proxy:read`, `proxy:write`).
- If no scopes: Red warning with "No scopes declared — this agent has no permission boundary. The Gateway cannot enforce any policy."

**Declared Tools Section (conditional):**
- Only appears if the agent has declared tools.
- Each tool shown as a card with: tool icon, tool name (bold), and tool description.

**Security & Failure Settings Section:**
- Two-column grid showing: HITL Enabled (green Yes / grey No badge), Shadow/Observe-Only Mode (amber Enabled / grey Disabled badge), HITL Timeout (hours), Failure Behaviour, HITL Webhook URL (monospace).

**Verification Swarm Verdict Section:**
- If no swarm verification has run: "No swarm verification has run for this agent yet."
- If verified: Shows the verdict badge (ALLOW/BLOCK), confidence score (0–100), and the swarm's reasoning as bullet points.

---

## 18. Marketplace

**Route:** `/marketplace`  
**API Endpoints:** `GET /api/v1/portal/marketplace/templates`, `POST /api/v1/portal/marketplace/templates/{id}/import`  
**Purpose:** The Marketplace is a library of pre-configured agent templates. Templates are production-ready agent configurations that can be imported with one click — creating a new agent with all identity, governance, and scope fields pre-filled. This dramatically accelerates agent onboarding for common use cases.

**What you see:**

**Header:** "Agent Marketplace" with the subtitle "Pre-configured agent templates for common use cases."

**Template Cards (grid layout):** Each template is displayed as a card showing:
- **Template name** — Bold headline text.
- **Description** — What the template does and what use case it serves.
- **Verified badge** — A green checkmark pill ("Verified") appears on templates that have been validated by the platform. Non-verified templates show an amber "Community" badge.
- **Download count** — How many times this template has been imported across the platform.
- **"Use Template" button** (orange) — Sends `POST /api/v1/portal/marketplace/templates/{id}/import` to clone the template into a new agent under your tenant. On success, you are redirected to the new agent's detail page (`/agents/{id}`). During import, the button shows "Importing..." and is disabled.

**Loading state:** A spinner appears while templates are being fetched.

**Empty state:** If no templates are available, a message indicates the marketplace is being populated.

**Cross-page workflow:** Browse templates → click "Use Template" → review the pre-filled agent on the detail page → update governance fields if needed → agent enters the certification pipeline.

---

## 19. Boilerplate Scaffold

**Route:** `/scaffold`  
**Purpose:** The Boilerplate Scaffold generator produces production-ready SDK integration code for connecting an agent to the Cicada Sentry Gateway. Developers select their programming language, framework, authentication method, and scope declarations, and the scaffold generates a complete, copy-paste-ready code package.

**What you see:**

**Header:** "Agent Scaffold Generator" with the subtitle "Generate production-ready boilerplate for integrating your agent with the Cicada Sentry Gateway."

**Configuration Panel (left side):**

- **Language selector** — Dropdown or card selector for: Python, TypeScript/Node.js, Go, Ruby, Java. Each language produces framework-specific code.
- **Framework** — Context-dependent: e.g., FastAPI/Flask for Python, Express/NestJS for TypeScript.
- **Authentication method** — EVAR Token (default) or mTLS.
- **Scope checkboxes** — Same six scopes as the registration wizard. Selected scopes are embedded in the generated code.
- **Agent name** — Pre-filled from context if available.

**Generated Code Panel (right side):**

- A syntax-highlighted code editor showing the generated boilerplate.
- **Copy to clipboard button** — Copies the entire generated code.
- **Download as ZIP button** — Downloads a structured project directory with the generated files.
- The code includes:
  - SDK initialisation with the Sentry Gateway URL.
  - EVAR token header injection.
  - Scope-aware request methods (only methods matching declared scopes are generated).
  - Error handling for Gateway rejections (403 with EVAR validation errors).
  - Retry logic matching the declared failure behaviour.

---

## 20. Policy Simulator

**Route:** `/simulator`  
**API Endpoint:** Directly calls the Sentry Gateway with `X-Cicada-Dry-Run: true` header  
**Purpose:** The Policy Simulator lets developers test API calls against the Sentry Gateway without actually executing them. By setting the `X-Cicada-Dry-Run: true` header, the Gateway runs the full verification pipeline — EVAR validation, scope checking, policy evaluation, Swarm confidence scoring — but does not forward the request to the target API. This gives developers immediate feedback on whether their agent would be allowed or blocked.

**What you see:**

**Header:** "Policy Simulator" with the subtitle "Test your agent's requests against the Sentry Gateway without executing them."

**Request Builder (left panel):**

- **EVAR Token** — Text input for the agent's EVAR token. Paste the full JWT here.
- **Endpoint selector** — Dropdown choosing between:
  - `/v1/agent/request` — Standard proxy request (shows Target URL field).
  - `/v1/chat/completions` — LLM proxy request (shows Provider and Model fields).
- **Target URL** — Only visible for agent/request endpoint. The URL the agent would be trying to reach.
- **Provider / Model** — Only visible for chat/completions endpoint. Dropdown for the LLM provider (e.g., "openai") and a text input for the model (e.g., "gpt-4o").
- **HTTP Method** — Dropdown: GET, POST, PUT, DELETE.
- **Request Body** — A code editor textarea for the JSON payload. Pre-filled with a sample request body.
- **"Run Simulation" button** (orange) — Sends the request to the Gateway. Button shows "Simulating..." during the request.

**Response Viewer (right panel):**

- **HTTP Status Code** — Large numeric display, colour-coded: green (200–299), red (400–499), amber (500+).
- **Response Headers** — Key-value display of all response headers from the Gateway.
- **Response Body** — Formatted JSON showing the Gateway's decision:
  - `allowed`: boolean
  - `reason`: string (e.g., "EVAR valid, scopes satisfied, Swarm confidence 0.87")
  - `violations`: array of policy violations (if any)
  - `swarm_confidence`: number
  - `dry_run`: true

**Cross-page workflow:** Register an agent → copy its EVAR token → paste into the simulator → test various endpoints → verify the Gateway's enforcement decisions before deploying the agent in production.

---

## 21. Mobile Aegis Companion

**Route:** `/aegis`  
**API Endpoints:** `POST /v1/portal/pair/generate` (Sentry Gateway), `GET /v1/portal/devices` (Sentry Gateway), `POST /v1/portal/devices/{id}/revoke` (Sentry Gateway)  
**Purpose:** The Mobile Aegis Companion page manages the pairing between the developer's mobile device and the Cicada Platform. Once paired, the mobile device receives cryptographically-signed push notifications for Human-in-the-Loop (HITL) approval requests. The pairing uses Zero-Trust Device Binding — the mobile device generates a private key inside its Secure Enclave that never leaves the device.

**What you see:**

**Header:** "Mobile Aegis Companion" with the subtitle "Pair your mobile device with the Cicada Platform to receive cryptographically secure, out-of-band alerts for Human-In-The-Loop (HITL) actions."

**Three-Step Pairing Guide (left side):**

1. **Download the Aegis App** — Instructions to install the Aegis companion app on iOS or Android. Includes a direct download link for the Android APK ("Download Android APK (v3.0.0 Release)") served from the platform's APK server.
2. **Generate Pairing Code** — "Generate a unique, single-use cryptographic token to bind your specific mobile device to this tenant."
3. **Scan QR Code** — "Open the Aegis app and tap 'Scan QR Code' to complete the hardware binding."

**QR Code Panel (right side):**
- **Before generation:** Shows a large QR code scanner icon and a "Generate Pairing QR Code" button (orange). Clicking sends `POST /v1/portal/pair/generate` to the Sentry Gateway.
- **After generation:** Displays the QR code containing a structured signed JSON payload (`{"v":1, "tid":"...", "n":"...", "exp":..., "sig":"..."}`). A note states: "Challenge generated. Scan this code with your Aegis app within 5 minutes."
- **Attestation indicator:** Shows either "✓ Device attestation enforced" (green) or "⚠ Attestation not enforced (dev mode)" (amber).
- **Clear Challenge** link — Dismisses the QR code.

**Zero-Trust Device Binding Security Note (info panel):**

An orange-bordered panel explaining: "By scanning this QR code, your device will generate a private key inside its Secure Enclave. This key never leaves your device and will be used to cryptographically sign all future HITL decisions, establishing an immutable, non-repudiable audit trail."

**Enrolled Aegis Devices Table:**

- **Table columns:** Device (model + truncated device ID), Platform (iOS/Android), Security Posture (Active in green / Pending in amber), Paired At (relative time), Actions.
- **View Details button** — Opens a modal showing full device telemetry: Model, Platform, OS Version, App Version, Operator, Status, Biometric Enrolled (green/amber), Secure Enclave Available (green/amber), Last Seen, Paired At, Created At, and the full Device ID (Ed25519 Public Key) in monospace.
- **Revoke button** (red) — Sends `POST /v1/portal/devices/{id}/revoke` to permanently revoke the device's pairing. Confirmation dialog required. A revoked device can no longer sign HITL decisions.
- **Empty state:** "No devices enrolled yet. Generate a QR code to bind your mobile device."

**Device refresh:** The device list polls every 30 seconds for status updates.

---

## 22. Enterprise Deploy

**Route:** `/enterprise/deploy`  
**Purpose:** The Enterprise Deploy page provides self-hosted distribution for Enterprise plan customers. It enforces a two-step UX: first upload the physical `.lic` licence file provided by the Cicada Account Manager, then view dynamically generated Docker deployment commands tailored to the customer's tenant.

**What you see:**

**Step 1 — Licence Upload:**

- **Header:** "Enterprise Self-Hosted Deployment"
- **Upload area:** A file input accepting `.lic` files. The licence file is a JSON document containing:
  - A Base64-encoded payload with the licence claims (tenant ID, company name, agent limit, features, expiry).
  - An Ed25519 signature (`sig_ed25519`) for cryptographic verification.
  - An ML-DSA-65 signature (`sig_mldsa65`) for post-quantum hybrid verification.
- **Validation:** The page validates the licence structure (requires `payload` and `sig_ed25519` fields). If invalid, a red error message appears: "Invalid license format. Missing payload or Ed25519 signature."
- **Claims extraction:** The payload is Base64-decoded and parsed to extract: Tenant ID, Company Name, Agent Limit, Enabled Features, and Expiry Date.

**Step 2 — Deployment Commands:**

Once the licence is validated, a deployment panel appears with:
- **Licence Summary** — Company name, tenant ID, agent limit, feature flags, and expiry date.
- **Docker Compose commands** — Pre-generated `docker-compose` commands with the customer's tenant ID and home URL pre-filled as environment variables.
- **Environment variables** — A list of all required environment variables: `CICADA_HOME`, `CICADA_TENANT_ID`, `CICADA_LICENCE_KEY`, database credentials, and encryption keys.
- **Copy buttons** — Each command block has a copy-to-clipboard button.

**Cross-page workflow:** Receive `.lic` file from Account Manager → upload on this page → copy deployment commands → deploy Docker containers → the Gateway phones home to `CICADA_HOME` for licence validation and telemetry.

---

*End of Manual — Version 3.0*
