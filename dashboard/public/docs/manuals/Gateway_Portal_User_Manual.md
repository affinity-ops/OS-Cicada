# Cicada Gateway Portal — Complete User Manual

**Version:** 3.0  
**Last Updated:** 12 June 2026  
**Classification:** Customer-Facing  
**Target Audience:** DevOps Engineers, Enterprise System Integrators, Infrastructure Managers, Security Engineers  
**Portal URL:** `http://localhost:3002`

---

## Table of Contents

1. [Root Redirect](#1-root-redirect)
2. [Login & Authentication](#2-login--authentication)
3. [OAuth Callback](#3-oauth-callback)
4. [Gateway Sidebar Navigation](#4-gateway-sidebar-navigation)
5. [Gateway Overview](#5-gateway-overview)
6. [Gateway Health](#6-gateway-health)
7. [Inbound Agents](#7-inbound-agents)
8. [Outbound Traffic](#8-outbound-traffic)
9. [Threat Intelligence](#9-threat-intelligence)
10. [Policy Management](#10-policy-management)
11. [Certified Agent Registry](#11-certified-agent-registry)
12. [Licence & Company](#12-licence--company)
13. [Cross-Portal Workflows](#13-cross-portal-workflows)
14. [CIBA Approval](#14-ciba-approval)
15. [Federation & SSO](#15-federation--sso)
16. [Revocation Webhooks](#16-revocation-webhooks)
17. [Network Flow](#17-network-flow)
18. [Agent Detail](#18-agent-detail)
19. [Health Indicators & Colour Reference](#19-health-indicators--colour-reference)

---

## 1. Root Redirect

**Route:** `/`  
**Purpose:** The root URL is a routing guard. It checks for the existence of a `cicada_gw_token` in localStorage. If the token exists, the user is immediately redirected to the Gateway Overview (`/overview`). If no token exists, the user is redirected to the Login page (`/login`). The developer never sees this page for more than a fraction of a second — it exists purely to enforce session state at the URL level.

**What you see:** A loading spinner on a dark background while the redirect resolves.

**Technical Detail:** The Gateway Portal uses a separate localStorage key (`cicada_gw_token`) from the Developer Portal (`cicada_token`). This means a user can be simultaneously logged into both portals in the same browser without session collision. The Gateway Portal also stores `cicada_gw_tenant` and `cicada_gw_plan`.

---

## 2. Login & Authentication

**Route:** `/login`  
**API Endpoint:** `GET {CORE_API}/auth/github?portal=gateway`, `GET {CORE_API}/auth/google?portal=gateway`  
**Purpose:** The Gateway Portal login page authenticates operators via the same OAuth infrastructure as the Developer Portal, but with a critical difference: the login URL includes a `portal=gateway` query parameter. The Laravel backend uses this parameter to redirect the user back to the correct callback URL after OAuth completes — the Gateway callback at port 3002, not the Developer Portal callback at port 3001.

**What you see:**

**Navigation Bar:** "CICADA" logo with a "Gateway Portal" badge to the right — a bordered pill that distinguishes this from the Developer Portal's login page. This visual cue prevents operators from accidentally logging into the wrong portal.

**Shield Icon:** A large shield icon inside a bordered container, visually communicating that this is a security-focused infrastructure portal.

**Header:** "Gateway Control" with "Control" in the primary orange colour. Subtitle: "Sign in to manage your Sentry Gateway installation."

**Error Display:** If the URL contains `?error=...`, a red banner reading "Authentication failed. Please try again" appears. Unlike the Developer Portal which distinguishes between `oauth_failed` and `registration_failed`, the Gateway Portal shows a single generic error message — appropriate for an infrastructure audience.

**Two OAuth Buttons:**
- **Continue with GitHub** — Dark branded button with GitHub icon. Navigates to `{CORE_API}/auth/github?portal=gateway`.
- **Continue with Google** — White branded button with Google icon. Navigates to `{CORE_API}/auth/google?portal=gateway`.

**Access Restriction Notice:** "Access is restricted to licensed Gateway operators. Contact support@cicada.io to request access." This communicates that the Gateway Portal is not self-service — it requires a licensed account.

---

## 3. OAuth Callback

**Route:** `/auth/callback`  
**Purpose:** Identical in function to the Developer Portal callback, but stores tokens under Gateway-specific localStorage keys and redirects to `/overview` instead of `/dashboard`.

**What happens:** Laravel redirects to `/auth/callback#token=<value>&tenant=<uuid>&plan=<tier>`. The page extracts these values from the URL fragment (never hitting server logs), stores them as `cicada_gw_token`, `cicada_gw_tenant`, and `cicada_gw_plan`, and redirects to `/overview`. If the token or tenant is missing, the user is redirected to `/login?error=oauth_failed`.

**What you see:** A loading spinner with "Authenticating gateway operator..." — the language explicitly says "gateway operator" rather than the Developer Portal's generic "Verifying identity..." to confirm the user is entering the correct portal.

---

## 4. Gateway Sidebar Navigation

**Component:** `layout.tsx` (gateway layout)  
**Purpose:** The sidebar provides the fixed navigation and session context for all authenticated Gateway Portal pages. It has a distinct visual identity from the Developer Portal sidebar.

**Structure (top to bottom):**

1. **Logo:** "CICADA" in primary orange with "Gateway Portal" subtitle. This distinguishes it from the Developer Portal ("Developer Portal") and the Operator Dashboard.

2. **Gateway Status Indicator:** Immediately below the logo, a bordered green pill shows a pulsing green dot and "GATEWAY ONLINE" text. This is always visible and provides an at-a-glance confirmation that the Sentry Gateway binary is running and responsive on the network. The indicator is rendered in the sidebar layout, not on individual pages.

3. **Navigation Groups:**
   - **COMMAND:** Overview, Gateway Health
   - **TRAFFIC:** Inbound Agents, Outbound Agents, Network Flow
   - **SECURITY:** Threat Intelligence, Policy Management, CIBA Approval, Revocation Webhooks
   - **IDENTITY:** Federation & SSO
   - **REGISTRY:** Certified Agents
   - **ACCOUNT:** Licence & Company

4. **User Panel (bottom):** Shows the operator's avatar (from OAuth), name, and company name (not plan tier, unlike the Developer Portal — Gateway operators care about their organisation identity, not their plan level). "Sign out" button clears Gateway localStorage keys only.

**Session Management:** On mount, the layout calls `GET /api/v1/auth/me` with the `cicada_gw_token`. Invalid tokens trigger a redirect to Login. This is identical to the Developer Portal but uses a separate token, allowing independent sessions.

---

## 5. Gateway Overview

**Route:** `/overview`  
**API Endpoints:** `GET /api/v1/portal/summary`, `GET {GATEWAY_URL}/` (health probe)  
**Purpose:** The Gateway Overview is the first screen operators see after login. It combines account-level KPIs with a real-time Gateway connectivity check, providing both a business summary and an infrastructure health signal in one view.

**What you see:**

**Header:** "Gateway Overview" with the company name below. On the right, a **Gateway connectivity badge** — a bordered pill that shows one of three states:
- **Green** ("Gateway Online") — The Sentry Gateway at `NEXT_PUBLIC_GATEWAY_URL` (default: `http://localhost:8080`) responded to a fetch within 3 seconds. A pulsing green dot animates.
- **Red** ("Gateway Offline") — The fetch failed or timed out. A solid red dot appears. This means the Sentry binary is not running or is unreachable from the browser.
- **Grey** ("Checking...") — The check is in progress.

**Six KPI Cards (3×2 grid):**
1. **Certified Agents** (green, verified icon) — Number of agents with valid EVARs.
2. **Pending Cert.** (yellow, pending icon) — Agents awaiting Swarm verification.
3. **Terminated** (grey, cancel icon) — Revoked agents.
4. **Total Transactions** (orange, receipt icon) — Total ledger entries.
5. **Blocked Today** (red, block icon) — Calls blocked today by the Gateway.
6. **Total Agents** (orange, robot icon) — Complete agent count.

**Quick Actions (2×2 grid):**
- **Inbound Traffic** → `/inbound` — "Monitor agents arriving at your Gateway."
- **Outbound Traffic** → `/outbound` — "Your agents going out to other systems."
- **Threat Intelligence** → `/threats` — "Anomalies, blocks, and suspicious patterns."
- **Policy Management** → `/policy` — "Configure OPA rules and trust thresholds."

Each card shows an icon, title, and a one-line description.

---

## 6. Gateway Health

**Route:** `/health`  
**API Endpoint:** `GET {GATEWAY_URL}/`, `GET {GATEWAY_URL}/health`  
**Purpose:** The Gateway Health page performs a comprehensive diagnostic of the Sentry Gateway's runtime dependencies. This is the infrastructure operator's primary troubleshooting interface — before checking logs, an operator should check this page to identify which subsystem has degraded.

**What you see:**

**Header:** "Gateway Health" with the last check timestamp. A "Recheck" button in the top-right triggers a fresh round of all health checks.

**Six Health Check Cards (vertical stack):**

Each card shows a coloured status icon (left), the subsystem name, an optional detail line, and a status badge (right):

1. **Gateway Process** — Checks if the Sentry Gateway responds on port 8080. Detail shows "Responding on :8080" on success.
   - OK (green) — Gateway is running.
   - Error (red) — "Not responding on :8080." The binary may have crashed or the port may be blocked.

2. **PostgreSQL Connection** — Whether the Gateway can reach its PostgreSQL instance.

3. **Redis Connection** — Whether the Gateway can reach Redis (used for velocity limits, circuit breakers, and rate limiting).

4. **Ed25519 Key Loaded** — Whether the cryptographic key material is properly loaded into memory. Without this, the Gateway cannot verify EVAR signatures.

5. **Edge Ledger (SQLite)** — The local SQLite ledger that stores events before syncing to the central Cicada Core API.

6. **Central Ledger Sync** — Whether the Edge Ledger is successfully syncing with the central Cicada Core API.

**Status States:**
- **OK** (green check, green badge) — Subsystem is healthy.
- **Warn** (yellow warning, yellow badge) — Subsystem has degraded but is functional. The health endpoint may not be available.
- **Error** (red error, red badge) — Subsystem has failed. Requires immediate attention.
- **Checking** (grey pending, grey badge, animated pulse) — Check is in progress.

**Fallback Behaviour:** If the `/health` endpoint is not implemented in the Sentry binary, all subsystems except "Gateway Process" will show "warn" status with "Health endpoint not available — check logs." The Gateway Process check always works because it only needs the root `/` endpoint to respond.

**Logs Callout Panel:** At the bottom, a panel explains: "Detailed Gateway logs are written to `logs/sentry.log` in your Gateway installation directory." The log path is displayed in a styled code element.

---

## 7. Inbound Agents

**Route:** `/inbound`  
**API Endpoint:** `GET /api/v1/portal/traffic/inbound`  
**Purpose:** This page shows every external agent that has been validated by your Sentry Gateway. "Inbound" means another company's agent is calling your systems — these are agents that you did not deploy, arriving at your Gateway for verification. This is the security view: you are monitoring who is trying to get in.

**What you see:**

**Header:** "Inbound Agents" with the subtitle "External agents that have been validated by your Sentry Gateway" and a total count.

**Status Filter Tabs:** Five pill buttons — All, Approved, Blocked, Pending Swarm, Shadow Sandbox. The active tab turns orange. Changing tabs resets to page 1 and reloads data with the selected status filter.

**Traffic Cards:** Each inbound event shows:
- **Arrow-in icon** — Colour-coded based on status: green for approved, red for blocked, yellow for pending.
- **Payload hash** — The first 20 characters of the encrypted payload hash in monospace font. This is a structural fingerprint, not the payload content.
- **Target API** — The internal API endpoint the external agent was attempting to reach.
- **Timestamp** — When the validation occurred.
- **Swarm Confidence** — Percentage score from the Verification Swarm. A low score (below 60%) explains why an agent might have been blocked.
- **Status badge** — Colour-coded pill: approved (green), blocked (red), pending swarm (yellow), shadow sandbox (purple).

**Pagination:** Previous / Next buttons with a page counter (e.g., "3 / 12").

**Empty state:** "No inbound agent traffic yet." — This typically means no external agents have attempted to call your Gateway, which could mean the Gateway is new or has no public-facing endpoints configured.

---

## 8. Outbound Traffic

**Route:** `/outbound`  
**API Endpoint:** `GET /api/v1/portal/traffic/outbound`  
**Purpose:** Shows your own agents' requests passing through the Sentry Gateway. "Outbound" means your agents are calling external systems — you deployed these agents and this view shows their real-time activity and the Gateway's enforcement decisions.

**What you see:**

**Header:** "Outbound Traffic" with a total count.

**Status Filter Tabs:** Identical to Inbound — All, Approved, Blocked, Pending Swarm, Shadow Sandbox.

**Traffic Cards:** Each outbound event shows:
- **Arrow-out icon** — Orange, indicating outbound direction.
- **Agent name** — Which of your agents made the call. Shows "Unknown Agent" if the name is not available.
- **Target API** — The external system the agent was calling.
- **Timestamp.**
- **Swarm Confidence** — Percentage score.
- **Status badge** — Same colour coding as inbound.

**Pagination and empty state** are identical to the Inbound page.

**Key difference from Inbound:** The Inbound page identifies agents by their payload hash (because you don't control those agents), while the Outbound page identifies them by agent name (because they're yours).

---

## 9. Threat Intelligence

**Route:** `/threats`  
**API Endpoint:** `GET /api/v1/portal/transactions?status=blocked`  
**Purpose:** A security-focused view that aggregates all blocked agent events, shadow sandbox activity, and low-confidence anomalies into a single threat monitoring interface. This is the page a SOC analyst or security engineer checks daily to understand what the Gateway is catching.

**What you see:**

**Header:** "Threat Intelligence" with the subtitle "Blocked agents, anomalies, and suspicious patterns detected by your Gateway."

**Three KPI Cards (3-column grid):**
1. **Agents Blocked** (red, block icon) — Total count of blocked events. This is the primary threat indicator.
2. **Shadow Sandboxed** (purple, science icon) — Agents routed to the honeypot sandbox instead of hard-rejected. This number being non-zero means your "Shadow Sandbox on Block" policy is active.
3. **Low Confidence** (yellow, warning icon) — Agent calls where the Swarm returned a confidence score below your configured threshold. These are not necessarily blocked but are flagged for review.

**Blocked Agent Events List:** Below the KPIs, a paginated list of every blocked event:
- **Red block icon** — All items in this list are blocked.
- **Agent name** — "Unknown Agent" if the blocked agent has no valid identity.
- **Target API** — What the agent was trying to reach.
- **Timestamp.**
- **Confidence Score** — Displayed in red. Low scores explain the block.
- **"blocked" badge** — Always red since this view is pre-filtered.

**Clean State:** If no blocked agents exist, a green verified shield icon with "No blocked agents. Your Gateway is clean." This is a positive security confirmation.

**Pagination:** Available when blocked events exceed one page.

---

## 10. Policy Management

**Route:** `/policy`  
**Purpose:** Configure the six core enforcement rules that govern how the Sentry Gateway processes every inbound agent request. Policy changes take effect on the next Gateway process cycle — they are not retroactive and do not affect past ledger entries.

**What you see:**

**Header:** "Policy Management" with the subtitle "Configure the rules your Gateway enforces against every inbound agent. Changes take effect on the next Gateway process cycle."

**Six Policy Rules (vertical list, divided by subtle borders):**

1. **Minimum Trust Tier** — Dropdown: unverified, nominal, elevated, critical. Default: nominal.
   - "Reject any inbound agent below this trust tier." Setting this to "elevated" blocks all agents without a proven track record.

2. **Maximum Permitted Scope** — Dropdown: proxy:read, proxy:chat, proxy:write, proxy:transact. Default: proxy:chat.
   - "Block agents claiming scopes beyond this level." If set to proxy:chat, any agent requesting proxy:write or proxy:transact will be rejected, regardless of their registration.

3. **Swarm Confidence Threshold** — Number input (0–1, step 0.05). Default: 0.6.
   - "Minimum Swarm confidence score to admit an agent." Setting this to 0.8 is conservative — only agents that the Verification Swarm is highly certain about will be admitted.

4. **Anomaly Block Threshold** — Number input (0–1, step 0.05). Default: 0.35.
   - "Anomaly score above which the agent is sandboxed." Lower values make the Gateway more aggressive in sandboxing potentially anomalous behaviour.

5. **Allow Unverified Agents** — Toggle switch. Default: OFF.
   - "Permit agents without a valid EVAR (not recommended)." This should only be turned on during controlled testing. In production, this should always be OFF — it defeats the entire purpose of the trust layer.

6. **Shadow Sandbox on Block** — Toggle switch. Default: ON.
   - "Route blocked agents to the honeypot instead of hard-rejecting." When ON, blocked agents are silently routed to a shadow sandbox that mimics real responses but captures their behaviour for analysis. When OFF, blocked agents receive a hard 403 rejection.

**Warning Panel (yellow):** "Policy changes are stored in your Gateway configuration. They do not retroactively affect past transactions recorded in the ledger."

**Save Policy button** — Persists the configuration. A green "Policy saved. Gateway will apply on next cycle." confirmation flashes for 3 seconds.

---

## 11. Certified Agent Registry

**Route:** `/registry`  
**API Endpoint:** `GET /api/v1/portal/agents`  
**Purpose:** A read-only view of all agents registered under your organisation and their certification status. Unlike the Developer Portal's Agent Registry (which allows registration and management), the Gateway Portal's registry is for monitoring only — the Gateway operator needs to know which agents are certified and which may cause issues, but they register agents through the Developer Portal.

**What you see:**

**Header:** "Certified Agent Registry" with the subtitle "Your organisation's registered agents and their certification status."

**Filter Tabs:** Five pills — All, Certified, Pending Certification, Recertification Required, Terminated.

**Agent Cards:** Each agent shows:
- **Robot icon** — Orange-tinted square.
- **Agent name** — Bold headline. "Unnamed Agent" if not set.
- **Metadata line** — Agent type, version number, certification date, recertification due date.
- **EVAR preview** — Truncated token preview in muted monospace.
- **Status badge** — Identical colour coding to the Developer Portal:
  - Certified (green)
  - Pending (yellow)
  - Recert. Required (orange)
  - Terminated (red)

**Empty state:** "No agents in this category." with a verified icon.

**Key difference from Developer Portal:** No "Register Agent" button. No management actions. This is observation-only.

---

## 12. Licence & Company

**Route:** `/account`  
**API Endpoints:** `GET /api/v1/portal/company`, `PUT /api/v1/portal/company`  
**Purpose:** View your Gateway licence details, update company information, and manage the primary contact. This is the administrative page for your Gateway deployment.

**What you see:**

**Header:** "Licence & Company" with the subtitle "Your Gateway licence details and organisation information."

**Gateway Licence Section (highlighted with primary border):**
A bordered card with a verified shield icon showing four read-only fields:
- **Plan** — The current plan tier (Starter, Professional, Enterprise) displayed in orange uppercase.
- **Status** — The account status, shown in green uppercase (e.g., "ACTIVE").
- **Tenant ID** — The UUID of your tenant, displayed in monospace. This is the identifier used in all API calls and audit logs.
- **Active Since** — The date your plan started.

**Company Details Section:**
- **Company Name** — Text input.
- **Company Email** — Email input.
- **Phone** — Phone input.
- **Website** — URL input.
- **Registered Address** — Full-width text input.

**Primary Contact Section:**
- **Full Name** — Text input.
- **Phone** — Phone input.
- **Role / Title** — Text input. Default placeholder: "Security Engineer" (reflecting the Gateway Portal's target audience, versus "Lead Developer" in the Developer Portal).

**Save Changes button** — Sends `PUT /api/v1/portal/company`. Shows "Saving…" during the request and a green "Changes saved." confirmation for 3 seconds on success.

---

## 13. Cross-Portal Workflows

### Workflow 1: Initial Gateway Deployment

1. **Developer Portal → Billing** — Ensure you are on the Professional or Enterprise plan. Gateway deployment requires a licensed plan.
2. **Gateway Portal → Login** — Authenticate using the same OAuth account used in the Developer Portal. The backend recognises the shared identity.
3. **Gateway Overview** — Check the Gateway connectivity badge. If it shows "Gateway Offline", the Sentry binary is not running.
4. **Gateway Health** — Run the 6-point health check. All subsystems should show green. If PostgreSQL or Redis show errors, the binary cannot function.
5. **Policy Management** — Review and adjust the six enforcement rules. For a first deployment, start with defaults: Swarm Confidence 0.6, Shadow Sandbox ON, Unverified OFF.
6. **Inbound Agents** — Once external agents start calling your systems, their validations appear here.

### Workflow 2: Investigating a Blocked Agent

1. **Threat Intelligence** — Identify the blocked event. Note the agent name, target API, and confidence score.
2. **Policy Management** — Check if your Swarm Confidence Threshold is too aggressive. Is it set to 0.9? That blocks most agents.
3. **Inbound Agents** — Filter by "blocked" status. Is it a single agent or a pattern?
4. **Certified Agent Registry** — Is the agent registered? If it shows "Terminated", its EVAR has been revoked. The block is correct.
5. **Gateway Health** — If blocks are inconsistent, check if the Ed25519 key is loaded. Without the key, the Gateway cannot verify any signatures and may block everything.

### Workflow 3: Tightening Security Policy

1. **Threat Intelligence** — Review the "Low Confidence" KPI. Are untrustworthy agents getting through?
2. **Policy Management** — Increase the Swarm Confidence Threshold from 0.6 to 0.75. Reduce the Maximum Permitted Scope from proxy:chat to proxy:read.
3. **Outbound Traffic** — Monitor your own agents to ensure the tighter policy isn't blocking legitimate traffic.
4. **Gateway Health** — Recheck after policy changes to confirm the Gateway process is stable.

### Workflow 4: Shadow Sandbox Investigation

1. **Inbound Agents** → Filter by "shadow sandbox."
2. **Policy Management** → Confirm "Shadow Sandbox on Block" is ON.
3. **Threat Intelligence** → Review the "Shadow Sandboxed" KPI to understand the volume.
4. **Decision:** If sandboxed agents are consistently the same entity, consider reporting them via the Operator Dashboard's "Blocked Agents" (Rogue Registry) page, which the Cicada platform operator manages.

### Workflow 5: Gateway Outage Response

1. **Gateway Overview** — Badge shows "Gateway Offline."
2. **Gateway Health** — Click "Recheck." If "Gateway Process" shows Error, the binary needs to be restarted at the infrastructure level.
3. **Check dependencies:** If PostgreSQL shows Error, the database is down. If Redis shows Error, velocity limits and circuit breakers cannot function — the Gateway may be running but cannot enforce rate limits.
4. **Logs:** Check `logs/sentry.log` in the Gateway installation directory for crash details.
5. **Central Ledger Sync** — If this shows Warn after restart, the Edge Ledger may have accumulated events that need to sync. This resolves automatically once the connection to the Cicada Core API is restored.

### Workflow 6: CIBA Mobile Approval Flow

1. **CIBA Approval** (`/ciba`) → A pending CIBA request appears with the agent name, action summary, and risk score.
2. **Review** → Read the risk reason and payload preview. Check the agent's certification status.
3. **Decision** → Click "Force Approve" (green) if the action is legitimate, or "Force Reject" (red) if suspicious.
4. **Audit** → The decision is recorded in the immutable action ledger. Navigate to Outbound Traffic to confirm the call was released or blocked.

### Workflow 7: Revocation Webhook Setup

1. **Revocation Webhooks** (`/revocation`) → Click "Add Webhook" to open the creation form.
2. **Configure** → Set the endpoint URL (e.g., your Okta SCIM endpoint or PagerDuty webhook), select event types, and choose the authentication method.
3. **Test** → Click "Test" on the new webhook row. A test event is sent and the response status is displayed.
4. **Monitor** → Check the Last Success and Consecutive Failures columns. Webhooks with >3 consecutive failures should be investigated.

### Workflow 8: Enterprise SSO Integration

1. **Federation & SSO** (`/federation`) → Click "Add Provider" on the Identity Providers tab.
2. **Configure** → Enter your IdP details (OIDC issuer URL, client ID, client secret, scopes).
3. **Role Mappings** → Switch to the Role Mappings tab. Map your IdP groups to Cicada roles (e.g., "security-admins" → "admin").
4. **Test** → Switch to the Test tab. Paste a comma-separated list of IdP groups and click "Resolve Roles" to verify the mapping logic.
5. **Enable** → Toggle the provider to Enabled. New logins through this IdP will be auto-provisioned if enabled.

---

## 14. CIBA Approval

**Route:** `/ciba`  
**API Endpoints:** `GET /api/v1/portal/ciba/pending`, `POST /api/v1/portal/ciba/{traceId}/respond`  
**Purpose:** The CIBA (Client Initiated Backchannel Authentication) Approval page is the Gateway operator's local view of pending out-of-band mobile authorization requests for agents under their tenant. While the Operator Dashboard's CIBA queue is a global view across all tenants, this page is scoped to the Gateway operator's own company — showing only requests for their agents.

**What you see:**

**Header:** "CIBA Approval Queue" with a badge showing the count of pending requests.

**Pending Request Cards:** Each pending CIBA request shows:
- **Agent identity** — Name, agent UUID, and tenant context.
- **Action summary** — What the agent was attempting to do.
- **Risk score** — Colour-coded gauge (green <50%, amber 50–79%, red ≥80%).
- **Risk reason** — Why the Gateway flagged this request for out-of-band verification.
- **Target API** — The URL the agent was trying to call.
- **Countdown timer** — Shows the time remaining before the CIBA request auto-expires.
- **Trace Reference** — The full trace UUID for audit trail linkage.

**Two Action Buttons per Card:**
- **Force Approve** (green) — Sends `POST /api/v1/portal/ciba/{traceId}/respond` with `{decision: 'approve'}`. The agent's request is released to proceed.
- **Force Reject** (red) — Sends the same endpoint with `{decision: 'reject'}`. The agent's request is denied.

**Auto-refresh:** The queue polls every 5 seconds for new requests.

**Empty state:** "No CIBA requests pending for your organisation." This is the healthy state.

**Cross-page workflow:** CIBA request arrives → review risk score and action summary → approve or reject → check Outbound Traffic to confirm the decision was applied.

---

## 15. Federation & SSO

**Route:** `/federation`  
**API Endpoints:** `GET /v1/federation/providers`, `POST /v1/federation/providers`, `PUT /v1/federation/providers/{id}`, `DELETE /v1/federation/providers/{id}`, `GET /v1/federation/role-mappings`, `POST /v1/federation/role-mappings`, `DELETE /v1/federation/role-mappings/{id}`, `POST /v1/federation/test-resolve` (all via Sentry Gateway)  
**Purpose:** The Federation & SSO page configures enterprise Single Sign-On integration for the Gateway Portal. It allows Gateway operators to connect external Identity Providers (IdPs) such as Okta, Microsoft Entra ID, Google Workspace, or any OIDC-compatible provider. Once configured, operators can log in via their corporate SSO rather than GitHub/Google OAuth, and their IdP group memberships are automatically mapped to Cicada roles.

**What you see:**

**Header:** "Federation & SSO" with the subtitle "Connect your enterprise Identity Provider for unified authentication and role-based access control."

**Three Tabs:**

### Tab 1: Identity Providers

- **Provider List** — Each configured IdP shows:
  - **Provider Name** — Human-readable label (e.g., "Okta Production").
  - **Protocol** — Currently OIDC (OpenID Connect). Displayed as a badge.
  - **OIDC Issuer URL** — The IdP's discovery endpoint (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`).
  - **Client ID** — The OIDC client identifier.
  - **Default Role** — The Cicada role assigned to users who don't match any role mapping.
  - **Auto-Provision** — Toggle (green/grey). When enabled, new users authenticating via this IdP are automatically created in Cicada.
  - **Enabled toggle** — Enable or disable the provider without deleting it.
  - **Delete button** (red) — Permanently removes the provider configuration.

- **"Add Provider" button** — Opens a creation form with fields:
  - Provider Name, Protocol (OIDC), Issuer URL, Client ID, Client Secret (password field), Scopes (defaults to `openid profile email groups`), Default Role (dropdown: operator, viewer, admin), Auto-Provision toggle.
  - A "Create Provider" button submits the form.

### Tab 2: Role Mappings

- **Mapping List** — Each mapping shows:
  - **IdP Group** — The group name from the external Identity Provider (e.g., "security-admins", "devops-team").
  - **Cicada Role** — The mapped Cicada role (admin, operator, viewer).
  - **Priority** — Numeric priority (lower = higher priority). When a user belongs to multiple groups, the highest-priority mapping wins.
  - **Description** — Human-readable description of the mapping.
  - **Delete button** — Removes the mapping.

- **"Add Mapping" button** — Opens a form with: IdP Group, Cicada Role (dropdown), Priority (number), Description.

### Tab 3: Test

- **Group Resolver** — A text input where you paste a comma-separated list of IdP groups (e.g., "security-admins, developers, interns").
- **"Resolve Roles" button** — Sends `POST /v1/federation/test-resolve` with the group list. The Gateway evaluates the groups against the configured role mappings.
- **Result panel** — Shows which groups matched, which Cicada role was resolved, and the priority of the winning mapping. If no mapping matches, it shows the default role.

---

## 16. Revocation Webhooks

**Route:** `/revocation`  
**API Endpoints:** `GET /api/v1/portal/revocation-webhooks`, `POST /api/v1/portal/revocation-webhooks`, `DELETE /api/v1/portal/revocation-webhooks/{id}`, `POST /api/v1/portal/revocation-webhooks/{id}/test`  
**Purpose:** Revocation Webhooks configure outbound webhook endpoints that Cicada fires when security events occur (agent quarantined, circuit breaker tripped, operator quarantine, attestation failed, canary triggered). These endpoints typically point to external IdPs (Okta, Entra, Auth0), SIEM platforms (Splunk, PagerDuty), or internal systems that need to revoke the agent's sessions across all connected services. The wire format follows the IETF Shared Signals Framework / CAEP standard.

**What you see:**

**Header:** "Revocation Webhooks" with the subtitle "Configure outbound CAEP-compatible webhook endpoints for automated cross-system revocation."

**Webhook List:** Each configured webhook shows:
- **Name** — Human-readable label (e.g., "Okta SCIM Revocation").
- **Endpoint URL** — The webhook destination URL in monospace. SSRF protection is enforced: private IPs, localhost, link-local addresses, and non-HTTPS URLs are blocked.
- **Event Types** — Badge pills showing which events trigger this webhook:
  - `agent_quarantined` — Fired when an agent is quarantined.
  - `circuit_breaker_trip` — Fired when an agent's circuit breaker trips.
  - `operator_quarantine` — Fired when an operator manually quarantines an agent.
  - `attestation_failed` — Fired when a device attestation check fails.
  - `canary_triggered` — Fired when a canary token is accessed.
- **Auth Method** — How the webhook authenticates: Bearer Token or Basic Auth.
- **Auth Secret** — Masked display of the authentication secret.
- **Enabled toggle** — Enable or disable the webhook without deleting it.
- **Last Success** — Timestamp of the last successful delivery. Shows "—" if never fired.
- **Consecutive Failures** — Count of consecutive delivery failures. If >0, displayed in red with an error indicator.
- **Test button** (blue) — Sends `POST /api/v1/portal/revocation-webhooks/{id}/test` to fire a test event. The result (success/failure with HTTP status code) is displayed inline.
- **Delete button** (red) — Permanently removes the webhook configuration.

**"Add Webhook" button** — Opens a creation form with fields:
- Webhook Name, Endpoint URL, Authentication Method (Bearer Token or Basic Auth), Authentication Secret (password field), Event Types (multi-select checkboxes for all 5 event types).
- A "Create Webhook" button submits the form.

**SSRF Protection:** The backend rejects webhook URLs targeting private IP ranges (10.x, 172.16–172.31, 192.168.x), localhost (127.0.0.1, ::1), link-local addresses (169.254.x, fe80::), and non-HTTPS URLs. This prevents an attacker from using the webhook system to probe internal infrastructure.

---

## 17. Network Flow

**Route:** `/flow`  
**API Endpoints:** `GET /api/v1/portal/traffic/flow`, `GET /api/v1/portal/agents`, `GET /api/v1/portal/transactions`  
**Purpose:** The Network Flow page provides a visual Sankey diagram showing the real-time flow of agent traffic through the Gateway. It maps the complete path from Tenant → Agent → LLM Model → Target API, with flow thickness proportional to traffic volume and node colours reflecting certification status and decision outcomes.

**What you see:**

**Header:** "Network Flow" with the subtitle "Visualise the real-time flow of agent traffic through your Sentry Gateway."

**Sankey Diagram (main panel):**

- A D3.js-rendered Sankey diagram with four node columns:
  1. **Tenant** (amber) — The company/organisation.
  2. **Agent** (green/amber/grey) — Each registered agent, colour-coded by certification status:
     - Green: Certified
     - Amber: Pending certification or recertification required
     - Grey: Suspended or terminated
  3. **Model** (purple) — The LLM model being called (e.g., "gpt-4o", "claude-3.5-sonnet").
  4. **Target API** (teal) — The destination endpoint.

- **Flow links** — Curved paths between nodes. Thickness represents traffic volume (total calls). Colour-coded by decision:
  - Green: Approved traffic
  - Red: Blocked traffic
  - Purple: Shadow sandbox traffic
- **Hover tooltips** — Hovering a node shows its label. Hovering a link shows the connection details and call count.

**Summary Statistics (below diagram):**

- **Total Flows** — Count of unique agent-to-API traffic paths.
- **Unique Agents** — Number of distinct agents with traffic.
- **Unique Targets** — Number of distinct target APIs.
- **Block Rate** — Percentage of all calls that were blocked.

**Recent Transactions Table (below statistics):**

- A paginated table showing the most recent individual transactions:
  - **Agent Name** — Which agent made the call.
  - **Target API** — Destination URL.
  - **Status badge** — Colour-coded: approved (green), blocked (red), pending swarm (yellow), shadow sandbox (purple).
  - **Timestamp** — When the call occurred.
- Pagination: Previous/Next with page counter.

**What healthy looks like:** A clean Sankey diagram with predominantly green flows, no red links, and all agent nodes in green (certified).

**What danger looks like:** Red-coloured links (blocked traffic) dominating the diagram. Agent nodes in amber or grey indicating certification issues. High block rate in the summary statistics.

---

## 18. Agent Detail

**Route:** `/registry/{agentId}`  
**API Endpoints:** `GET /api/v1/portal/agents/{agentId}`, `GET /api/v1/portal/agents/{agentId}/certification-events`, `POST /api/v1/portal/agents/{agentId}/{action}`  
**Purpose:** The Agent Detail page provides a comprehensive view of a single agent's identity, certification status, lifecycle history, and recent transaction activity. Unlike the Developer Portal's agent detail (which focuses on governance completeness), this page focuses on the Gateway operator's perspective: is this agent safe, is it certified, and what has it been doing?

**How to reach this page:** Click any agent card in the Certified Agent Registry (`/registry`).

**What you see:**

**Navigation:** A "← Back to registry" link returns to the agent list.

**Header:** The agent name in large bold text, with status and certification badges:
- **Status badge** — Colour-coded pill: Certified (green), Pending Review (yellow), Escalation Required (red), Suspended (orange), Recert. Required (orange), Terminated (red).
- **Lifecycle action buttons** (context-sensitive):
  - **Certify** (green) — For pending agents. Requires a reason (text prompt). Sends `POST /api/v1/portal/agents/{id}/certify`.
  - **Suspend** (orange) — For certified agents. Temporarily revokes the EVAR.
  - **Re-certify** (green) — For suspended agents.
  - **Terminate** (red) — For all non-terminated agents. Permanent EVAR revocation.
  - Each action requires a reason prompt, which is recorded in the certification event log.

**Agent Details Section:**
- Two-column grid showing: Agent Type, Version, Role, Target Model, Criticality Level, Data Classification, Owner Name, Owner Email, Business Unit, Registered Date, Certified Date.
- **EVAR Token Preview** — Truncated token in monospace.
- **Scopes** — Orange pill badges for each declared scope.

**Certification Event History:**
- A chronological timeline of all lifecycle state changes:
  - Each event shows: a timeline dot (coloured by event type), the event label (e.g., "Certified", "Suspended", "Escalation Flagged"), the operator who performed the action, the reason they provided, and the timestamp.
  - Event types include: registered, escalation_flagged, certified, recertified, suspended, terminated, recertification_due.

**Recent Transactions:**
- A compact table showing the agent's most recent Gateway intercepts:
  - Target API, Status badge (approved/blocked), Timestamp.
- Limited to the most recent transactions for quick reference.

**Cross-page workflow:** Identify a problematic agent in Threat Intelligence → navigate to Agent Detail → review certification history and recent transactions → suspend or terminate if necessary → verify the action in the certification event timeline.

---

## 19. Health Indicators & Colour Reference

The Gateway Portal uses a consistent colour language across all pages:

### Status Colours

| Colour | Meaning | Where Used |
|---|---|---|
| **Green** (`text-green-400`) | Approved, Certified, OK, Online | Traffic badges, health checks, connectivity |
| **Yellow** (`text-yellow-400`) | Pending, Warning, Awaiting | Swarm pending, health degraded |
| **Red** (`text-red-400`) | Blocked, Error, Offline, Terminated | Rejected agents, health failures |
| **Purple** (`text-purple-400`) | Shadow Sandbox | Honeypot-routed agents |
| **Orange** (`text-orange-400`) | Recertification Required | Agent lifecycle warning |
| **Grey** (`text-gray-400/500`) | Checking, Terminated (muted) | Loading states |

### Health Check Icons

| Icon | Status | Meaning |
|---|---|---|
| `check_circle` | OK | Subsystem is healthy |
| `warning` | Warn | Degraded but functional |
| `error` | Error | Subsystem has failed |
| `pending` | Checking | Test in progress (animated pulse) |

### Traffic Direction Indicators

| Icon | Direction | Context |
|---|---|---|
| `call_received` | Inbound | External agents arriving at your Gateway |
| `call_made` | Outbound | Your agents calling external systems |
| `block` | Blocked | Agent was rejected by Gateway policy |

### Gateway Connectivity Badge

| State | Appearance | Meaning |
|---|---|---|
| Online | Green pulsing dot, green text | Gateway binary is running and responding on :8080 |
| Offline | Red solid dot, red text | Gateway is unreachable — requires infrastructure intervention |
| Checking | Grey dot, muted text | Health probe in progress |

---

*End of Manual — Version 3.0*
