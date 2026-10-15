# Cicada Platform — User Documentation

**Version:** 1.2  
**Last Updated:** 26 July 2026

Welcome to the Cicada Platform Documentation. This guide is intended for end-users (Tenants/Developers) who manage AI agents within the Cicada ecosystem. It explains how to utilize the core features of the Developer Portal.

---

## Table of Contents

1. [Navigating the Developer Portal](#1-navigating-the-developer-portal)
2. [Agent Marketplace (New!)](#2-agent-marketplace)
3. [Agent Lifecycle & Certification](#3-agent-lifecycle--certification)
4. [Agent Provisioning & Scaffolding](#4-agent-provisioning--scaffolding)
5. [Monitoring & Telemetry](#5-monitoring--telemetry)
6. [Operator Command Center (Admin)](#6-operator-command-center-admin)
7. [Schema Ownership Policy](#7-schema-ownership-policy)

---

## 1. Navigating the Developer Portal

The Developer Portal is your primary workspace for creating, deploying, and monitoring AI agents. 
- **Dashboard:** A high-level overview of your agent fleet, active EVAR (Endpoint Verifiable Agent Receipt) sessions, and recent proxy transactions.
- **Agents:** The central registry for all agents linked to your tenant account.
- **Marketplace:** A community-driven directory of verified agent blueprints.
- **Build (Scaffolding):** Tools to rapidly generate `cicada.yaml` configurations and bootstrap new agent deployments.
- **Security:** Manage Mobile Aegis pairing for out-of-band Human-in-the-Loop (HITL) authorizations.

---

## 2. Agent Marketplace

The **Agent Marketplace** allows tenants to discover, import, and share pre-configured agent blueprints. This feature dramatically accelerates the time-to-deployment for standard agent use cases.

### Discovering Templates
1. Navigate to **Agents > Marketplace** in the left sidebar.
2. Browse the grid of available templates. 
3. Look for the **Verified** badge. Verified templates have been audited by the Cicada global operator team for policy safety and best practices.

### 1-Click Import
1. Find a template that matches your needs (e.g., "Customer Support Triage").
2. Click the **1-Click Import** button on the template card.
3. The platform will automatically clone the blueprint into your workspace as a **Pending** agent.
4. You will be redirected to the newly drafted Agent's detail page, where you can modify its policy constraints, tools, and identity before certifying it for production use.

### Publishing Your Own Agents (Coming Soon to UI)
In the future, you will be able to publish your highly-tuned agents to the Marketplace. When published, sensitive details (like your EVAR and Tenant ID) are stripped, leaving only the structural configuration (tools, identity, velocity limits) for others to learn from.

---

## 3. Agent Lifecycle & Certification

Cicada operates on a Zero Trust model. Creating an agent is not enough to grant it access to the Gateway; it must pass through a strict certification lifecycle.

### Lifecycle States
*   **Pending Certification (`pending_review`):** The agent has been registered and possesses a *provisional* EVAR. It is forcefully restricted to **Shadow Mode** (observe-only). It can send requests, but the Gateway will drop them while logging the attempt.
*   **Certified (`certified`):** The agent has been manually reviewed and approved by a tenant administrator. It receives a fully active EVAR and can execute production transactions (subject to its policy).
*   **Suspended (`suspended`):** Temporary revocation. The agent's EVAR is blocked at the edge.
*   **Terminated (`terminated`):** Permanent revocation. The agent is cryptographically destroyed and cannot be recovered.

### Managing Certification
*(Note: These controls are currently being rolled out to the UI)*
1. Go to **Agents > Registry** and select an agent.
2. In the top-right corner, you will find lifecycle controls:
    *   **Certify:** Promotes a Pending agent to Certified status.
    *   **Suspend / Terminate:** Immediately invalidates the agent's EVAR at the Gateway layer, blocking all further access.

---

## 4. Agent Provisioning & Scaffolding

If you prefer to build from scratch rather than use the Marketplace, the **Scaffold Agent** tool is your starting point.

1. Navigate to **Build > Scaffold Agent**.
2. Complete the visual wizard to define your agent's:
    *   Identity (Name, Version, Description)
    *   Capabilities (Tools, Data Residency, HITL enforcement)
3. Click **Generate & Download**. This produces a `cicada.yaml` file.
4. Use the `cicada register` CLI command with this YAML file, or use the **Register New** button in the portal to upload it directly.

---

## 5. Monitoring & Telemetry

Once your agents are certified and deployed, Cicada provides deep observability into their actions.

*   **Transactions:** View a real-time ledger of every API call your agents attempt through the Sentry Gateway.
*   **Inbound/Outbound Traffic:** Visualize data flow and pinpoint policy rejections (e.g., FGA blocks, Velocity violations).
---

## 6. Operator Command Center (Admin)

For Global Operators, the platform provides a dedicated administrative dashboard to enforce fleet-wide governance.

*   **Global CIBA & HITL Queues:** Monitor and forcefully resolve pending out-of-band mobile authorizations (CIBA) and Human-In-The-Loop decisions across all tenants.
*   **Compliance & Audit Export:** Generate and download cryptographically signed JSONL/CSV datasets and SOC2/GDPR compliance reports for auditing or AI model retraining.
*   **Universal Revoke (The Kill Switch):** Operators can instantly quarantine a rogue agent from the registry. This is a strict, cross-system tear-down that:
    1. Instantly drops the agent's EVAR (Enterprise Verifiable Agent Registry) credential across the Gateway edge.
    2. Flags the agent as quarantined (`revoked_at`), ensuring it is immediately monitored in the **Blocked Agents** and **Shadow Sandbox** views.
    3. Forcefully rejects any lingering pending HITL or CIBA approvals for that agent.
    4. Fires CAEP (Continuous Access Evaluation Profile) revocation webhooks to external Identity Providers.
    5. Writes an immutable `universal_revoke` trace to the Action Ledger and creates a critical alert for global visibility.
*   **Data Retention Policies:** Manage automatic record purging rules (from 1 to 3650 days) across data categories to satisfy SOC2, ISO 27001, and NIST AI RMF data minimization requirements. Supports legal hold suspensions and pre-deletion encrypted archiving.
*   **Aegis Threat Status Sync:** The Gateway edge actively synchronizes high-severity localized threats (including Credential Exfiltration, Prompt Injection, Semantic Mismatch, and Velocity Breaches) to the Operator Core API in real-time. By bypassing the asynchronous telemetry ledger, these threats trigger instantaneous Operator notifications and Webhook/PagerDuty integrations via the unified `AlertDispatcherService`.
*   **Active Gateway Fleet Telemetry:** The dashboard features a global Command Matrix (Globe) and Heartbeat Status table that visualize the physical deployment of all Sentry Gateway instances. This is driven by live telemetry: each gateway `POST`s a heartbeat to the Core API containing its cached agent volume, active TLS status, Canary Token health, and proxy loads. The Core API dynamically calculates node health (Online, Degraded, Offline) based on these check-ins, guaranteeing that operators always have an accurate view of physical network health without relying on dummy data.
*   **Security Policies Monitor:** Found under the `/security` tab, this allows operators to test and manage the strict Rego-like admission rules that govern agent traffic at the Gateway. 
    1.  **Live Testing:** Operators can run simulated tests against live ledger data. The system fetches the most recent transaction blocked by a specific policy (e.g., `trust_score_check` or `block_untrusted_traffic`) and displays the exact reason for the denial in a built-in terminal.
    2.  **Exception Overrides:** If an agent was illegitimately blocked, operators can instantly whitelist them by adding an exception. This records an immutable audit log and automatically upgrades the agent's `trust_tier` to `elevated` in the Core database, allowing the Gateway to seamlessly admit their traffic on the very next request.
*   **Live Compute Monitor:** Found under the `/compute` tab (labeled "Security Monitor" in the sidebar), this acts as a real-time "htop" or task manager for the entire agent fleet. It queries the `action_ledger` to visualize load exclusively from the **last 60 minutes**. 
    *   It calculates current `System Load` (the percentage of active threads being blocked by the gateway).
    *   It measures `Threat Velocity` (how many blocks are occurring per second).
    *   The built-in terminal streams a live, color-coded tail of every agent transaction as it hits the gateway. If there has been no traffic in the last hour, the UI gracefully enters a `[Waiting for agent activity...]` holding state.
*   **Live Call Inspector (`/pipeline`):** This diagnostic view allows operators to track a single EVAR token as it moves chronologically through the Sentry Gateway cryptographic pipeline. The UI polls `/api/v1/logs` and visualizes each micro-decision (Identity Resolution, Semantic Alignment, Swarm Attestation) made by the gateway engine, providing a transparent audit trace of exactly why an API call was admitted or blocked.
*   **Agent Fleet (`/nodes`):** A centralized Command Center mapping all active provisioned agent nodes globally. It connects via `/api/v1/nodes` to monitor real-time node behavior and aggregated action metrics. From this interface, Operators possess the strict authority to execute a "Hard Stop" (quarantine) on any rogue agent, immediately terminating its access credentials network-wide.
*   **Agent Registry (`/registry`):** Functions as the global index mapping core AI identity, role definitions, and SOC2 compliance structures from the PostgreSQL ledger. The Registry (`/api/v1/registry`) allows Operators to execute bulk compliance actions such as enabling "Shadow Mode," seamlessly transitioning fleets from active prevention to read-only monitoring.
*   **Credential Vault (`/vault`):** A highly secure KMS interface for managing encrypted API keys (e.g., OpenAI, Anthropic) utilized by the AI agents. The vault visualizes cryptographic health indicators—flagging keys as Healthy, Warning, Critical, or Expired based on customizable rotation policies. The interface allows manual or triggered rotation (`/api/v1/vault/keys/{keyId}/rotate`) seamlessly without exposing the AES-256-GCM payloads in plain text, logging every rotation event immutably into the operator audit trail.
*   **Activity Ledger (`/logs`):** A comprehensive telemetry and audit history aggregating every action request sent to the Gateway. Driven by `/api/v1/logs`, it displays source identities, target APIs, decisions, and scores (Swarm and Semantic Alignment). Operators can filter these immutable traces by statuses (such as blocked or approved) and export verifiable CSV/JSON compliance reports.
*   **Action Rollbacks (`/sagas`):** A dedicated view monitoring the distributed saga orchestration. The system fetches `/api/v1/sagas` to visualize operations that required programmatic reversal. This explicitly tracks out-of-bounds agent behavior that triggered circuit breakers, required Human-in-the-Loop rejections, or forced auto-stopping measures, providing an explicit list of high-risk operational interventions.
*   **Client Companies (`/crm`):** The global tenant management dashboard connecting via `/api/v1/crm/companies`. It provides operators an aggregated top-down perspective on platform adoption, delineating tenant onboarding, total active or suspended plans, and raw counts of registered versus certified AI agents per entity.

---

## 7. Schema Ownership Policy

> **Established:** Iteration 20 (16 May 2026)  
> **Classification:** Architectural Decision Record

### Principle: Fail-Fast, Not Silent Self-Healing

The Cicada platform uses a single source of truth for all database schema: **Laravel migrations** (`Core_API/database/migrations/`). The Sentry Gateway does not create, alter, or repair schema. It validates that required tables and columns exist at boot and **refuses to start if any are missing**.

This is a deliberate design decision. A Gateway that silently creates missing tables masks underlying problems — the platform appears healthy while audit trails may not be written, certification status may not be enforced, and EVAR credentials may not be validated. A hard crash with a clear error message is always preferable to silent data loss.

### Three-Part Architecture

| Layer | Responsibility | Failure Mode |
|---|---|---|
| **Laravel Migrations** | Creates and alters all tables and columns. This is the single source of truth for the database schema. | `php artisan migrate` must succeed before any service starts. |
| **Go Schema Validation** | At boot, the Gateway checks that every required table and column exists. If any are missing, it logs a detailed error and calls `log.Fatalf`. | Gateway refuses to start. Operator is told exactly what's missing and how to fix it. |
| **CI Schema Parity Gate** | `scripts/verify-schema-parity.sh --ci` compares every table and column between `cicada_ledger` (production) and `cicada_test` (test). | Blocks release if any drift is detected. |

### Rules

1. **All schema changes** (new tables, new columns, type changes, indexes, constraints) **must** be defined as a Laravel migration under `Core_API/database/migrations/`.
2. **The Sentry Gateway does not manage schema.** It reads and writes to tables that already exist.
3. **Before any deployment,** `php artisan migrate` must be run against the target database.
4. **Before any merge,** `./scripts/verify-schema-parity.sh --ci` must pass with exit code 0.
5. **The Go migration SQL files** in `Sentry_Gateway/migrations/` are archived for historical reference. They document the reasoning behind each schema decision but are no longer executed.

### Historical Context

Prior to Iteration 20, the Sentry Gateway ran 17 SQL migration files at boot using `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`. This caused schema drift between the production database (`cicada_ledger`) and the test database (`cicada_test`), because the test database was only built from Laravel migrations and never received the Go-managed additions. Tests passed against incomplete schema, masking real failures.

The consolidation transferred all 8 Go-managed tables and 12 Go-managed columns into Laravel migrations. The Go boot sequence was replaced with `store.ValidateSchema()`, which checks for the existence of every required table and column without creating anything.
