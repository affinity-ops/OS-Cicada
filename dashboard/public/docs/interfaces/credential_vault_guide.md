# Credential Vault — Operator User Guide

**Version:** 1.0  
**Last Updated:** 2026-06-07  
**Audience:** Platform Operators (System Administrators)

---

## What Is the Credential Vault?

The Credential Vault is where you manage the API keys that power your AI agents. Every AI agent that runs through Cicada needs an API key to talk to its underlying model provider (OpenAI, Anthropic, etc.). These keys are stored encrypted in the vault and are never visible in plain text — not to you, not to your agents, and not even to Cicada's own backend code.

Think of the Credential Vault as a secure, monitored safe for your most sensitive credentials. It doesn't just store keys — it actively tracks their health, warns you when they need rotating, and logs every time they're accessed.

---

## Page Overview

When you open the Credential Vault from the sidebar, you'll see five distinct sections:

1. **Health Summary Bar** — Fleet-wide status at a glance
2. **Aegis AI Assistant Key** — Your AI security assistant's API connection
3. **Add API Keys** — Bind new keys for your agents
4. **Stored Credentials** — All keys currently in the vault with lifecycle tracking
5. **Key Usage Log** — Recent vault-related activity

Let's walk through each one.

---

## 1. Health Summary Bar

At the top-right of the page, you'll see four small cards showing the overall health of all stored credentials:

| Status | Colour | What It Means |
|--------|--------|---------------|
| **Healthy** | 🟢 Green | Key is within its safe rotation window (less than 54 days old) |
| **Warning** | 🟡 Amber | Key is approaching its rotation deadline (54–76 days old) |
| **Critical** | 🟠 Orange | Key is overdue for rotation (76–90 days old) |
| **Expired** | 🔴 Red | Key has exceeded the rotation policy limit (90+ days old) |

The number next to each status tells you how many keys fall into that category. Your goal as an operator is to keep everything in the green "Healthy" column.

> **What triggers a rotation warning?**
> The platform enforces a configurable rotation policy (default: 90 days). This aligns with security best practices — API keys that are never rotated are a compliance and security risk. When a key crosses the warning threshold, the card will visually escalate from green to amber to orange to red.

---

## 2. Aegis AI Assistant Key

### What Is Aegis?

Aegis is your built-in AI security assistant. It is the "brain" behind Cicada's automated threat detection and response. While the Sentry Gateway handles the mechanical work of proxying and blocking agent calls, Aegis is the intelligence layer that:

- **Monitors all agent activity** in real time, looking for unusual patterns
- **Reasons about threats** — it doesn't just match rules, it analyses behaviour and explains its thinking
- **Takes protective actions** when it identifies genuine threats (quarantining agents, engaging ghost mode, triggering rollbacks)
- **Alerts you** via the dashboard when it needs human confirmation for high-impact decisions

Aegis connects to the Sentry Gateway through a protocol called MCP (Model Context Protocol). This gives it direct access to tools like:

| Tool | What Aegis Uses It For |
|------|------------------------|
| `quarantine_agent` | Immediately blocks a rogue agent across all gateway nodes |
| `engage_ghost_mode` | Silently diverts a suspicious agent's traffic to a sandbox without the agent knowing |
| `trigger_saga_rollback` | Reverses a harmful action an agent already took |
| `list_quarantined` | Checks which agents are currently blocked |
| `get_agent_velocity` | Reads how fast an agent is making calls to detect velocity anomalies |

### Why Does Aegis Need an API Key?

Aegis is itself an AI — it runs on a large language model to do its analysis and reasoning. It uses **OpenRouter** as its model gateway, which gives it access to a wide selection of AI models (DeepSeek R1, Claude, Llama, and more). You choose which model Aegis uses from the Aegis Command Center page.

The OpenRouter key you bind here is what gives Aegis its "brain power." Without it, Aegis cannot reason about threats — it would be deaf and blind.

### How to Bind Your Aegis Key

1. Obtain an API key from [OpenRouter](https://openrouter.ai)
2. Paste it into the input field under "Aegis AI Key"
3. Click **Bind to Vault**
4. You'll see a confirmation: *"CiphertextBlob generated. Plain text destroyed."*

Once bound, the key is:
- Encrypted with AES-256-GCM
- Scoped to the system-level operator account (`sys_admin_core`)
- Immediately wiped from your browser's memory

> **Security note:** The moment you click "Bind to Vault," the plain-text key is physically removed from the browser input field and from memory. It cannot be retrieved, viewed, or copied again — only the encrypted version exists in the vault. If you need to change the key, simply paste the new one and bind again.

---

## 3. Add API Keys for Your Agents

Below the Aegis section, you'll find two input fields for binding agent-facing API keys:

- **Anthropic Key** — For agents that use Claude models
- **OpenAI Key** — For agents that use GPT models

These are the keys your tenants' AI agents will use when making inference calls through the Cicada proxy. The binding process is identical to the Aegis key:

1. Paste the key from the provider's dashboard
2. Click **Bind to Vault**
3. Confirmation appears — key is now encrypted and stored

### How Keys Are Used at Runtime

When an AI agent sends a request through the Sentry Gateway, the gateway:
1. Validates the agent's identity (EVAR token / session)
2. Checks the agent's policy compliance (scope, trust tier, velocity)
3. Retrieves the tenant's encrypted API key from the vault
4. Decrypts it **only inside the Verification Swarm** (an isolated execution environment)
5. Forwards the request to the AI provider with the decrypted key
6. Returns the AI provider's response to the agent

The key is never exposed outside the Swarm boundary. Even the Sentry Gateway itself only handles the ciphertext.

---

## 4. Stored Credentials

This is the main section of the page — a grid of cards showing every key currently stored in the vault. Each card gives you a complete lifecycle view of a single credential.

### Anatomy of a Key Card

#### Provider Badge
The coloured label at the top-left (e.g., "OPENAI", "ANTHROPIC") tells you which AI provider this key belongs to.

#### Health Badge
The badge at the top-right shows the current health status of this key:
- **✓ Healthy** (green) — Within safe rotation window
- **⏰ Rotation Due** (amber) — Approaching rotation deadline
- **⚠ Overdue** (orange) — Past the recommended rotation date
- **✕ Expired** (red) — Exceeded the rotation policy

#### Tenant Name
The company name that owns this key. This is the client organisation who brought the key to the platform.

#### Age Ring
The circular gauge on the left shows how old the key is as a visual countdown:
- The number in the centre is the **age in days**
- The coloured ring fills up as the key ages
- The ring changes colour to match the health status

#### Lifecycle Stats
Next to the age ring, three data points:

| Stat | What It Shows |
|------|---------------|
| **Expires In** | Days remaining before the key enters "expired" status. Shows "EXPIRED" in red if already past the limit. |
| **Rotations** | How many times this key has been rotated since it was first created. Tracked via the audit trail. |
| **Last Used** | The most recent date an agent belonging to this tenant made any API call through the proxy. |

#### Key Display
The masked display (`██████████████████████████████...`) confirms a key exists for this slot. The actual key value is never shown — this is by design. The platform enforces a zero-visibility policy.

#### Age Progress Bar
A thin bar below the masked key that fills from left (0 days) to right (policy limit, e.g., 90 days). Matches the health status colour.

#### Footer
Shows the creation date and last rotation date. The **Rotate Key** button is here too.

### Rotate Key Button

When you click **Rotate Key**, you're telling Cicada: "I have rotated this key at the provider's end — reset the age clock."

What happens:
1. The key's `updated_at` timestamp is reset to now
2. The health status recalculates (typically returns to "Healthy")
3. An audit log entry is created recording who rotated the key and when
4. The card refreshes to show the updated lifecycle data

> **Important:** Clicking "Rotate Key" does **not** generate a new API key for you. You must rotate the key directly with the provider (OpenAI dashboard, Anthropic console, etc.) first, then either re-bind the new key via the "Add API Keys" section, or click "Rotate Key" if the same key is still valid and you just need to reset the compliance clock.

When a key is **critical** or **expired**, the Rotate Key button pulses red and changes to **Rotate Now** to signal urgency.

---

## 5. Urgent Rotation Banner

If any keys are in "critical" or "expired" status, a red/orange gradient banner appears at the top of the stored credentials section. It tells you:
- How many credentials need immediate attention
- What your current rotation policy is (e.g., 90 days)
- That these keys violate your rotation policy

This banner disappears automatically once all overdue keys are rotated.

---

## 6. Key Usage Log

At the bottom of the page, a chronological log shows the 10 most recent vault-related events:

| Column | What It Shows |
|--------|---------------|
| **Action** | The type of event (e.g., "key rotation", "agent provisioned", "vault sync") |
| **Tenant** | Which company's keys were involved |
| **Status** | Whether the operation succeeded or failed |
| **Time** | When it happened |

Each entry is colour-coded — the most recent entries get the brightest left border to draw your eye to the latest activity.

Click **View Full Activity Log** to open the complete Activity Ledger page for deeper investigation.

---

## How Aegis Uses the Credential Vault

Here's the full picture of how Aegis, the Credential Vault, and the Sentry Gateway work together:

```
                                                ┌─────────────────────┐
                                                │   OpenRouter API    │
                                                │   (AI Model Host)   │
                                                └──────▲──────────────┘
                                                       │
                                          Aegis's encrypted key
                                           is decrypted here
                                                       │
┌─────────┐    MCP Protocol     ┌──────────────────────┤──────────────┐
│  Aegis  │◄──────────────────► │    Sentry Gateway    │              │
│  (AI)   │  quarantine_agent   │                      │  Credential  │
│         │  engage_ghost_mode  │  • Proxy Pipeline    │  Vault (DB)  │
│         │  trigger_rollback   │  • Gossip Mesh       │              │
│         │  list_quarantined   │  • Policy Engine     │  tenant_keys │
│         │  get_agent_velocity │  • Key Binding       │  table       │
└─────────┘                     └──────────────────────┴──────────────┘
                                          ▲
                                          │
                                   Agent API calls
                                   flow through here
                                          │
                                ┌─────────┴─────────┐
                                │   AI Agents        │
                                │   (Client-side)    │
                                └────────────────────┘
```

**Step by step:**

1. You bind your OpenRouter key in the Credential Vault under "Aegis AI Assistant Key"
2. Aegis uses this key to power its reasoning model (e.g., DeepSeek R1)
3. When Aegis detects a threat, it calls a Gateway MCP tool (e.g., `quarantine_agent`)
4. The Gateway executes the action immediately across all nodes
5. You see the result on the Aegis Command Center page and in the Activity Ledger

Meanwhile, your tenants' agent-facing keys (OpenAI, Anthropic) flow through a parallel path:

1. Tenant binds their API key via the Developer Portal or the Vault page
2. The key is encrypted and stored in `tenant_keys`
3. When an agent makes a proxied call, the Gateway decrypts the key inside the Verification Swarm
4. The key is used for one request and never retained in memory

---

## Quick Reference

| Task | How To |
|------|--------|
| **Activate Aegis** | Paste your OpenRouter key in the "Aegis AI Assistant Key" section and click "Bind to Vault" |
| **Add a new API key** | Paste the provider key in the "Add API Keys" section and click "Bind to Vault" |
| **Check key health** | Look at the Health Summary cards at the top-right, or the health badge on individual key cards |
| **Rotate a key** | Rotate at the provider first, then click "Rotate Key" on the card to reset the compliance clock |
| **Investigate key usage** | Check the "Key Usage Log" at the bottom, or click "View Full Activity Log" for the complete trail |
| **Change Aegis's model** | Go to the Aegis Command Center page (separate from the Vault) to select a different model |
| **View Aegis's actions** | Go to the Aegis Command Center page to see its reasoning, actions taken, and active alerts |

---

## Security Guarantees

| Guarantee | How It's Enforced |
|-----------|-------------------|
| **Keys are never shown in plain text** | `payload_encrypted` stores AES-256-GCM ciphertext; UI shows `██████...` mask |
| **Keys are wiped from browser memory** | `SecureInput` component zeros the DOM input after POST |
| **Keys are wiped from server memory** | Go handler zeros `body.RawKey` after encryption |
| **Key access is audited** | Every rotation and vault event is logged to `operator_audit_log` |
| **Keys are scoped to tenants** | `UNIQUE(tenant_id, provider)` constraint — one key per provider per company |
| **Aegis key is isolated** | Uses `sys_admin_core` tenant ID — separate from all client keys |
| **Decryption is contained** | Keys are only decrypted inside the Verification Swarm isolation boundary |

---

*This guide is part of the Cicada Operator Manual. For technical details, see the companion [Credential Vault Forensic Audit](./credential_vault_forensic_audit.md).*
