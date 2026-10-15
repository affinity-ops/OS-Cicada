# Cicada Boilerplate & Scaffolding Architecture

This document explains the technical implementation of the Cicada Agent Scaffolding system, developed in Phase P1 & P2. The goal of this architecture is to provide an enterprise developer on-ramp that ensures every agent deployed on the platform is "secure-by-default" and automatically bound to Cicada's zero-trust gateway.

## Component Overview

The Scaffolder ecosystem spans the entire tech stack—from the local developer environment to the Sentry Gateway execution layer. It consists of four core components:

### 1. `cicada.yaml` (The Governance Policy Schema)
The system centers around `cicada.yaml`. Rather than declaring security configurations in code, developers construct a declarative YAML file that maps exactly to Sentry Gateway's internal enforcements. 
- **Identity:** `name`, `owner`, `criticality`
- **Scope & Tools:** Explicit allowlists mapping tool names to URL regex patterns. Complete denial of undeclared URLs.
- **Enforcement:** `hitl` thresholds, `max_writes_per_minute` velocity configurations, and `shadow_mode` switches.
- **Provenance:** Toggle for RAG source tagging into the action ledger.

### 2. Developer Portal Scaffolder (Frontend UI)
Located at `/scaffold` in the Developer Portal, this tool provides a 6-step visual wizard for developers. 
- **Integrations Catalogue:** Users select tools (e.g., Stripe, Slack, custom endpoints). The UI flags "destructive" capabilities.
- **Risk Assessor:** Automatically enforces Human-in-the-Loop (HITL) mandatory toggling if a selected tool is destructive or if the agent is declared "mission critical."
- **YAML Generator:** Compiles the selections into a raw `cicada.yaml` file dynamically.
- **Project Export:** Generates a complete project ZIP containing the selected framework template (Node, LangChain, CrewAI, AutoGen) with the generated YAML and `.env` template injected.

### 3. Core API YAML Consumer (Backend Registration)
The Laravel backend (via `YamlProvisioningController.php`) orchestrates the registration of these boilerplate configurations.
- When an agent is registered, the API accepts the raw `cicada.yaml` string alongside the developer's BYOK LLM key.
- The API uses `Symfony\Component\Yaml\Yaml` to parse the file structure, injecting the rules into their respective relational DB schemas (`agents`, `agent_tools`).
- The API automatically calls the Sentry Gateway via mTLS to mint the active Ed25519 JWT (EVAR), returning it directly to the developer environment.

### 4. Sentry Gateway (The Enforcement Layer)
**Edge-Native Hot Reloading:** The system utilizes inherent hot reloading. Because the Sentry Gateway queries PostgreSQL (`LookupAgentByHash`) on every proxy execution loop, any change made via the Developer Portal Scaffold UI or a CLI update is immediately effective on the next agent request. There is no config cache to invalidate, preventing split-brain policy drift between the dashboard and the gateway enforcement point.

## Workflow

1. Developer accesses Developer Portal `->` /scaffold.
2. Configures framework, tools, and compliance.
3. Downloads the Boilerplate ZIP.
4. Extracted codebase is registered via the backend `POST /api/v1/portal/provision/agent-from-yaml`.
5. The local agent boots up, sending requests through `http://localhost:8080/v1/proxy/...` passing its newly minted EVAR.
6. The Sentry Gateway executes the precise constraints generated during the scaffolding step without friction.
