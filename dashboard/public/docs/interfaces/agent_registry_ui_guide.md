# The Verified Agent Registry

The **Agent Registry** (accessible via the `Nodes` navigation link at `/nodes`) acts as the interactive decentralized ledger and Command & Control center for the Cicada Mesh Network. It visualizes the active swarm of autonomous nodes and is responsible for manual operator overrides.

## Interface Components

### 1. Mesh Network Nodes (Bento Grid)
The core visualization presents a dynamic matrix of currently active swarm instances (e.g., `VALKYRIE-09`, `ORACLE-03`, `TITAN-14`). 
- **Trust Score**: This percentage represents real-time algorithmic confidence in the agent's behavior. A high trust score (e.g., >95%) indicates the agent acts predictably within scope.
- **Latency & Load**: Identifies how much raw compute the microVM constraint is utilizing. 
- High-risk nodes automatically trigger an `Alert` visual state, warning the Operator of decoupled boundaries.

### 2. Featured Central Cluster
The primary structural pane highlights the backbone architectural unit (e.g., `HELIOS CENTRAL CLUSTER`). This metric indicates how much weight a specific localized node pool handles in context to the global mesh.

### 3. Agent Submission Protocol
Situated functionally at the bottom-right of the interface is the **Register Agent** operator macro. 
- Activating this sequence commands the client to intercept raw agent specifications and dispatch them explicitly to the `Sentry Gateway` via the `POST /v1/agents/submit` pipeline.
- It provides physical visual feedback mapping the cryptographic delay (the wait period while HMAC-SHA256 tokens are minted offline) before generating an `HTTP 202 EVAR Certified` action ledger commitment directly to the screen.

## Verification Checklist
- [x] Connected dynamic CSS collapsible layout integration.
- [x] Functional `use_client` state execution successfully mapping Swarm submission pipelines.
- [x] Grid flexibility supporting theoretically limitless EVAR node arrays.
