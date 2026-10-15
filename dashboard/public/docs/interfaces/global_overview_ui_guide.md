# The Global Overview Interface

The **Global Overview** (accessible via the `Architecture` node at root `/`) serves as the panoptic command sequence for the entire CICADA mesh network. It synthesizes execution metrics across the 10-stage trust continuum into highly scannable, real-time widgets.

## Interface Components

### 1. The Core KPI Matrix
The dashboard leads with 4 cardinal statistics that dictate the immediate health of the A-aaS platform:
- **Active Instances**: Tracks the total volume of ephemeral MicroVMs (Shadow Sandboxes) currently executing agent payloads. An increase here signifies heavy Swarm processing.
- **Compute Load**: Aggregates the CPU/Memory pressure across the `gVisor` and `Firecracker` clusters. 
- **Threat Vectors**: A direct pipeline into the Sentry Gateway. Any attempts by an agent EVAR to exceed its cryptographic scope are blocked and instantly tabulated here.
- **Data Ingestion**: The byte-velocity of the Kafka message queue broker processing asynchronous swarm commands.

### 2. Multi-Dimensional Telemetry Graph
This primary line-chart is no longer an action volume generic map; it is a fully mathematically synchronized routing engine utilizing Cubic Bezier interpolations against raw data arrays.
- **Metric Array Switching**: Operators can utilize the action switches above the plot `[Analytics]`, `[Compute]`, `[Threats]` to instantly load divergent data arrays onto the visual spectrum. 
- **Time Bounding Box**: Operators can manipulate the timeline using the `Live | 24H | 7D` toggle hooks, instantly redefining the maximum boundaries and labels.
- **Node-Anchored Routing**: Every point plotted mathematically on the trajectory curve contains a hover-state Node `<circle>`. Hovering identifies the exact statistical density, and clicking the Node actively teleports the operator to the sub-dashboard defined by the active metric constraint. For example:
  - Clicking a **Threat** Spike routes strictly to `/security` (Rego limits).
  - Clicking a **Compute** Spike routes strictly to `/compute` (Swarm diagnostics).
  - Clicking a **Latency** Spike routes strictly to `/pipeline` (Kafka ingestion queue diagnostics).

### 3. Node Distribution & Drill-Down
A geographical mapping of active processing clusters. 
- If a specific AWS or On-Prem infrastructure node goes offline (e.g., `CLUSTER_NORTH_AM_01` suffering >90ms latency drift), it will flash an error variant locally.
- **Interaction Flow:** By clicking directly on the pulsing geographic anchor, the Operator is natively teleported straight into the `/nodes` (Agent Registry CRM). This ensures zero abstraction between seeing a global error and diagnosing its specific EVAR subset component.

## Verification Checklist
- [x] Responsive layout utilizing global `--sidebar-width` transitions.
- [x] Dynamic visual routing leveraging `<KPICard href="..." />` endpoints structurally mapping to `/nodes`, `/compute`, `/security`, and `/pipeline`.
- [x] Timeframe Action Volume mapping via React state operators flipping visual indices locally.
