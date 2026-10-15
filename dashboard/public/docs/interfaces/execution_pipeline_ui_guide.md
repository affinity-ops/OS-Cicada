# The Execution Pipeline Dashboard

The **Execution Pipeline** (accessible via the `Pipeline` navigation link at `/pipeline`) is arguably the most critical diagnostic interface. It allows operators to trace a single agent's cognitive processing vector through the 10-Stage Trust Continuum.

## Interface Components

### 1. Mini-CRM Target Profiler
A sophisticated isolation panel allowing operators to select and query a specific agent interacting with the Gateway.
- Dynamically highlights physical agent capabilities (e.g. `scopes: ["sys.read", "db.write"]`).
- Maps the agent's `<EVAR>` token hashing structure alongside its active Trust Classification level.

### 2. The 10-Stage Propagation Vector
A beautiful, highly technical graphical tree explicitly visualizing the processing lifecycle of an intelligence workload.
- **Stage 1-3**: Pre-processing (Claim Extraction & Context Graph Retrieval).
- **Stage 4-5**: Offline mapping and payload serialization into the Kafka Messaging Log (`sqlite`).
- **Stage 6-8**: The core Sandbox Execution cycle tracking Shadow VM processing against pure adversarial pressure testing.
- **Stage 9-10**: The finalizing Sentry gateway actions, converting mathematical vectors into binary Allow/Deny states.

### 3. Real-Time Daemon Logging Terminal
A raw, scrolling code-terminal visualization mirroring standard output from the backend verification swarm. 
- It tracks the `KafkaConsumerMock.poll` sequences natively, translating background python SQLite read-mechanisms into live visual diagnostics.

## Verification Checklist
- [x] Absolute structural parity with the "Cyber Obsidian" master branding.
- [x] Responsive layout integration dynamically adjusting to Sidebar state compression.
- [x] Accurate mathematical routing representation of the adversarial review structure.
