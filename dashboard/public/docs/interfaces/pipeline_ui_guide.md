---
title: "Pipeline Execution Map"
category: "Sentry Gateway Protocol"
description: "Visualizing the 10-stage Kafka messaging ingestion sequence."
---

# Sentry Pipeline Engine

The Pipeline Execution module (`/pipeline`) provides a surgical diagnostic environment for resolving latency spikes or execution intercepts occurring within the Sentry Gateway Kafka pipeline.

## 1. Topographic Execution Traces
Operators analyze physical constraints using decoupled execution vectors, switching contexts using the **Mode Switchers**.
- **Intercept Mode**: Pulls the specific Kafka offset that failed execution limits, halting at Stage 5 and demonstrating Rego bounds blocking the exact payload (e.g., `DROP TABLE`).
- **Nominal Mode**: Overlays a clean pass logic tree to benchmark against standard execution speeds (e.g. baseline `12ms` vs intercepted `114ms`).

## 2. Terminal-to-Graphic State Routing (Friction Points)
Operating under the strict platform interaction mandate, the Pipeline ensures operators never manually hunt for correlation logic.
- Instead of clicking through dead endpoints, any operator reading the **Shadow Consumer Log** terminal can simply `hover` over a log index line.
- Triggering an `onHover` sequence across the terminal line natively fires a focus lock onto the massive graphic architecture, dramatically dimming unaffected execution stages and visually isolating the exact microVM logic block that produced the terminal payload ping.
- This creates physical interactivity across debugging sessions, tying backend textual errors seamlessly to graphical representations of swarm latency parameters.

## 3. Diagnostic Portals
When an execution trace mathematically fails (e.g. Sentry Threshold timeout), the friction-point visual `node` physically binds to the subsystem router handling that evaluation. 
- Hovering over a glowing anomalous stage injects an overlay prompt requesting diagnostic intervention. 
- Clicking the stage entirely removes the operator from the execution trace and places them precisely into the control dashboard for that data vector (e.g., Stage 5 drops you instantly into `/security` to view the Rego bounds restricting the EVAR).
