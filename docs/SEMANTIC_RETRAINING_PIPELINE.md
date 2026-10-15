# Semantic Engine Retraining Pipeline

Cicada utilizes a dual-tier semantic engine for real-time intent verification. The primary embedding model (`nomic-embed-text`) is deterministic, runs locally within the Gateway edge node, and performs continuous zero-trust validation of agent payloads against their declared behavioral embedding cluster.

Over time, as enterprise use cases evolve, "semantic drift" can occur—leading to a potential increase in false positive blocks (where legitimate novel agent behavior is incorrectly flagged as a deviation from the established baseline). 

To prevent model degradation and ensure high fidelity intent verification, Cicada provides a built-in telemetry loop and automated dataset generation pipeline for fine-tuning the underlying embeddings.

## 1. Feedback Capture (The Telemetry Loop)

When the Sentry Gateway blocks a payload due to semantic drift (Tier 1 rejection), the action is immutably logged to the centralized `action_ledger` with `status = 'blocked'`.

If an enterprise operator determines that the blocked action was actually legitimate, they can manually override the decision via the Developer Portal. 
When this override occurs, Cicada automatically hits the **False Positive Endpoint** (`POST /api/v1/portal/logs/{traceId}/false-positive`). 

This endpoint flags the specific trace in the `action_ledger` by setting `is_false_positive = true`, while preserving the exact `payload_hash`, the agent's `reasoning_trace`, the `human_user_context`, and the generated `semantic_alignment_score`.

## 2. Dataset Export

The Cicada Core API provides an administrative endpoint to export this aggregated telemetry:
`GET /api/v1/portal/admin/retraining-dataset`

This endpoint queries the partitioned `action_ledger` for all records where `is_false_positive = true` and streams the results back as a highly compressed `.jsonl` (JSON Lines) file. 

The exported JSONL dataset contains:
*   `trace_id`
*   `agent_id`
*   `target_api`
*   `action_type`
*   `payload_hash`
*   `human_user_context`
*   `reasoning_trace`
*   `semantic_alignment_score`

This format is natively compatible with standard MLOps platforms and fine-tuning pipelines.

## 3. Retraining Process

To fine-tune the `nomic-embed-text` weights:

1.  **Data Ingestion:** Import the `cicada_retraining_dataset_YYYY_MM_DD.jsonl` file into your MLOps pipeline (e.g., Hugging Face Autotrain, MLflow, or a custom PyTorch script).
2.  **Contrastive Learning:** Use the dataset as positive pairs for contrastive learning. The `payload_hash` (the prompt) and the `action_type` (the target capability) represent pairs that the model previously scored poorly on but *should* be mapped closely together in vector space.
3.  **Model Compilation:** Once the new weights are trained, re-compile the model using `ollama create` with the updated Modelfile.
4.  **Deployment:** Deploy the updated model artifact to the Gateway fleet. The Gateways will hot-reload the updated embeddings into memory without requiring a restart, immediately resolving the semantic drift.
