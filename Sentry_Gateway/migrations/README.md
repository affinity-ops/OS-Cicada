# ARCHIVED — Go-Managed Migrations

> **Status:** Archived as of 2026-05-16 (Iteration 20)
> **Reason:** Schema ownership consolidated under Laravel

## What Changed

These SQL files were previously executed by the Sentry Gateway at boot via `store.RunMigrations()` in `cmd/sentry/main.go`. Each migration used `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` to be idempotent.

As of Iteration 20, **all schema is now owned by Laravel** (`Core_API/database/migrations/`). The Gateway validates schema at boot via `store.ValidateSchema()` and fails fast if expected tables/columns are missing, rather than creating them.

## Why These Files Are Retained

1. **Historical reference** — Documents the reasoning behind each schema decision
2. **Migration traceability** — Maps production columns back to the iteration they were added
3. **Audit compliance** — Preserves the chain of custody for schema changes

## Mapping to Laravel Migrations

| Go Migration | Laravel Migration |
|---|---|
| `001_multi_tenant_schema.sql` | `2026_04_19_000001_create_tenants_table.php` + `2026_04_19_000002_create_agents_table.php` |
| `002_ghost_mode_consent.sql` | `2026_05_16_000002_add_go_managed_agent_columns.php` |
| `003_policy_governance.sql` | `2026_05_16_000001_create_go_managed_tables.php` (policy_versions) |
| `004_reasoning_trace.sql` | `2026_05_15_160350_sync_action_ledger_schema.php` |
| `005_gateway_instances.sql` | `2026_04_23_000001_create_gateway_instances_table.php` |
| `006_semantic_alignment.sql` | `2026_05_15_160350_sync_action_ledger_schema.php` |
| `007_mobile_devices.sql` | `2026_05_16_000001_create_go_managed_tables.php` (mobile_devices, decision_nonces, hold_payloads, quorum_votes) |
| `008_aegis_devices.sql` | `2026_05_16_000001_create_go_managed_tables.php` (aegis_devices) |
| `009_pairing_challenges.sql` | `2026_04_30_000002_create_mobile_pairing_challenges.php` + `2026_05_16_000001_create_go_managed_tables.php` (attestation_config) |
| `009_quorum_enforcement.sql` | `2026_05_16_000001_create_go_managed_tables.php` (quorum_votes) |
| `010_credential_rotation.sql` | `2026_05_16_000001_create_go_managed_tables.php` (credential_rotation_events) |
| `011_federation_config.sql` | System configs — already in `2026_04_21_202542_create_system_configs_table.php` |
| `012_role_mappings.sql` | Handled at application level |
| `013_scim_operators.sql` | Handled at application level |
| `014_mobile_pqc_columns.sql` | `2026_05_16_000001_create_go_managed_tables.php` (ml_dsa65_pub, ml_kem768_pub on mobile_devices) |
| `015_certification_lifecycle.sql` | `2026_05_16_000002_add_go_managed_agent_columns.php` + `2026_05_16_000003_create_certification_events_table.php` |
| `016_provisioning_governance_columns.sql` | `2026_05_16_000002_add_go_managed_agent_columns.php` |
| `017_action_ledger_model.sql` | `2026_05_15_160350_sync_action_ledger_schema.php` |

## Do Not Modify

These files should not be edited. They are frozen at their last-executed state.
Any new schema changes must go through `Core_API/database/migrations/`.
