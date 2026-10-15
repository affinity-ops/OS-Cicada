# ADR-001: Hybrid Relational Schema & Table Ownership Model

**Status:** Accepted & Enforced  
**Date:** June 2026 (Iteration 20 Baseline)  
**Context:** Multi-language hybrid architecture (Go Sentry Gateway + Laravel Core API)

---

## 1. Context & Architectural Challenge

Cicada utilizes a dual-engine control plane:
1. **Sentry Gateway (Go):** High-throughput, sub-millisecond network security proxy executing 15 sequential enforcement stages per request.
2. **Core API (Laravel/PHP):** Management control plane, developer portal backchannel, organization management, and OAuth 2.0 / CIBA authentication workflows.

Because both engines interact with the same underlying PostgreSQL cluster, an uncoordinated database schema leads to migration lockups, ambiguous column definitions, and cross-framework coupling.

---

## 2. Decision: Strict Namespace & Table Ownership Isolation

To preserve sub-millisecond execution in Go while maintaining Laravel Eloquent flexibility in the Core API, database tables are strictly partitioned into two domain namespaces:

### A. The `sentry` Schema Namespace (Go Owned)
- **Primary Owner:** `Sentry_Gateway` (`go-pgxpool`)
- **Key Tables:** `sentry.action_ledger`, `sentry.token_usage_logs`, `sentry.agent_rate_meters`, `sentry.active_policies`
- **Ownership Rule:** The Go gateway manages DDL migrations in `active_migrations/*.sql`. The Laravel Core API reads `sentry.action_ledger` as read-only audit signal data.

### B. The `public` Schema Namespace (Laravel Owned)
- **Primary Owner:** `Core_API` (`Laravel Eloquent Migrations`)
- **Key Tables:** `public.users`, `public.tenants`, `public.agents`, `public.agent_keys`, `public.ciba_requests`
- **Ownership Rule:** Laravel manages DDL migrations for user identity, team membership, and API credential provisioning. Go accesses `public.agents` and `public.agent_keys` via high-speed, read-only Redis caches with PostgreSQL fallbacks.

---

## 3. Benefits & Trade-Offs

- **Zero Migration Collisions:** Go service deployments never lock Laravel migration tables.
- **Fail-Closed Isolation:** If the Laravel control plane is offline, the Sentry Gateway continues enforcing network security policies using local Redis cached states.
- **Non-Blocking Audit Trail:** High-velocity audit logs in `sentry.action_ledger` do not contend with user session locks in `public.users`.
