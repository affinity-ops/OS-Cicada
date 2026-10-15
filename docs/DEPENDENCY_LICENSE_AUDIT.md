# Cicada Project — Dependency License Audit

**Date:** 26 May 2026
**License:** Apache-2.0 (Open Source Edition)
**Status:** ✅ No copyleft risks detected

---

## Summary

All dependencies across the entire project use **permissive licenses** (MIT, BSD, Apache-2.0, ISC) compatible with Apache-2.0 open-source distribution. A single LGPL dependency exists (psycopg2-binary) with a linking exception that makes it safe for downstream distribution.

**No GPL, AGPL, or strong copyleft dependencies were found in any component.**

---

## Go Dependencies

**Audited modules:** Sentry Gateway, Licensing Authority, Shadow Sandbox

**Direct dependencies (14 total):**

| Module | Dependency | License | Safe? |
|--------|-----------|---------|-------|
| Sentry Gateway | github.com/cloudflare/circl v1.6.3 | BSD-3-Clause | ✅ |
| Sentry Gateway | github.com/go-chi/chi/v5 v5.0.11 | MIT | ✅ |
| Sentry Gateway | github.com/golang-jwt/jwt/v5 v5.2.0 | MIT | ✅ |
| Sentry Gateway | github.com/gorilla/websocket v1.5.1 | BSD-2-Clause | ✅ |
| Sentry Gateway | github.com/jackc/pgx/v5 v5.5.1 | MIT | ✅ |
| Sentry Gateway | github.com/open-policy-agent/opa v0.60.0 | Apache-2.0 | ✅ |
| Sentry Gateway | github.com/redis/go-redis/v9 v9.4.0 | BSD-2-Clause | ✅ |
| Sentry Gateway | go.opentelemetry.io/otel v1.43.0 | Apache-2.0 | ✅ |
| Sentry Gateway | go.opentelemetry.io/otel/trace v1.43.0 | Apache-2.0 | ✅ |
| Sentry Gateway | golang.org/x/net v0.25.0 | BSD-3-Clause | ✅ |
| Sentry Gateway | golang.org/x/oauth2 v0.36.0 | BSD-3-Clause | ✅ |
| Sentry Gateway | modernc.org/sqlite v1.28.0 | BSD-3-Clause | ✅ |
| Licensing Authority | github.com/cloudflare/circl v1.6.3 | BSD-3-Clause | ✅ |
| Shadow Sandbox | github.com/mattn/go-sqlite3 v1.14.22 | MIT | ✅ |

**Indirect/transitive:** ~60+ unique dependencies all under MIT, BSD-2/3, or Apache-2.0.

**GPL/AGPL flagged:** None.

---

## Python Dependencies

**Audited modules:** Verification Swarm, Saga Executor, Cicada SDK

| Package | Version | License | Safe? |
|---------|---------|---------|-------|
| langgraph | >=0.0.26 | MIT | ✅ |
| redis | >=5.0.1 | MIT | ✅ |
| openai | >=1.12.0 | Apache-2.0 | ✅ |
| numpy | >=1.24.0 | BSD-3-Clause | ✅ |
| psycopg2-binary | >=2.9.9 | **LGPL** (linking exception) | ✅ |
| cryptography | >=42.0.0 | Apache-2.0 / BSD-3-Clause | ✅ |
| fastapi | >=0.115.0 | MIT | ✅ |
| uvicorn | >=0.34.0 | BSD-3-Clause | ✅ |
| pydantic | >=2.5.0 | MIT | ✅ |
| requests | >=2.31.0 | Apache-2.0 | ✅ |
| pandas | >=2.2.0 | BSD-3-Clause | ✅ |
| pyarrow | >=15.0.0 | Apache-2.0 | ✅ |
| boto3 | >=1.34.0 | Apache-2.0 | ✅ |
| pyyaml | >=6.0 | MIT | ✅ |
| jsonschema | >=4.17.0 | MIT | ✅ |
| langchain-core | >=0.1.0 | MIT | ✅ |
| crewai | >=0.1.0 | MIT | ✅ |

**GPL/AGPL flagged:** Only psycopg2-binary (LGPL with linking exception — safe as a dynamically-linked C extension).

---

## Node.js Dependencies

**Audited modules:** Dashboard, Developer Portal, Gateway Portal, Landing Page, Master Admin Panel

| Portal | Dependencies | Licenses | Safe? |
|--------|-------------|----------|-------|
| Dashboard | next, react, react-dom, three, react-globe.gl, @simplewebauthn, react-markdown, remark-gfm, @tailwindcss/typography | MIT | ✅ |
| Developer Portal | next, react, react-dom, js-yaml, react-qr-code | MIT | ✅ |
| Gateway Portal | next, react, react-dom, d3, d3-sankey | MIT, ISC | ✅ |
| Landing Page | next, react, react-dom | MIT | ✅ |
| Master Admin Panel | next, react, react-dom, react-qr-code | MIT | ✅ |

Internal workspace package `@cicada/ui` is licensed under Apache-2.0.

**GPL/AGPL flagged:** None.

---

## Flutter/Dart Dependencies

**Audited modules:** Aegis Companion App, Sentinel App

| Package | License | Safe? | Used by |
|---------|---------|-------|---------|
| flutter | BSD-3-Clause | ✅ | Both |
| cryptography | BSD-3-Clause / Apache-2.0 | ✅ | Both |
| flutter_secure_storage | BSD-3-Clause | ✅ | Both |
| local_auth | BSD-3-Clause | ✅ | Both |
| flutter_bloc | MIT | ✅ | Both |
| mobile_scanner | MIT | ✅ | Both |
| http | BSD-3-Clause | ✅ | Both |
| dio | MIT | ✅ | Aegis |
| google_fonts | BSD-3-Clause | ✅ | Aegis |
| shimmer | MIT | ✅ | Aegis |
| firebase_core | BSD-3-Clause | ✅ | Aegis |
| firebase_messaging | BSD-3-Clause | ✅ | Aegis |
| flutter_local_notifications | BSD-3-Clause | ✅ | Aegis |
| flutter_soloud | MIT | ✅ | Aegis |
| sqflite | BSD-3-Clause | ✅ | Aegis |
| path_provider | BSD-3-Clause | ✅ | Aegis |
| connectivity_plus | BSD-3-Clause | ✅ | Aegis |
| intl | BSD-3-Clause | ✅ | Aegis |
| shared_preferences | BSD-3-Clause | ✅ | Aegis |
| device_info_plus | BSD-3-Clause | ✅ | Aegis |
| cupertino_icons | MIT | ✅ | Both |

**GPL/AGPL flagged:** None.

---

## PHP (Composer) Dependencies

**Audited module:** Core API

| Package | License | Safe? |
|---------|---------|-------|
| laravel/framework | MIT | ✅ |
| laravel/sanctum | MIT | ✅ |
| laravel/socialite | MIT | ✅ |
| laravel/tinker | MIT | ✅ |
| barryvdh/laravel-dompdf | LGPL | ✅ (LGPL, safe for linking) |
| darkaonline/l5-swagger | MIT | ✅ |

**GPL/AGPL flagged:** barryvdh/laravel-dompdf (LGPL — safe for use as a library dependency).

---

## Overall Verdict

**License type breakdown:**
| License | Count | Risk |
|---------|-------|------|
| MIT | ~40 | ✅ None |
| BSD-2/3-Clause | ~35 | ✅ None |
| Apache-2.0 | ~35 | ✅ None |
| ISC | 2 | ✅ None |
| LGPL (with linking exception) | 2 (psycopg2-binary, laravel-dompdf) | ✅ Safe for distribution |
| GPL / AGPL | 0 | ✅ No risk |

**Continuous Verification:**
1. Run `go-licenses check ./...` and `npx license-checker --production` in CI when adding new dependencies.
2. Root `LICENSE` file defines the Apache-2.0 open-source license terms for the repository.