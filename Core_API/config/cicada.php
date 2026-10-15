<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Centralised configuration for Cicada platform services.
 * All custom env vars are read here — use config('cicada.*') everywhere else.
 *
 * NOTE: PostgreSQL is a hard dependency. The action_ledger, agents, and
 * governance queries use FILTER(), ::varchar casts, JSONB operators, and
 * interval arithmetic that are PostgreSQL-specific. Do not attempt to run
 * this application against MySQL or SQLite in production.
 */
return [
    // ── Service URLs ──────────────────────────────────────────────────────────
    'swarm_url'   => env('CICADA_SWARM_URL', 'http://localhost:9091'),
    'gateway_url' => env('CICADA_GATEWAY_URL', 'http://localhost:8080'),
    'sandbox_url' => env('SANDBOX_API_URL', 'http://localhost:9090'),

    // ── Circuit Breaker ───────────────────────────────────────────────────────
    'circuit_breaker' => [
        'window_minutes'       => (int) env('CIRCUIT_BREAKER_WINDOW_MINUTES', 10),
        'min_calls'            => (int) env('CIRCUIT_BREAKER_MIN_CALLS', 5),
        'confidence_threshold' => (float) env('CIRCUIT_BREAKER_CONFIDENCE_THRESHOLD', 0.4),
        'low_confidence_ratio' => (float) env('CIRCUIT_BREAKER_LOW_CONFIDENCE_RATIO', 0.5),
        'block_ratio'          => (float) env('CIRCUIT_BREAKER_BLOCK_RATIO', 0.3),
    ],
];
