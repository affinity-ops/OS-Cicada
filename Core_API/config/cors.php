<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * Cicada Core API — CORS Configuration
 *
 * Restricts Cross-Origin requests to only the three known portal origins.
 * Without this, any website could make authenticated API calls using
 * the victim's browser tokens (MED-01 hardening).
 */
return [

    'paths' => ['api/*', '/.well-known/*'],

    'allowed_methods' => ['*'],

    'allowed_origins' => [
        env('DASHBOARD_URL',       'http://localhost:3000'),
        env('FRONTEND_URL',        'http://localhost:3001'),
        env('GATEWAY_PORTAL_URL',  'http://localhost:3002'),
    ],

    'allowed_origins_patterns' => [],

    'allowed_headers' => [
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Operator-Key',
        'X-Requested-With',
        'X-Gateway-ID',
    ],

    'exposed_headers' => [],

    'max_age' => 3600,

    'supports_credentials' => false,
];
