<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

<x-mail::message>
# ⚠️ Agent Authorization Required

An AI agent operating under your tenant requires your approval to proceed with a high-risk action.

**Agent:** {{ $agentName }}
**Action:** {{ $actionSummary }}
**Target:** {{ $targetUrl }}
**Risk Score:** {{ number_format($riskScore * 100, 0) }}%
**Reason:** {{ $riskReason }}
**Expires:** {{ $expiresAt }}

<x-mail::panel>
This request will be **automatically denied** if not responded to before the expiry time. This is the Cicada fail-closed security model.
</x-mail::panel>

<x-mail::button :url="$dashboardUrl" color="primary">
Review & Respond in Dashboard
</x-mail::button>

**Trace ID:** `{{ $traceId }}`

If you did not expect this agent to perform this action, deny the request immediately and review the agent's configuration.

— Cicada Sentry Gateway
</x-mail::message>
