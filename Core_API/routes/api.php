<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\VaultController;
use App\Http\Controllers\TenantController;
use App\Http\Controllers\BillingController;
use App\Http\Controllers\ProvisioningController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\CompanyController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PortalController;
use App\Http\Controllers\AgentPolicyController;
use App\Http\Controllers\SecurityPolicyController;
use App\Http\Controllers\BiographyController;
use App\Http\Controllers\AgentGovernanceController;
use App\Http\Controllers\ComplianceController;
use App\Http\Controllers\GatewayController;
use App\Http\Controllers\OperatorWebAuthnController;
use App\Http\Controllers\OAuthController;
use App\Http\Controllers\AlertRuleController;
use App\Http\Controllers\RetentionPolicyController;
// HitlController removed — pre-CIBA dead code. CIBA replaced the async
// HITL suspend/resume flow with a mandatory synchronous poll gate (29 Apr 2026).
use App\Http\Controllers\CibaController;
use App\Http\Controllers\CredentialVaultCheckController;
use App\Http\Controllers\ThreatAlertController;
use App\Http\Controllers\UniversalRevokeController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('/v1/ciba/device/register', [CibaController::class, 'registerDevice']);
Route::get('/v1/ciba/session/validate', [CibaController::class, 'validateSession'])
    ->middleware('auth:sanctum');

// Legacy mobile handshake removed. Pairing is now handled by the Go Gateway via /v1/mobile/pair/handshake

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 1: AUTH SESSION (token-validated, not OAuth redirects)
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1')->middleware('throttle:auth')->group(function () {
    Route::get('/auth/me', [AuthController::class, 'me']);
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    // ┌────────────────────────────────────────────────────────────────────────┐
    // │ TODO(security): REMOVE BEFORE PRODUCTION                              │
    // │ This is a development-only backdoor with hardcoded credentials.        │
    // │ It MUST be removed or replaced with proper authentication (e.g.       │
    // │ Laravel Sanctum, Passport, or the existing OAuth flow) before any     │
    // │ production deployment. See Finding 13 in the June 2026 audit.         │
    // └────────────────────────────────────────────────────────────────────────┘
    Route::post('/auth/login', function (\Illuminate\Http\Request $request) {
        // Guard: only allow in local/testing environments
        if (!in_array(config('app.env'), ['local', 'testing'])) {
            return response()->json(['error' => 'This endpoint is disabled in production.'], 403);
        }

        if ($request->email === 'admin@cicada.local' && $request->password === 'password') {
            $contact = \Illuminate\Support\Facades\DB::table('contacts')->first();
            $tenant = \Illuminate\Support\Facades\DB::table('tenants')->where('id', $contact->tenant_id)->first();
            
            $tokenValue = \Illuminate\Support\Str::random(64);
            \Illuminate\Support\Facades\DB::table('personal_access_tokens')->insert([
                'tokenable_type' => 'contact',
                'tokenable_id'   => $contact->id,
                'name'           => "{$contact->id}|{$tenant->id}",
                'token'          => hash('sha256', $tokenValue),
                'abilities'      => json_encode(['portal:access']),
                'created_at'     => now(),
                'updated_at'     => now(),
                'expires_at'     => now()->addDays(7),
            ]);
            return response()->json(['data' => ['token' => $tokenValue]]);
        }
        return response()->json(['error' => 'Unauthorized'], 401);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 2: PUBLIC (unauthenticated — open to the internet)
// Only EVAR verification, JWKS, company self-registration, and webhooks.
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1')->middleware('throttle:api')->group(function () {
    // Vault Verification API — anyone can verify an EVAR
    Route::get('/vault/verify/{evar}', [VaultController::class, 'verifyEvar']);

    // Tenant Identity & Key Management
    Route::post('/tenant/keys', [TenantController::class, 'bindKey']);

    // Company Self-Registration (Landing Page → Developer Portal onboarding)
    Route::post('/provision/company', [CompanyController::class, 'register'])->middleware('throttle:auth');
    Route::get('/provision/verify', [CompanyController::class, 'verify']);
    Route::post('/provision/resend-verification', [CompanyController::class, 'resendVerification'])->middleware('throttle:auth');

    // Billing & Stripe — signature-verified in the controller
    Route::post('/billing/webhook', [BillingController::class, 'handleStripeWebhook']);
});

// Federation Identity Keys (OAuth 2.1 M2M)
Route::post('/v1/oauth/token', [OAuthController::class, 'token'])->middleware('throttle:auth');
Route::get('/.well-known/jwks.json', [OAuthController::class, 'jwks']);

// Gateway heartbeat — unauthenticated, gateway-to-platform only.
// Identified by X-Gateway-ID header in the payload body.
Route::post('/v1/gateway/heartbeat', [GatewayController::class, 'heartbeat'])->middleware('throttle:api');

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 3: INTERNAL (Gateway-to-Platform only, not public-facing)
// These are called by the Sentry Gateway binary, not by browsers.
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1/internal')->middleware(['gateway.auth', 'throttle:api'])->group(function () {
    // /hitl/suspend removed — Gateway never called this endpoint.
    // CIBA createRequest + poll replaced this flow (see CibaController).

    // CIBA — Gateway creates authorization requests and polls for responses
    Route::post('/ciba/request', [CibaController::class, 'createRequest']);
    Route::get('/ciba/poll/{traceId}', [CibaController::class, 'poll']);

    // WebAuthn state bridging — Next.js Dashboard ↔ Laravel
    Route::get('/operator/webauthn', [OperatorWebAuthnController::class, 'getCredential']);
    Route::post('/operator/webauthn/register', [OperatorWebAuthnController::class, 'storeCredential']);
    Route::post('/operator/webauthn/update-counter', [OperatorWebAuthnController::class, 'updateCounter']);

    // S1.1 — Vault credential cross-reference.
    // Gateway sends SHA-256 hash of detected credential; this endpoint checks
    // whether it matches any of the tenant's encrypted BYOK keys.
    // If match → Gateway elevates exfiltration severity to CRITICAL.
    Route::post('/vault/check-hash', [CredentialVaultCheckController::class, 'checkHash']);

    // S1.2 — Unified threat alert receiver.
    // Gateway fires structured alerts here when high-severity threats (exfiltration,
    // injection, semantic mismatch, velocity) are detected.
    // Core API persists to operator_alerts table and dispatches via AlertDispatcherService.
    Route::post('/threat-alert', [ThreatAlertController::class, 'receive']);
});

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 4: OPERATOR (admin-only — protected by OperatorAuth middleware)
// Graceful: if OPERATOR_API_KEY env var is NOT set, allows all requests.
// Set the env var to activate enforcement without code changes.
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1')->middleware(['operator.auth', 'throttle:admin'])->group(function () {
    // Operator Dashboard — summary and agent management
    Route::get('/dashboard/summary', [DashboardController::class, 'summary']);
    Route::get('/agents', [DashboardController::class, 'agents']);

    // Agent Biographies
    Route::get('/agents/biographies', [BiographyController::class, 'list']);
    Route::get('/agents/{id}/biography', [BiographyController::class, 'biography']);
    Route::get('/agents/{id}/timeline', [BiographyController::class, 'timeline']);
    Route::get('/agents/{id}/governance-profile', [AgentGovernanceController::class, 'profile']);
    Route::post('/agents/{id}/quarantine', [BiographyController::class, 'quarantine']);

    // S1.5 — Universal Revoke: single-click agent revocation.
    // Combines quarantine + ledger + audit + HITL invalidation + alert + CAEP webhooks.
    Route::post('/admin/agents/{id}/universal-revoke', [UniversalRevokeController::class, 'revoke']);

    // Aegis-0 threat signals — aggregated anomaly counts across V01–V10 vectors
    Route::get('/admin/threat-signals', [DashboardController::class, 'threatSignals']);

    // Automated vendor procurement / compliance exports (SOC2, EU AI Act, GDPR)
    Route::get('/admin/compliance-report', [ComplianceController::class, 'report']);

    // Third-Party Model Risk Management (MLOps webhooks)
    Route::post('/webhooks/model-registry', [\App\Http\Controllers\ModelRiskWebhookController::class, 'handleCompromisedModel']);

    // Gateway Fleet — all registered Sentry Gateway installations
    Route::get('/admin/gateways', [GatewayController::class, 'index']);

    // HITL Approval Queue — pending and recent human-in-the-loop decisions
    Route::get('/admin/hitl/queue', [DashboardController::class, 'hitlQueue']);
    Route::post('/admin/hitl/{traceId}/approve', [DashboardController::class, 'hitlApprove']);
    Route::post('/admin/hitl/{traceId}/reject', [DashboardController::class, 'hitlReject']);

    // /hitl/{trace_id}/resolve removed — pre-CIBA dead code.
    // Operator decisions now flow through DashboardController::hitlApprove/hitlReject
    // (which updates action_ledger) and CibaController::adminRespond (which resolves
    // the CIBA hold and lets the Gateway's poll loop complete).

    // CIBA — Dashboard/companion app responds to authorization requests
    Route::get('/admin/ciba/pending', [CibaController::class, 'pending']);
    Route::post('/admin/ciba/{traceId}/respond', [CibaController::class, 'respond']);
    Route::post('/admin/ciba/{traceId}/admin-respond', [CibaController::class, 'adminRespond']);

    // Policy violation trends — daily counts over 30 days
    Route::get('/admin/violation-trends', [DashboardController::class, 'violationTrends']);

    // Alert Rules — operator-configured security notifications
    Route::get('/admin/alert-rules', [AlertRuleController::class, 'index']);
    Route::post('/admin/alert-rules', [AlertRuleController::class, 'store']);
    Route::patch('/admin/alert-rules/{id}', [AlertRuleController::class, 'toggle']);
    Route::delete('/admin/alert-rules/{id}', [AlertRuleController::class, 'destroy']);

    // Retention Policies — data lifecycle configuration
    Route::get('/admin/retention-policies', [RetentionPolicyController::class, 'index']);
    Route::put('/admin/retention-policies', [RetentionPolicyController::class, 'bulkUpdate']);

    // CRM — admin view of all tenants / companies
    Route::get('/crm/companies', [DashboardController::class, 'companies']);
    Route::get('/crm/companies/{id}', [DashboardController::class, 'company']);
    Route::patch('/crm/companies/{id}/notes', [DashboardController::class, 'updateTenantNotes']);

    // Operator Dashboard — real data endpoints
    Route::get('/logs', [DashboardController::class, 'logs']);
    Route::get('/logs/{traceId}', [DashboardController::class, 'logDetail']);
    Route::post('/logs/{traceId}/false-positive', [DashboardController::class, 'flagFalsePositive']);
    Route::get('/nodes', [DashboardController::class, 'nodes']);
    Route::get('/registry', [DashboardController::class, 'registry']);
    Route::post('/agents/shadow-mode', [DashboardController::class, 'toggleShadowMode']);
    Route::get('/sandbox/events', [DashboardController::class, 'sandboxEvents']);
    Route::get('/sagas', [DashboardController::class, 'sagas']);
    Route::get('/discovery', [DashboardController::class, 'discovery']);
    Route::get('/compute/metrics', [DashboardController::class, 'computeMetrics']);
    Route::get('/vault/keys', [DashboardController::class, 'vaultKeys']);
    Route::post('/vault/keys/{keyId}/rotate', [DashboardController::class, 'rotateVaultKey']);
    Route::get('/alerts', [DashboardController::class, 'alerts']);
    // Dismiss (resolve) an active threat alert from the Global Overview.
    // Transitions operator_alerts.status from 'open' → 'resolved' with audit trail.
    Route::post('/admin/alerts/{id}/dismiss', [DashboardController::class, 'dismissAlert']);
    Route::get('/admin/audit-logs', [DashboardController::class, 'auditLogs']);
    Route::get('/admin/gateway-metrics', [DashboardController::class, 'gatewayMetrics']);
    Route::get('/admin/retraining-dataset', [DashboardController::class, 'exportRetrainingDataset']);

    // Platform security policies
    Route::get('/security/policies', [SecurityPolicyController::class, 'index']);
    Route::get('/security/policies/{slug}', [SecurityPolicyController::class, 'show']);
    Route::post('/security/policies/{slug}/test', [SecurityPolicyController::class, 'test']);
    Route::post('/security/policies/{slug}/exceptions', [SecurityPolicyController::class, 'addException']);
    Route::delete('/security/policies/{slug}/exceptions/{agentId}', [SecurityPolicyController::class, 'removeException']);
    Route::patch('/security/policies/{slug}/config', [SecurityPolicyController::class, 'updateConfig']);
    Route::post('/aegis/directives', [DashboardController::class, 'saveAegisDirectives']);
    Route::get('/aegis/directives', [DashboardController::class, 'getAegisDirectives']);
    Route::get('/aegis/model', [DashboardController::class, 'getAegisModel']);
    Route::post('/aegis/model', [DashboardController::class, 'saveAegisModel']);
    Route::get('/aegis/alerts', [DashboardController::class, 'getAegisAlerts']);
    Route::get('/aegis/activity', [DashboardController::class, 'getAegisActivity']);
    Route::get('/aegis/models', [DashboardController::class, 'listAegisModels']);
    Route::post('/aegis/alerts/{id}/release', [DashboardController::class, 'releaseAegisAlert']);

    // Aegis Governance — Rules Engine
    Route::get('/aegis/rules', [DashboardController::class, 'getAegisRules']);
    Route::post('/aegis/rules', [DashboardController::class, 'createAegisRule']);
    Route::patch('/aegis/rules/{id}', [DashboardController::class, 'updateAegisRule']);
    Route::delete('/aegis/rules/{id}', [DashboardController::class, 'deleteAegisRule']);

    // Aegis Governance — Tool Registry
    Route::get('/aegis/tools', [DashboardController::class, 'getAegisTools']);
    Route::patch('/aegis/tools/{id}', [DashboardController::class, 'updateAegisTool']);

    // Aegis Governance — Trace Log
    Route::get('/aegis/traces', [DashboardController::class, 'getAegisTraces']);
    Route::get('/aegis/traces/{traceId}', [DashboardController::class, 'getAegisTraceDetail']);

    // Aegis Governance — System Prompt & Settings
    Route::get('/aegis/system-prompt', [DashboardController::class, 'getAegisSystemPrompt']);
    Route::get('/aegis/settings', [DashboardController::class, 'getAegisSettings']);
    Route::post('/aegis/settings', [DashboardController::class, 'saveAegisSettings']);
});

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 5: PORTAL (tenant-scoped — requires developer portal auth token)
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1/portal')->middleware(['portal.auth', 'throttle:api'])->group(function () {
    Route::get('/summary', [PortalController::class, 'summary']);
    Route::get('/agents', [PortalController::class, 'agents']);
    Route::get('/agents/{id}', [PortalController::class, 'agent']);

    // Agent Certification Lifecycle
    Route::post('/agents/{id}/certify', [PortalController::class, 'certifyAgent']);
    Route::post('/agents/{id}/suspend', [PortalController::class, 'suspendAgent']);
    Route::post('/agents/{id}/terminate', [PortalController::class, 'terminateAgent']);
    Route::post('/agents/{id}/recertify', [PortalController::class, 'recertifyAgent']);
    Route::get('/agents/{id}/certification-events', [PortalController::class, 'certificationEvents']);
    Route::get('/traffic/outbound', [PortalController::class, 'trafficOutbound']);
    Route::get('/traffic/inbound', [PortalController::class, 'trafficInbound']);
    Route::get('/transactions', [PortalController::class, 'transactions']);
    Route::get('/flow-data', [PortalController::class, 'flowData']);
    Route::get('/tenant/keys', [PortalController::class, 'keys']);
    Route::get('/company', [PortalController::class, 'company']);
    Route::put('/company', [PortalController::class, 'updateCompany']);
    Route::put('/billing/plan', [PortalController::class, 'updatePlan']);
    Route::post('/mobile/pair', [PortalController::class, 'generatePairingToken']);
    Route::get('/mobile/devices', [PortalController::class, 'devices']);

    // Marketplace and Templates (Gap 11)
    Route::get('/marketplace/templates', [\App\Http\Controllers\MarketplaceController::class, 'index']);
    Route::post('/marketplace/templates/{id}/import', [\App\Http\Controllers\MarketplaceController::class, 'import']);
    Route::post('/marketplace/publish', [\App\Http\Controllers\MarketplaceController::class, 'publish']);

    // Agent E2E Registration — requires email verification (Phase 6.6)
    Route::post('/provision/agent', [ProvisioningController::class, 'provisionAgent'])->middleware('verified.email');
    Route::post('/provision/agent-from-yaml', [\App\Http\Controllers\YamlProvisioningController::class, 'provisionFromYaml'])->middleware('verified.email');

    // FGA resource policies — developer manages per-agent URL/method allowlists
    Route::get('/agents/{agentId}/policies', [AgentPolicyController::class, 'index']);
    Route::post('/agents/{agentId}/policies', [AgentPolicyController::class, 'store']);
    Route::patch('/agents/{agentId}/policies/{policyId}', [AgentPolicyController::class, 'update']);
    Route::delete('/agents/{agentId}/policies/{policyId}', [AgentPolicyController::class, 'destroy']);

    // Cross-System Revocation Webhooks (H2.3) — developer manages outbound
    // CAEP-compatible revocation endpoints for their tenant's external IdPs/SIEMs.
    Route::get('/revocation-webhooks', [\App\Http\Controllers\RevocationWebhookController::class, 'index']);
    Route::post('/revocation-webhooks', [\App\Http\Controllers\RevocationWebhookController::class, 'store']);
    Route::delete('/revocation-webhooks/{id}', [\App\Http\Controllers\RevocationWebhookController::class, 'destroy']);
    Route::post('/revocation-webhooks/{id}/test', [\App\Http\Controllers\RevocationWebhookController::class, 'test']);
});

// ═══════════════════════════════════════════════════════════════════════════
// ZONE 6: ENTERPRISE IDENTITY (Phase H2.2 & H2.3)
// ═══════════════════════════════════════════════════════════════════════════
Route::prefix('v1/enterprise')->middleware('throttle:api')->group(function () {
    Route::post('/sso/saml/consume', [\App\Http\Controllers\EnterpriseSSOController::class, 'consumeSamlAssertion']);
    Route::post('/sso/caep/webhook', [\App\Http\Controllers\EnterpriseSSOController::class, 'handleCaepRevocation']);
});
