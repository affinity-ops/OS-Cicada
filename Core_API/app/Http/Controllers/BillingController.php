<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class BillingController extends Controller
{
    /**
     * Handle incoming Stripe Webhooks for subscription and telemetry reconciliation.
     * 
     * The Sentry Gateway processes raw traffic, but the Laravel Core API must 
     * reconcile that traffic against the tenant's actual subscription status.
     * If billing fails, the Laravel API immediately schedules a quarantine event.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function handleStripeWebhook(Request $request)
    {
        $payload = $request->getContent();
        $sigHeader = $request->header('Stripe-Signature');
        $endpointSecret = config('services.stripe.webhook_secret');

        // ── Signature Verification (CRIT-03 hardening) ───────────────────
        if ($endpointSecret) {
            // Production mode: verify Stripe-Signature using HMAC-SHA256.
            if (!$sigHeader) {
                Log::warning('Stripe webhook rejected: missing Stripe-Signature header', [
                    'ip' => $request->ip(),
                ]);
                return response()->json(['error' => 'Missing signature'], 403);
            }

            // Parse the timestamp and signature from the Stripe-Signature header
            $elements = explode(',', $sigHeader);
            $timestamp = null;
            $signature = null;
            foreach ($elements as $element) {
                [$prefix, $value] = explode('=', $element, 2);
                if ($prefix === 't')  $timestamp = $value;
                if ($prefix === 'v1') $signature = $value;
            }

            if (!$timestamp || !$signature) {
                return response()->json(['error' => 'Invalid signature format'], 403);
            }

            // Protect against replay attacks: reject payloads older than 5 minutes
            if (abs(time() - (int) $timestamp) > 300) {
                Log::warning('Stripe webhook rejected: timestamp too old', [
                    'timestamp' => $timestamp,
                    'ip'        => $request->ip(),
                ]);
                return response()->json(['error' => 'Webhook timestamp expired'], 403);
            }

            // Compute expected signature and compare in constant time
            $signedPayload = "{$timestamp}.{$payload}";
            $expectedSignature = hash_hmac('sha256', $signedPayload, $endpointSecret);

            if (!hash_equals($expectedSignature, $signature)) {
                Log::warning('Stripe webhook rejected: invalid signature', [
                    'ip' => $request->ip(),
                ]);
                return response()->json(['error' => 'Invalid signature'], 403);
            }
        } else {
            // Development mode: no webhook_secret configured — log warning
            Log::warning('Stripe webhook: WEBHOOK_SECRET not configured — accepting without signature verification. Set services.stripe.webhook_secret for production.');
        }

        $event = json_decode($payload, true);

        if (!$event || !isset($event['type'])) {
            return response()->json(['error' => 'Invalid payload'], 400);
        }

        // Audit Trail
        Log::info('Stripe Webhook Received', ['type' => $event['type']]);

        // Process the Event
        switch ($event['type']) {
            case 'invoice.payment_succeeded':
                $stripeCustomerId = $event['data']['object']['customer'] ?? null;
                if ($stripeCustomerId) {
                    $tenant = \DB::table('tenants')
                        ->where('stripe_customer_id', $stripeCustomerId)
                        ->first();

                    if ($tenant) {
                        \DB::table('tenants')
                            ->where('id', $tenant->id)
                            ->update([
                                'billing_status' => 'active',
                                'billing_status_updated_at' => now(),
                            ]);

                        Log::info('Tenant billing reactivated', [
                            'tenant_id' => $tenant->id,
                            'stripe_customer_id' => $stripeCustomerId,
                        ]);
                    } else {
                        Log::warning('Stripe webhook: no tenant found for customer', [
                            'stripe_customer_id' => $stripeCustomerId,
                        ]);
                    }
                }
                break;

            case 'invoice.payment_failed':
                $stripeCustomerId = $event['data']['object']['customer'] ?? null;
                if ($stripeCustomerId) {
                    $tenant = \DB::table('tenants')
                        ->where('stripe_customer_id', $stripeCustomerId)
                        ->first();

                    if ($tenant) {
                        // Mark tenant as delinquent
                        \DB::table('tenants')
                            ->where('id', $tenant->id)
                            ->update([
                                'billing_status' => 'delinquent',
                                'billing_status_updated_at' => now(),
                            ]);

                        // Schedule quarantine for all tenant agents via action_ledger
                        $agents = \DB::table('agents')
                            ->where('tenant_id', $tenant->id)
                            ->whereNull('revoked_at')
                            ->pluck('id');

                        foreach ($agents as $agentId) {
                            \DB::table('action_ledger')->insert([
                                'id' => \Illuminate\Support\Str::uuid()->toString(),
                                'agent_id' => $agentId,
                                'tenant_id' => $tenant->id,
                                'action_type' => 'billing_quarantine',
                                'target_api' => 'internal:billing',
                                'status' => 'blocked',
                                'policy_violations' => 'Payment failed — tenant is delinquent. Agent quarantined pending payment resolution.',
                                'created_at' => now(),
                            ]);
                        }

                        Log::error('Tenant billing delinquent — agents quarantined', [
                            'tenant_id' => $tenant->id,
                            'stripe_customer_id' => $stripeCustomerId,
                            'agents_quarantined' => count($agents),
                        ]);
                    }
                }
                break;

            default:
                // Unhandled events are safely ignored, returning 200 to satisfy Stripe's retry logic.
        }

        return response()->json(['status' => 'success']);
    }
}
