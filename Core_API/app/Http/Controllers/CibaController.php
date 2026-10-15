<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use App\Mail\CibaAuthorizationAlert;
use Carbon\Carbon;
use App\Models\Contact;
use App\Models\Device;
use App\Models\CibaAuthorizationRequest;

/**
 * CibaController handles OAuth 2.0 CIBA (Client Initiated Backchannel Authentication)
 * authorization requests for the Sentry Gateway's last-hop approval system.
 *
 * Flow:
 *   1. Gateway intercepts a high-risk action and POSTs to /api/internal/ciba/request
 *   2. This controller stores the request as "pending" with a TTL
 *   3. The dashboard (and eventually the Flutter companion app) shows pending requests
 *   4. The owner approves or denies via POST /api/internal/ciba/respond/{traceId}
 *   5. The Gateway polls GET /api/internal/ciba/poll/{traceId} until resolved or expired
 */
class CibaController extends Controller
{
    /**
     * Create a new CIBA authorization request.
     * Called by the Sentry Gateway when Tier 1 risk scoring triggers escalation.
     */
    public function createRequest(Request $request)
    {
        $validated = $request->validate([
            'trace_id'        => 'required|string|max:255',
            'agent_id'        => 'required|uuid',
            'tenant_id'       => 'required|string|max:255',
            'action_summary'  => 'required|string|max:1000',
            'target_url'      => 'nullable|string|max:2000',
            'payload_preview' => 'nullable|string|max:2000',
            'risk_score'      => 'required|numeric|min:0|max:1',
            'risk_reason'     => 'nullable|string|max:1000',
            'timeout_seconds' => 'nullable|integer|min:10|max:300',
        ]);

        $timeoutSeconds = $validated['timeout_seconds'] ?? 120;
        $id = (string) Str::uuid();
        $now = Carbon::now();

        // Fetch agent name for display in the notification
        $agentName = DB::table('agents')
            ->where('id', $validated['agent_id'])
            ->value('name') ?? 'Unknown Agent';

        DB::table('ciba_authorization_requests')->insert([
            'id'              => $id,
            'trace_id'        => $validated['trace_id'],
            'agent_id'        => $validated['agent_id'],
            'tenant_id'       => $validated['tenant_id'],
            'agent_name'      => $agentName,
            'action_summary'  => $validated['action_summary'],
            'target_url'      => $validated['target_url'] ?? null,
            'payload_preview' => $validated['payload_preview'] ?? null,
            'risk_score'      => $validated['risk_score'],
            'risk_reason'     => $validated['risk_reason'] ?? null,
            'status'          => 'pending',
            'expires_at'      => $now->copy()->addSeconds($timeoutSeconds),
            'created_at'      => $now,
            'updated_at'      => $now,
        ]);

        Log::info('CIBA authorization request created', [
            'id'       => $id,
            'trace_id' => $validated['trace_id'],
            'agent_id' => $validated['agent_id'],
            'timeout'  => $timeoutSeconds,
        ]);

        // ── Dispatch notification to operator ────────────────────────────────
        // Look up the tenant's notification preferences to decide HOW to alert them.
        $tenant = DB::table('tenants')
            ->where('id', $validated['tenant_id'])
            ->first(['ciba_notification_channel', 'ciba_notification_email', 'company_email']);

        $notificationChannel = $tenant->ciba_notification_channel ?? 'dashboard';
        $notificationEmail   = $tenant->ciba_notification_email ?? $tenant->company_email ?? null;

        // Dashboard URL for the operator to click through to
        $dashboardBaseUrl = env('CICADA_DASHBOARD_URL', 'http://localhost:3000');
        $dashboardUrl     = "{$dashboardBaseUrl}/governance/ciba?trace={$validated['trace_id']}";
        $expiresAt        = $now->copy()->addSeconds($timeoutSeconds)->toDateTimeString();

        if ($notificationChannel === 'email' && $notificationEmail) {
            try {
                Mail::to($notificationEmail)->send(new CibaAuthorizationAlert(
                    agentName:     $agentName,
                    traceId:       $validated['trace_id'],
                    actionSummary: $validated['action_summary'],
                    riskScore:     $validated['risk_score'],
                    riskReason:    $validated['risk_reason'] ?? 'No reason specified',
                    expiresAt:     $expiresAt,
                    targetUrl:     $validated['target_url'] ?? 'N/A',
                    dashboardUrl:  $dashboardUrl,
                ));

                Log::info('CIBA notification email sent', [
                    'trace_id' => $validated['trace_id'],
                    'to'       => $notificationEmail,
                ]);
            } catch (\Exception $e) {
                // Fail-open on notification — don't block the CIBA flow because email failed.
                // The request still exists in the DB and the dashboard can still show it.
                Log::error('CIBA notification email failed', [
                    'trace_id' => $validated['trace_id'],
                    'error'    => $e->getMessage(),
                ]);
            }
        } elseif ($notificationChannel === 'dashboard') {
            Log::info('CIBA notification via dashboard only — operator must check pending queue', [
                'trace_id'  => $validated['trace_id'],
                'tenant_id' => $validated['tenant_id'],
            ]);
        } else {
            Log::warning('CIBA notification channel configured but no email set', [
                'trace_id' => $validated['trace_id'],
                'channel'  => $notificationChannel,
            ]);
        }

        return response()->json([
            'id'         => $id,
            'trace_id'   => $validated['trace_id'],
            'status'     => 'pending',
            'expires_at' => $now->copy()->addSeconds($timeoutSeconds)->toIso8601String(),
        ], 201);
    }

    /**
     * Poll the status of a CIBA authorization request.
     * Called by the Sentry Gateway in a tight loop until resolved or timed out.
     */
    public function poll(string $traceId)
    {
        $record = DB::table('ciba_authorization_requests')
            ->where('trace_id', $traceId)
            ->first();

        if (!$record) {
            return response()->json(['error' => 'CIBA request not found'], 404);
        }

        // Auto-expire if past the deadline
        if ($record->status === 'pending' && Carbon::parse($record->expires_at)->isPast()) {
            DB::table('ciba_authorization_requests')
                ->where('trace_id', $traceId)
                ->update([
                    'status'     => 'expired',
                    'updated_at' => Carbon::now(),
                ]);

            Log::warning('CIBA request expired — fail closed', ['trace_id' => $traceId]);

            return response()->json([
                'trace_id' => $traceId,
                'status'   => 'expired',
                'approved' => false,
            ]);
        }

        return response()->json([
            'trace_id'     => $traceId,
            'status'       => $record->status,
            'approved'     => $record->status === 'approved',
            'responded_by' => $record->responded_by,
            'responded_at' => $record->responded_at,
        ]);
    }

    public function respond(Request $request, string $traceId)
    {
        $validated = $request->validate([
            'decision' => 'required|in:approve,deny',
            'device_signature' => 'required|string',
            'device_public_key' => 'required|string',
            'responded_at' => 'required|date',
        ]);

        $cibaRequest = CibaAuthorizationRequest::findOrFail($traceId);
        
        // Find device by public key and owner
        $device = Device::where('public_key', $validated['device_public_key'])
            ->where('owner_id', $cibaRequest->owner_id)
            ->first();

        if (!$device) {
            return response()->json(['error' => 'Unregistered device'], 403);
        }

        // Verify signature
        $message = "APPROVE:{$traceId}:{$cibaRequest->created_at->toIso8601String()}";
        $isValid = sodium_crypto_sign_verify_detached(
            base64_decode($validated['device_signature']),
            $message,
            base64_decode($device->public_key)
        );

        if (!$isValid) {
            return response()->json(['error' => 'Invalid signature'], 403);
        }

        $cibaRequest->update([
            'status' => $validated['decision'],
            'responded_at' => now(),
            'device_id' => $device->id,
            'responded_by' => $cibaRequest->owner_id,
        ]);

        return response()->json(['status' => 'success']);
    }

    public function registerDevice(Request $request)
    {
        $validated = $request->validate([
            'public_key' => 'required|string|max:512',
            'device_name' => 'required|string|max:100',
            'owner_id' => 'required|string|uuid',
            'device_signature' => 'required|string',
            'registered_at' => 'required|date',
        ]);

        $owner = Contact::findOrFail($validated['owner_id']);
        
        // Verify device signature
        $message = "REGISTER:{$validated['owner_id']}:{$validated['registered_at']}";
        $isValid = sodium_crypto_sign_verify_detached(
            base64_decode($validated['device_signature']),
            $message,
            base64_decode($validated['public_key'])
        );

        if (!$isValid) {
            return response()->json(['error' => 'Invalid device signature'], 403);
        }

        // SINGLE DEVICE: Revoke any existing device for this owner
        Device::where('owner_id', $owner->id)->delete();

        $device = Device::create([
            'owner_id' => $owner->id,
            'public_key' => $validated['public_key'],
            'device_name' => $validated['device_name'],
            'registered_at' => now(),
        ]);

        return response()->json([
            'device_id' => $device->id,
            'message' => 'Device registered. Previous devices revoked.',
        ], 201);
    }

    public function validateSession(Request $request)
    {
        return response()->json([
            'valid' => true,
            'owner_id' => $request->user()->id,
            'device_bound' => true,
        ]);
    }

    /**
     * List all pending CIBA authorization requests for the dashboard.
     * Returns only active (non-expired) pending requests.
     */
    public function pending()
    {
        // ── Auto-expire stale holds and log them to the immutable ledger ──
        $expired = DB::table('ciba_authorization_requests')
            ->where('status', 'pending')
            ->where('expires_at', '<', Carbon::now())
            ->get();

        foreach ($expired as $hold) {
            DB::table('ciba_authorization_requests')
                ->where('trace_id', $hold->trace_id)
                ->update([
                    'status'     => 'expired',
                    'updated_at' => Carbon::now(),
                ]);

            // Write to immutable action_ledger for traceability
            // action_ledger.trace_id is UUID; CIBA trace_id is varchar — generate a new UUID
            DB::table('action_ledger')->insert([
                'trace_id'          => (string) Str::uuid(),
                'tenant_id'         => $hold->tenant_id,
                'agent_id'          => $hold->agent_id,
                'action_type'       => 'hitl_timeout',
                'target_api'        => $hold->target_url ?? 'N/A',
                'status'            => 'blocked',
                'policy_violations' => json_encode("CIBA hold expired without operator response (ref: {$hold->trace_id})"),
                'created_at'        => Carbon::now(),
            ]);

            Log::warning('CIBA hold expired — logged to ledger', [
                'trace_id' => $hold->trace_id,
            ]);
        }

        // Return ONLY pending (unresolved) holds
        $pending = DB::table('ciba_authorization_requests')
            ->where('status', 'pending')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'count' => $pending->count(),
            'data'  => $pending,
        ]);
    }

    /**
     * Admin override for CIBA decisions.
     * Resolves a pending hold, writes to the immutable action_ledger.
     * Resolved holds disappear from the CIBA queue permanently.
     */
    public function adminRespond(Request $request, string $traceId)
    {
        $validated = $request->validate([
            'decision' => 'required|in:approve,reject',
        ]);

        $cibaRequest = DB::table('ciba_authorization_requests')
            ->where('trace_id', $traceId)
            ->first();

        if (!$cibaRequest) {
            return response()->json(['error' => 'CIBA request not found'], 404);
        }

        if ($cibaRequest->status !== 'pending') {
            return response()->json([
                'error' => "Already resolved: {$cibaRequest->status}",
            ], 409);
        }

        $newStatus = $validated['decision'] === 'approve' ? 'approved' : 'denied';

        // ── Update CIBA hold ──
        DB::table('ciba_authorization_requests')
            ->where('trace_id', $traceId)
            ->update([
                'status'       => $newStatus,
                'responded_by' => 'admin-dashboard',
                'responded_at' => Carbon::now(),
                'updated_at'   => Carbon::now(),
            ]);

        // ── Write to immutable action_ledger ──
        // action_ledger.trace_id is UUID; CIBA trace_id is varchar — generate a new UUID
        DB::table('action_ledger')->insert([
            'trace_id'          => (string) Str::uuid(),
            'tenant_id'         => $cibaRequest->tenant_id,
            'agent_id'          => $cibaRequest->agent_id,
            'action_type'       => $validated['decision'] === 'approve' ? 'hitl_approved' : 'hitl_rejected',
            'target_api'        => $cibaRequest->target_url ?? 'N/A',
            'status'            => $validated['decision'] === 'approve' ? 'approved' : 'blocked',
            'policy_violations' => json_encode("Admin dashboard override: {$newStatus} (ref: {$traceId})"),
            'created_at'        => Carbon::now(),
        ]);

        Log::info('CIBA resolved — logged to ledger', [
            'trace_id' => $traceId,
            'decision' => $newStatus,
        ]);

        return response()->json([
            'status'   => 'success',
            'trace_id' => $traceId,
            'decision' => $newStatus,
        ]);
    }
}
