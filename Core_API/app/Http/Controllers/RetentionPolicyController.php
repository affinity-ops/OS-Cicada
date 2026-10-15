<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Services\AuditService;

/**
 * RetentionPolicyController — read/update data retention policies.
 *
 * GET   /api/v1/admin/retention-policies        — list all policies
 * PUT   /api/v1/admin/retention-policies         — bulk upsert all policies
 */
class RetentionPolicyController extends Controller
{
    /** Defaults seeded on first access if the table is empty. */
    private const DEFAULTS = [
        ['id' => 'action_ledger',  'label' => 'Action Ledger',      'description' => 'All agent call records, block/approve decisions, and swarm scores.',          'retention_days' => 365, 'auto_delete' => false, 'archive_before_delete' => true],
        ['id' => 'evidence_chain', 'label' => 'Evidence Chain',     'description' => 'Cryptographic proof chain stored in edge ledger. Required for legal hold.', 'retention_days' => 730, 'auto_delete' => false, 'archive_before_delete' => true],
        ['id' => 'session_tokens', 'label' => 'Session Token Logs', 'description' => 'JIT session token issuance and expiry records.',                              'retention_days' => 90,  'auto_delete' => true,  'archive_before_delete' => false],
        ['id' => 'swarm_results',  'label' => 'Verification Swarm', 'description' => 'Redis queue results and confidence scores from the verification swarm.',       'retention_days' => 180, 'auto_delete' => true,  'archive_before_delete' => false],
        ['id' => 'hitl_events',    'label' => 'HITL Approvals',     'description' => 'Human-in-the-loop approval and rejection records.',                           'retention_days' => 365, 'auto_delete' => false, 'archive_before_delete' => true],
    ];

    public function index(): \Illuminate\Http\JsonResponse
    {
        // Seed defaults if table is empty (first-run UX)
        if (DB::table('retention_policies')->count() === 0) {
            $now = now();
            foreach (self::DEFAULTS as $d) {
                DB::table('retention_policies')->insert(array_merge($d, [
                    'created_at' => $now,
                    'updated_at' => $now,
                ]));
            }
        }

        $policies = DB::table('retention_policies')
            ->orderBy('id')
            ->get();

        return response()->json(['status' => 'success', 'data' => $policies]);
    }

    public function bulkUpdate(Request $request): \Illuminate\Http\JsonResponse
    {
        $policies = $request->validate([
            'policies'                          => 'required|array',
            'policies.*.id'                     => 'required|string|max:100',
            'policies.*.retention_days'         => 'required|integer|min:1|max:3650',
            'policies.*.auto_delete'            => 'required|boolean',
            'policies.*.archive_before_delete'  => 'required|boolean',
        ]);

        $now = now();
        foreach ($policies['policies'] as $p) {
            DB::table('retention_policies')->updateOrInsert(
                ['id' => $p['id']],
                [
                    'retention_days'        => $p['retention_days'],
                    'auto_delete'           => $p['auto_delete'],
                    'archive_before_delete' => $p['archive_before_delete'],
                    'updated_at'            => $now,
                ]
            );
        }

        AuditService::log(
            $request,
            'data_retention_changed',
            'policy',
            'bulk_update',
            null,
            $policies,
            'Operator updated data retention policies'
        );

        return response()->json(['status' => 'success', 'message' => 'Retention policies updated.']);
    }
}
