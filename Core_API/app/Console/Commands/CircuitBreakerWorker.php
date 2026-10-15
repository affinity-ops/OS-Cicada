<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Carbon\Carbon;

// CircuitBreakerWorker monitors the action_ledger for misbehaving agents and
// automatically revokes them before a human operator would notice.
//
// Why ratios, not raw counts: an agent processing 1000 calls/minute would trip
// a raw count threshold innocuously; an agent processing 5 calls would never
// trip it even with 100% failures. Ratios are volume-independent.
//
// Why 10-minute window: long enough to smooth transient network noise, short
// enough that a genuinely compromised agent is stopped before it can do
// significant damage. Configurable via CIRCUIT_BREAKER_WINDOW_MINUTES.
//
// Scheduling: runs every minute via the Laravel scheduler. Each run is fast
// (two aggregate SQL queries per agent). The scheduler is registered in
// app/Console/Kernel.php.
class CircuitBreakerWorker extends Command
{
    protected $signature   = 'cicada:circuit-breaker';
    protected $description = 'Auto-revoke agents whose recent behaviour exceeds anomaly thresholds';

    public function handle(): int
    {
        $cb = config('cicada.circuit_breaker');
        $windowMinutes  = $cb['window_minutes'];
        $minCalls       = $cb['min_calls'];
        $confThreshold  = $cb['confidence_threshold'];
        $lowConfRatio   = $cb['low_confidence_ratio'];
        $blockRatio     = $cb['block_ratio'];

        $since = Carbon::now()->subMinutes($windowMinutes);

        // Aggregate call statistics per agent over the rolling window.
        // Using a single query to avoid N+1 patterns on large ledgers.
        $stats = DB::select("
            SELECT
                agent_id,
                COUNT(*)                                                              AS total_calls,
                COUNT(*) FILTER (WHERE swarm_confidence_score < ?)                  AS low_conf_calls,
                COUNT(*) FILTER (WHERE status = 'blocked')                          AS blocked_calls
            FROM action_ledger
            WHERE created_at >= ?
              AND revoked_at IS NULL  -- Skip already-revoked agents
            GROUP BY agent_id
            HAVING COUNT(*) >= ?
        ", [$confThreshold, $since, $minCalls]);

        $tripped = 0;

        foreach ($stats as $row) {
            $lowConfRatioActual = $row->total_calls > 0
                ? $row->low_conf_calls / $row->total_calls
                : 0;

            $blockRatioActual = $row->total_calls > 0
                ? $row->blocked_calls / $row->total_calls
                : 0;

            $shouldTrip = $lowConfRatioActual >= $lowConfRatio
                       || $blockRatioActual   >= $blockRatio;

            if (!$shouldTrip) {
                continue;
            }

            // Atomic: revoke only if still active (WHERE revoked_at IS NULL),
            // then insert audit trail — all inside a single transaction.
            try {
                DB::transaction(function () use ($row, &$tripped, $lowConfRatioActual, $blockRatioActual, $windowMinutes) {
                    $affected = DB::table('agents')
                        ->where('id', $row->agent_id)
                        ->whereNull('revoked_at')
                        ->update(['revoked_at' => Carbon::now()]);

                    if ($affected === 0) {
                        return; // Already revoked by another process — skip
                    }

                    // Fetch tenant_id for the ledger entry now that we know the agent exists
                    $tenantId = DB::table('agents')->where('id', $row->agent_id)->value('tenant_id');

                    // Write a circuit_breaker_trip record to the ledger so Aegis-0
                    // and the Operator Dashboard can surface this event.
                    DB::table('action_ledger')->insert([
                        'trace_id'              => 'circuit-breaker-' . Str::uuid(),
                        'tenant_id'             => $tenantId,
                        'agent_id'              => $row->agent_id,
                        'action_type'           => 'circuit_breaker_trip',
                        'payload_hash'          => '',
                        'target_api'            => 'internal://circuit-breaker',
                        'status'                => 'blocked',
                        'swarm_confidence_score'=> null,
                        'created_at'            => Carbon::now(),
                    ]);

                    $this->warn(sprintf(
                        '[CIRCUIT BREAKER] Agent %s tripped — low_conf_ratio=%.2f block_ratio=%.2f over %d calls in last %d min',
                        $row->agent_id,
                        $lowConfRatioActual,
                        $blockRatioActual,
                        $row->total_calls,
                        $windowMinutes
                    ));

                    $tripped++;
                });
            } catch (\Throwable $e) {
                Log::error('[CIRCUIT BREAKER] Failed to trip agent', [
                    'agent_id'  => $row->agent_id,
                    'exception' => $e->getMessage(),
                ]);
                $this->error("[CIRCUIT BREAKER] Error tripping agent {$row->agent_id}: {$e->getMessage()}");
            }
        }

        if ($tripped === 0) {
            $this->info('[CIRCUIT BREAKER] All agents nominal');
        } else {
            $this->warn("[CIRCUIT BREAKER] Tripped {$tripped} agent(s)");
        }

        return Command::SUCCESS;
    }
}
