<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;

class ProcessSwarmResultsWorker extends Command
{
    protected $signature = 'cicada:process-swarm-results';
    protected $description = 'Process results from the Verification Swarm background queue';

    public function handle(): int
    {
        $this->info('[SWARM_RESULTS] Listening for verification results...');

        // Graceful shutdown: register signal handlers so supervisord / Kubernetes
        // can stop this worker cleanly between iterations rather than mid-query.
        $shouldRun = true;
        pcntl_signal(SIGTERM, function () use (&$shouldRun) {
            $this->warn('[SWARM_RESULTS] Received SIGTERM — shutting down gracefully...');
            $shouldRun = false;
        });
        pcntl_signal(SIGINT, function () use (&$shouldRun) {
            $this->warn('[SWARM_RESULTS] Received SIGINT — shutting down gracefully...');
            $shouldRun = false;
        });

        while ($shouldRun) {
            pcntl_signal_dispatch();

            try {
                // brpop blocks until an item is available, timeout 5s so we can
                // re-check the $shouldRun flag and dispatch signals periodically.
                $result = Redis::brpop('cicada_swarm_results', 5);
                
                if (!$result) continue;

                $data = json_decode($result[1], true);
                if (!$data || !isset($data['agent_id'])) {
                    $this->error('[SWARM_RESULTS] Invalid payload received');
                    continue;
                }

                $agentId = $data['agent_id'];
                $score = (float) ($data['composite_confidence_score'] ?? 0.0);
                
                // score_to_trust_tier logic mapped to PHP
                $trustTier = 'unverified';
                if ($score >= 0.80) $trustTier = 'nominal';
                elseif ($score >= 0.60) $trustTier = 'provisional';
                elseif ($score >= 0.40) $trustTier = 'restricted';

                DB::table('agents')
                    ->where('id', $agentId)
                    ->update([
                        'trust_tier' => $data['trust_tier'] ?? $trustTier,
                        'swarm_confidence_score' => $score,
                        'swarm_verdict' => $data['verdict'] ?? 'BLOCK',
                        'swarm_reasons' => json_encode($data['reasons'] ?? []),
                        'verified_at' => now(),
                        'governance_updated_at' => now()
                    ]);

                $this->info("[SWARM_RESULTS] Processed agent {$agentId} (score: {$score})");

            } catch (\Exception $e) {
                $this->error("[SWARM_RESULTS] Error: {$e->getMessage()}");
                sleep(2); // Pause on error to avoid tight spin
            }
        }

        $this->info('[SWARM_RESULTS] Worker shut down cleanly.');
        return Command::SUCCESS;
    }
}
