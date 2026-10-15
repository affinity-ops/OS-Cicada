<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;
use App\Console\Commands\CircuitBreakerWorker;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Circuit breaker: scans action_ledger every minute, auto-revokes agents whose
// swarm confidence or block ratios exceed thresholds. withoutOverlapping()
// ensures a slow DB scan doesn't queue up multiple concurrent runs.
// Configure via .env: CIRCUIT_BREAKER_LOW_CONFIDENCE_RATIO (default 0.5),
// CIRCUIT_BREAKER_BLOCK_RATIO (default 0.3), CIRCUIT_BREAKER_WINDOW_MINUTES (default 10).
Schedule::command(CircuitBreakerWorker::class)->everyMinute()->withoutOverlapping();

// Enforces enterprise 90-day Data Encryption Key mapping routines
Schedule::command('vault:rotate')->daily()->withoutOverlapping();

// Phase 7: Periodic Agent Re-verification via Swarm
Schedule::command('cicada:reverify-agents')->daily()->withoutOverlapping();

// Pre-CIBA hitl-sweep cron removed — swept hitl_suspensions table which the
// Gateway never populated. CIBA expiry is handled by CibaController::pending()
// which auto-expires holds past their TTL on every poll.
