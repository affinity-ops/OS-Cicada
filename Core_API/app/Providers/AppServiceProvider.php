<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Http\Request;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // ─── API Rate Limiters ───────────────────────────────────────────
        // Standard API: 120 req/min per IP
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(120)->by($request->ip());
        });

        // Auth endpoints (login, register): 10 req/min to prevent brute force
        RateLimiter::for('auth', function (Request $request) {
            return Limit::perMinute(10)->by($request->ip());
        });

        // Admin/operator endpoints: 3000 req/min.
        // The Operator Dashboard has multiple concurrent polling components
        // (Global Overview, TopAppBar CIBA/alerts, Activity Ledger) that all
        // share this rate limit. 600/min caused 429 errors during cold start
        // and multi-tab usage. 3000/min accommodates normal dashboard load
        // while still providing brute-force protection.
        RateLimiter::for('admin', function (Request $request) {
            return Limit::perMinute(3000)->by($request->ip());
        });
    }
}
