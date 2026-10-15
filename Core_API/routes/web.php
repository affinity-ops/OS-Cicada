<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/', fn() => response()->json(['service' => 'Cicada Core API', 'status' => 'online']));

// Dev-only login bypass — seeds a local user and mints a real token (APP_ENV=local only)
Route::get('/auth/dev-login', [AuthController::class, 'devLogin']);

// OAuth redirect + callback — must be web routes (browser redirects)
Route::get('/auth/{provider}', [AuthController::class, 'redirect']);
Route::get('/auth/{provider}/callback', [AuthController::class, 'callback']);
