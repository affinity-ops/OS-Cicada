<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'portal.auth'    => \App\Http\Middleware\PortalAuth::class,
            'operator.auth'  => \App\Http\Middleware\OperatorAuth::class,
            'gateway.auth'   => \App\Http\Middleware\GatewayAuth::class,
            'verified.email' => \App\Http\Middleware\EnsureEmailVerified::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // All /api/* routes return structured JSON errors instead of HTML stack traces.
        // This is the single catch-all for unhandled exceptions, abort() calls, and
        // validation failures — prevents framework internals leaking to API clients.
        $exceptions->render(function (\Throwable $e, \Illuminate\Http\Request $request) {
            if (!$request->is('api/*') && !$request->wantsJson()) {
                return null; // let the default HTML handler render non-API errors
            }
            $status  = 500;
            $message = 'An unexpected error occurred.';
            if ($e instanceof \Symfony\Component\HttpKernel\Exception\HttpExceptionInterface) {
                $status = $e->getStatusCode();
                $raw    = $e->getMessage();
                $message = ($raw !== '' && $raw !== (string) $status)
                    ? $raw
                    : (\Symfony\Component\HttpFoundation\Response::$statusTexts[$status] ?? 'Error');
            }
            return response()->json(['error' => $message], $status);
        });
    })->create();
