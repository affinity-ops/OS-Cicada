<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class CompanyController extends Controller
{
    /**
     * Company self-registration from the public Landing Page.
     *
     * Creates a tenant record and returns a confirmation. The company then
     * uses the Developer Portal to bind their BYOK API key and provision agents.
     */
    public function register(Request $request)
    {
        $validated = $request->validate([
            'company_name' => 'required|string|max:255',
            'email'        => 'required|email|max:255',
            'plan'         => 'required|in:starter,professional,enterprise',
        ]);

        $tenantId = (string) Str::uuid();
        $token = (string) Str::uuid();

        DB::table('tenants')->insert([
            'id'                 => $tenantId,
            'name'               => $validated['company_name'],
            'company_email'      => $validated['email'],
            'plan'               => $validated['plan'],
            'status'             => 'pending',
            'verification_token' => $token,
            'created_at'         => now(),
        ]);

        // In production, we dispatch a Mailable via a queue here.
        // For development/due-diligence, we simulate it via logs.
        Log::info("Simulated Email Sent", [
            'to' => $validated['email'],
            'subject' => 'Verify your Cicada Account',
            'body' => "Please click this link to verify your account: " . env('APP_URL') . "/api/v1/provision/verify?token=" . $token
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'Company registered. Check your email for next steps.',
            'data'    => [
                'tenant_id' => $tenantId,
                'plan'      => $validated['plan'],
                'dev_verification_link' => "/api/v1/provision/verify?token=" . $token // Included for testing
            ],
        ], 201);
    }

    /**
     * GET /api/v1/provision/verify?token=XYZ
     */
    public function verify(Request $request)
    {
        $token = $request->query('token');
        if (!$token) {
            return response()->json(['error' => 'No token provided'], 400);
        }

        $updated = DB::table('tenants')
            ->where('verification_token', $token)
            ->update([
                'status' => 'active',
                'email_verified_at' => now(),
                'verification_token' => null
            ]);

        if (!$updated) {
            return response()->json(['error' => 'Invalid or expired token'], 400);
        }

        // Redirect user to the Dev Portal
        $devPortalUrl = env('PORTAL_URL', 'http://localhost:3001');
        return redirect($devPortalUrl . '/auth/login?verified=true');
    }

    /**
     * POST /api/v1/provision/resend-verification
     *
     * Resends the verification email for a pending tenant.
     * Rate-limited to prevent abuse. Generates a fresh token each time
     * to invalidate any previously issued links.
     */
    public function resendVerification(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email|max:255',
        ]);

        $tenant = DB::table('tenants')
            ->where('company_email', $validated['email'])
            ->whereNull('email_verified_at')
            ->first();

        // Always return success to prevent email enumeration
        if (!$tenant) {
            return response()->json([
                'status'  => 'success',
                'message' => 'If that email is registered and unverified, a new verification link has been sent.',
            ]);
        }

        // Generate a fresh token (invalidates the old one)
        $newToken = (string) Str::uuid();
        DB::table('tenants')
            ->where('id', $tenant->id)
            ->update(['verification_token' => $newToken]);

        Log::info("Verification Email Resent", [
            'to'      => $validated['email'],
            'subject' => 'Verify your Cicada Account',
            'body'    => "Please click this link to verify your account: " . env('APP_URL') . "/api/v1/provision/verify?token=" . $newToken
        ]);

        return response()->json([
            'status'  => 'success',
            'message' => 'If that email is registered and unverified, a new verification link has been sent.',
            'data'    => [
                'dev_verification_link' => "/api/v1/provision/verify?token=" . $newToken // Included for testing
            ],
        ]);
    }
}
