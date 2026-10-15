<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    /**
     * Strict allowlist of portal redirect URLs.
     * Only these origins will ever receive authentication tokens.
     */
    private function portalRedirectUrl(string $portal): string
    {
        $urls = [
            'developer' => env('FRONTEND_URL', 'http://localhost:3001'),
            'gateway'   => env('GATEWAY_PORTAL_URL', 'http://localhost:3002'),
            'operator'  => env('OPERATOR_DASHBOARD_URL', 'http://localhost:3000'),
        ];
        return $urls[$portal] ?? $urls['developer'];
    }

    /**
     * Redirect the user to the OAuth provider's login page.
     * Called by Developer Portal or Gateway Portal: GET /auth/{provider}?portal=developer|gateway
     */
    public function redirect(Request $request, string $provider)
    {
        $this->validateProvider($provider);

        // Persist which portal initiated the login so callback knows where to redirect.
        $portal = in_array($request->query('portal'), ['developer', 'gateway']) 
            ? $request->query('portal') 
            : 'developer';
        session(['cicada_portal' => $portal]);

        return Socialite::driver($provider)->stateless()->redirect();
    }

    /**
     * Handle the OAuth callback from the provider.
     *
     * Flow:
     *   1. Fetch verified identity from provider
     *   2. Find or create oauth_identity record
     *   3. Find or create contact + tenant records
     *   4. Issue Sanctum token
     *   5. Redirect to Developer Portal with token in URL fragment
     *      (never in query string — fragments don't hit server logs)
     */
    public function callback(string $provider)
    {
        $this->validateProvider($provider);

        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
        } catch (\Exception $e) {
            $portal = session('cicada_portal', 'developer');
            $frontendUrl = $this->portalRedirectUrl($portal);
            return redirect("{$frontendUrl}/login?error=oauth_failed");
        }

        $providerEmail    = $socialUser->getEmail();
        $providerName     = $socialUser->getName() ?? $socialUser->getNickname() ?? 'Unknown';
        $providerAvatar   = $socialUser->getAvatar();
        $providerUsername = $provider === 'github' ? $socialUser->getNickname() : null;
        $providerId       = (string) $socialUser->getId();

        DB::beginTransaction();

        try {
            // Find existing oauth_identity by immutable provider ID.
            $identity = DB::table('oauth_identities')
                ->where('provider', $provider)
                ->where('provider_id', $providerId)
                ->first();

            if ($identity) {
                // Returning user — update last used and any changed email/avatar.
                DB::table('oauth_identities')
                    ->where('id', $identity->id)
                    ->update([
                        'provider_email'      => $providerEmail,
                        'provider_avatar_url' => $providerAvatar,
                        'last_used_at'        => now(),
                    ]);

                $contact = DB::table('contacts')->where('id', $identity->contact_id)->first();

                DB::table('contacts')
                    ->where('id', $contact->id)
                    ->update([
                        'last_login_at' => now(),
                        'avatar_url'    => $providerAvatar,
                        'updated_at'    => now(),
                    ]);

            } else {
                // New identity — find existing contact by email or create from scratch.
                $contact = DB::table('contacts')->where('email', $providerEmail)->first();

                if (!$contact) {
                    // Brand new user — create tenant + contact together.
                    $tenantId  = (string) Str::uuid();
                    $contactId = (string) Str::uuid();

                    DB::table('tenants')->insert([
                        'id'           => $tenantId,
                        'name'         => $providerName . "'s Organisation",
                        'status'       => 'pending',
                        'plan'         => 'starter',
                        'created_at'   => now(),
                        'updated_at'   => now(),
                    ]);

                    DB::table('contacts')->insert([
                        'id'           => $contactId,
                        'tenant_id'    => $tenantId,
                        'name'         => $providerName,
                        'email'        => $providerEmail,
                        'avatar_url'   => $providerAvatar,
                        'is_primary'   => true,
                        'last_login_at' => now(),
                        'created_at'   => now(),
                        'updated_at'   => now(),
                    ]);

                    $contact = DB::table('contacts')->where('id', $contactId)->first();

                } else {
                    DB::table('contacts')
                        ->where('id', $contact->id)
                        ->update([
                            'last_login_at' => now(),
                            'avatar_url'    => $providerAvatar,
                            'updated_at'    => now(),
                        ]);
                }

                // Link this OAuth identity to the contact.
                DB::table('oauth_identities')->insert([
                    'id'                  => (string) Str::uuid(),
                    'contact_id'          => $contact->id,
                    'provider'            => $provider,
                    'provider_id'         => $providerId,
                    'provider_email'      => $providerEmail,
                    'provider_username'   => $providerUsername,
                    'provider_avatar_url' => $providerAvatar,
                    'created_at'          => now(),
                    'last_used_at'        => now(),
                ]);
            }

            DB::commit();

            // Fetch full tenant for the token payload.
            $tenant = DB::table('tenants')->where('id', $contact->tenant_id)->first();

            // Mint a Sanctum personal access token scoped to this contact + tenant.
            // We use a lightweight in-memory token model since contacts aren't Laravel Users.
            $token = $this->mintSanctumToken($contact, $tenant, $provider);

            // Redirect to the correct portal — token in fragment so it never appears in server logs.
            $portal = session('cicada_portal', 'developer');
            $frontendUrl = $this->portalRedirectUrl($portal);
            return redirect("{$frontendUrl}/auth/callback#token={$token}&tenant={$tenant->id}&plan={$tenant->plan}");

        } catch (\Exception $e) {
            DB::rollBack();
            $portal = session('cicada_portal', 'developer');
            $frontendUrl = $this->portalRedirectUrl($portal);
            return redirect("{$frontendUrl}/login?error=registration_failed");
        }
    }

    /**
     * Return the authenticated contact's profile and tenant details.
     * Called by the Developer Portal on every page load to hydrate session state.
     */
    public function me(Request $request)
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['status' => 'error', 'message' => 'Unauthenticated.'], 401);
        }

        $pat = DB::table('personal_access_tokens')
            ->where('token', hash('sha256', $token))
            ->first();

        if (!$pat || ($pat->expires_at && now()->isAfter($pat->expires_at))) {
            return response()->json(['status' => 'error', 'message' => 'Token expired or invalid.'], 401);
        }

        // token name encodes contact_id|tenant_id
        [$contactId, $tenantId] = explode('|', $pat->name, 2);

        $contact = DB::table('contacts')->where('id', $contactId)->first();
        $tenant  = DB::table('tenants')->where('id', $tenantId)->first();

        if (!$contact || !$tenant) {
            return response()->json(['status' => 'error', 'message' => 'Session invalid.'], 401);
        }

        // Update last seen.
        DB::table('personal_access_tokens')->where('id', $pat->id)->update(['last_used_at' => now()]);

        return response()->json([
            'status' => 'success',
            'data'   => [
                'contact' => [
                    'id'         => $contact->id,
                    'name'       => $contact->name,
                    'email'      => $contact->email,
                    'avatar_url' => $contact->avatar_url,
                    'role'       => $contact->role,
                ],
                'tenant' => [
                    'id'      => $tenant->id,
                    'name'    => $tenant->name,
                    'plan'    => $tenant->plan,
                    'status'  => $tenant->status,
                ],
            ],
        ]);
    }

    /**
     * Revoke the current token (logout).
     */
    public function logout(Request $request)
    {
        $token = $request->bearerToken();
        if ($token) {
            DB::table('personal_access_tokens')
                ->where('token', hash('sha256', $token))
                ->delete();
        }

        return response()->json(['status' => 'success', 'message' => 'Logged out.']);
    }

    // ─── Private ─────────────────────────────────────────────────────────────

    private function validateProvider(string $provider): void
    {
        if (!in_array($provider, ['github', 'google'])) {
            abort(400, 'Unsupported OAuth provider.');
        }
    }

    private function mintSanctumToken(object $contact, object $tenant, string $provider): string
    {
        $tokenValue = Str::random(64);

        DB::table('personal_access_tokens')->insert([
            'tokenable_type' => 'contact',
            'tokenable_id'   => $contact->id,
            'name'           => "{$contact->id}|{$tenant->id}",
            'token'          => hash('sha256', $tokenValue),
            'abilities'      => json_encode(['portal:access']),
            'created_at'     => now(),
            'updated_at'     => now(),
            'expires_at'     => now()->addDays(7),
        ]);

        return $tokenValue;
    }

    /**
     * Development-only login bypass.
     *
     * Seeds a deterministic dev user (dev@cicada.local) and mints a real Sanctum
     * token, then redirects through the same /auth/callback flow as OAuth.
     * The portal has no idea this wasn't a real GitHub/Google login.
     *
     * Guarded by APP_ENV=local — will hard 403 in any other environment.
     */
    public function devLogin(Request $request)
    {
        if (config('app.env') !== 'local') {
            abort(403, 'Dev login is only available in local environments.');
        }

        $portal = in_array($request->query('portal'), ['developer', 'gateway', 'operator'])
            ? $request->query('portal')
            : 'developer';

        $devTenantId  = '00000000-0000-0000-0000-000000000001';
        $devContactId = '00000000-0000-0000-0000-000000000002';

        // Upsert tenant
        $tenant = DB::table('tenants')->where('id', $devTenantId)->first();
        if (!$tenant) {
            DB::table('tenants')->insert([
                'id'         => $devTenantId,
                'name'       => 'Cicada Dev Workspace',
                'status'     => 'active',
                'plan'       => 'enterprise',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        // Upsert contact
        $contact = DB::table('contacts')->where('id', $devContactId)->first();
        if (!$contact) {
            DB::table('contacts')->insert([
                'id'            => $devContactId,
                'tenant_id'     => $devTenantId,
                'name'          => 'Dev Operator',
                'email'         => 'dev@cicada.local',
                'is_primary'    => true,
                'last_login_at' => now(),
                'created_at'    => now(),
                'updated_at'    => now(),
            ]);
        } else {
            DB::table('contacts')->where('id', $devContactId)->update(['last_login_at' => now()]);
        }

        $contact = DB::table('contacts')->where('id', $devContactId)->first();
        $tenant  = DB::table('tenants')->where('id', $devTenantId)->first();

        $token = $this->mintSanctumToken($contact, $tenant, 'dev-bypass');

        $frontendUrl = $this->portalRedirectUrl($portal);
        return redirect("{$frontendUrl}/auth/callback#token={$token}&tenant={$tenant->id}&plan={$tenant->plan}");
    }
}
