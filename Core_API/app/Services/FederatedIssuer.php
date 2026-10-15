<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Services;

use App\Models\SystemConfig;
use Illuminate\Support\Facades\Cache;

/**
 * Generates and caches the internal Ed25519 Federation Keys.
 * Automatically distributes the public key natively formatted as JWKS for verifying servers.
 */
class FederatedIssuer
{
    public static function getKeys()
    {
         return Cache::remember('federated_issuer_ed25519_keys', 3600, function () {
             $config = SystemConfig::where('key', 'federated_issuer_ed25519')->first();
             
             if (!$config) {
                 // Natively generate secure Ed25519 (EdDSA) parameters over libsodium
                 $keypair = sodium_crypto_sign_keypair();
                 $privKey = sodium_crypto_sign_secretkey($keypair);
                 $pubKey = sodium_crypto_sign_publickey($keypair);
                 
                 $config = SystemConfig::create([
                     'key' => 'federated_issuer_ed25519',
                     'value' => [
                         'kid' => 'cicada-root-' . substr(md5(random_bytes(16)), 0, 8),
                         'private' => base64_encode($privKey),
                         'public' => base64_encode($pubKey),
                     ]
                 ]);
             }
             return $config->value;
         });
    }

    public static function getJwks()
    {
        $keys = self::getKeys();
        return [
            'keys' => [
                [
                    'kty' => 'OKP', // Octet key pair specifically required for Ed25519
                    'crv' => 'Ed25519',
                    'x' => self::base64url_encode(base64_decode($keys['public'])),
                    'kid' => $keys['kid'],
                    'use' => 'sig',
                ]
            ]
        ];
    }

    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
