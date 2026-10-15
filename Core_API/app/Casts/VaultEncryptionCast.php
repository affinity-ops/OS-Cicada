<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Encryption\Encrypter;
use App\Models\SystemConfig;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * Enterprise-grade polymorphic Encrypter specifically built for Tenant API Vault Keys.
 * Isolates encryption bounds so rotating the main Application Session Key does not
 * irreversibly corrupt or break all stored vendor integrations.
 */
class VaultEncryptionCast implements CastsAttributes
{
    protected function getConfigs() {
        return Cache::remember('vault_crypto_config', 300, function () {
            $record = SystemConfig::where('key', 'vault_dek_payload')->first();
            
            // Auto-heal / Initialization
            if (!$record) {
                Log::notice("Generating Primary Global DEK Framework for Vault Infrastructure.");
                $key = Encrypter::generateKey('AES-256-CBC');
                $record = SystemConfig::create([
                    'key' => 'vault_dek_payload',
                    'value' => [
                        'active' => base64_encode($key),
                        'previous' => [],
                        'rotated_at' => now()->toIso8601String()
                    ]
                ]);
            }
            return $record->value;
        });
    }

    public function get(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        if (empty($value)) return null;

        $configs = $this->getConfigs();
        
        // 1. Attempt natively parsing with the active primary key
        try {
            $encrypter = new Encrypter(base64_decode($configs['active']), 'AES-256-CBC');
            return $encrypter->decryptString($value);
        } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
            // 2. Cascade fallback to legacy keys array natively to prevent outage during rotation
            foreach ($configs['previous'] as $prevKeyB64) {
                try {
                    $fallback = new Encrypter(base64_decode($prevKeyB64), 'AES-256-CBC');
                    return $fallback->decryptString($value);
                } catch (\Illuminate\Contracts\Encryption\DecryptException $ex) {
                    continue;
                }
            }
            
            // 3. Ultimate Fallback: Legacy Global APP_KEY (Seamless backward-compatibility migration)
            try {
                $appKey = substr(config('app.key'), 7); // Strip 'base64:'
                $fallback = new Encrypter(base64_decode($appKey), config('app.cipher', 'AES-256-CBC'));
                return $fallback->decryptString($value);
            } catch (\Exception $legacyEx) {
                throw new \Exception("CRITICAL: Vault Data Decryption Failed. Key signature heavily corrupt or DEK permanently lost.");
            }
        }
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        if (empty($value)) return null;
        
        // Cryptographically lock string under the ACTIVE DEK parameter
        $configs = $this->getConfigs();
        $encrypter = new Encrypter(base64_decode($configs['active']), 'AES-256-CBC');
        return $encrypter->encryptString($value);
    }
}
