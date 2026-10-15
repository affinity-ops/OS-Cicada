<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\SystemConfig;
use App\Models\TenantKey;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

class RotateVaultKeys extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:rotate {--force : Force rotation regardless of the 90 day limit}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Rotate the Data Encryption Keys (DEKs) for the Tenant Vaults securely.';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        // 1. Fetch current centralized DEK configs
        $configRecord = SystemConfig::where('key', 'vault_dek_payload')->first();
        if (!$configRecord) {
            $this->warn("No Vault DEK found in DB. Setting up the initial encryption framework...");
            $key = Encrypter::generateKey('AES-256-CBC');
            $configRecord = SystemConfig::create([
               'key' => 'vault_dek_payload',
               'value' => [
                   'active' => base64_encode($key),
                   'previous' => [],
                   'rotated_at' => now()->toIso8601String()
               ]
            ]);
            $this->info("Initialized pristine root Vault DEK.");
            return 0; // Freshly initialized, no vaults exist to rotate yet
        }

        $payload = is_string($configRecord->value) ? json_decode($configRecord->value, true) : $configRecord->value;

        // 2. Check 90 day rotation threshold compliance
        $rotatedAt = Carbon::parse($payload['rotated_at'] ?? now()->subDays(100));
        if (!$this->option('force') && $rotatedAt->diffInDays(now()) < 90) {
            $this->info("Vault Keys are fresh ({$rotatedAt->diffInDays(now())} days old). Skipping rotation.");
            return 0;
        }

        $this->warn("Initiating Enterprise Vault Data Encryption Key Rotation Ceremony...");
        Log::notice("Key Rotation Ceremony Triggered.");

        // 3. Formulate New AES-256 Key
        $newKey = base64_encode(Encrypter::generateKey('AES-256-CBC'));
        
        // 4. Architect Array Shift Pattern
        $oldKey = $payload['active'];
        $previous = $payload['previous'] ?? [];
        array_unshift($previous, $oldKey);

        // Discard any keys older than 10 generations to protect JSON limits
        if (count($previous) > 10) {
            array_pop($previous);
        }

        $payload['active'] = $newKey;
        $payload['previous'] = $previous;
        $payload['rotated_at'] = now()->toIso8601String();

        // 5. Update State & Annihilate Global Cache Array
        $configRecord->update(['value' => $payload]);
        Cache::forget('vault_crypto_config');
        
        $this->info("New DEK established. Decrypting & Re-encrypting Vault Payload In-Place...");

        // 6. Safe Batch Re-Encryption
        $count = 0;
        TenantKey::chunkById(500, function ($keys) use (&$count) {
            foreach ($keys as $tk) {
                // Read via legacy key -> VaultEncryptionCast automatically triggers GET loop
                $plaintext = $tk->payload_encrypted; 
                // Write via active key -> VaultEncryptionCast sets it securely using new DEK
                $tk->payload_encrypted = $plaintext; 
                // Strictly bypass updating 'updated_at' to prevent masking user modifications
                $tk->timestamps = false;
                $tk->save();
                $count++;
            }
        });

        $this->info("Ceremony execution complete. [$count] enterprise items gracefully rotated.");
        Log::notice("Key Rotation Ceremony Success.", ['rotated_items' => $count]);
        return 0;
    }
}
