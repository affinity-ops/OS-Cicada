<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Bootstrap the first operator account.
 *
 * This command seeds a pending operator invitation so that the WebAuthn
 * registration endpoint only accepts enrolments from explicitly authorised
 * email addresses. Without this, anyone who can reach admin.cicada.io
 * could enrol a hardware key and gain operator access.
 *
 * Usage:
 *   php artisan operator:create --email=admin@cicada.io --name="Platform Admin"
 *
 * After running this command, navigate to https://admin.cicada.io/login and
 * enrol a hardware key using the email address specified. The operator_credentials
 * table will be updated with the credential public key on successful enrolment.
 */
class CreateOperator extends Command
{
    protected $signature = 'operator:create
        {--email= : Email address of the operator (required)}
        {--name=  : Display name of the operator (optional)}';

    protected $description = 'Seed an authorised operator invitation for WebAuthn enrolment';

    public function handle(): int
    {
        $email = $this->option('email');
        $name  = $this->option('name') ?: 'Operator';

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->error('A valid --email is required.');
            return self::FAILURE;
        }

        // Check for duplicate
        $exists = DB::table('operator_credentials')
            ->where('operator_email', $email)
            ->exists();

        if ($exists) {
            $this->warn("Operator [{$email}] already exists.");
            return self::SUCCESS;
        }

        DB::table('operator_credentials')->insert([
            'id'               => (string) Str::uuid(),
            'operator_email'   => $email,
            'operator_name'    => $name,
            'credential_id'    => null,       // Populated on WebAuthn enrolment
            'public_key'       => null,       // Populated on WebAuthn enrolment
            'sign_count'       => 0,
            'status'           => 'pending',  // Cannot log in until key is enrolled
            'created_at'       => now(),
            'updated_at'       => now(),
        ]);

        $this->info("✅ Operator [{$email}] created with status 'pending'.");
        $this->info("   → Navigate to the Dashboard and enrol a hardware key with this email.");
        $this->newLine();
        $this->warn('⚠️  Only operators seeded via this command can enrol hardware keys.');
        $this->warn('   If you lose access, re-run this command with a new email and re-enrol.');

        return self::SUCCESS;
    }
}
