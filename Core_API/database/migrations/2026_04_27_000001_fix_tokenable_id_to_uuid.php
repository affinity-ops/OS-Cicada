<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

/**
 * Fix tokenable_id type mismatch.
 *
 * The personal_access_tokens table was created with a bigint tokenable_id
 * (Sanctum default), but contacts.id is uuid. This caused a type mismatch
 * that was temporarily patched with crc32(). This migration fixes the column
 * type to uuid and removes the need for the hack.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Drop any existing tokens — they were dev-only anyway.
        DB::table('personal_access_tokens')->truncate();

        // Alter the column from bigint to uuid.
        DB::statement('ALTER TABLE personal_access_tokens ALTER COLUMN tokenable_id TYPE uuid USING NULL');
    }

    public function down(): void
    {
        DB::table('personal_access_tokens')->truncate();
        DB::statement('ALTER TABLE personal_access_tokens ALTER COLUMN tokenable_id TYPE bigint USING NULL');
    }
};
