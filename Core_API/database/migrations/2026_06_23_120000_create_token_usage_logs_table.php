<?php
/**
 * V09 Token-IP Correlation Table.
 *
 * Lightweight log of (agent, source_ip) pairs written by the Sentry Gateway
 * on each authenticated request. Enables V09 threat signal detection:
 * agents whose tokens are used from multiple distinct IPs within a rolling
 * window, indicating credential theft or replay.
 *
 * The table is append-only with a created_at index for efficient windowed
 * queries and cleanup. Rows older than 90 days should be purged by the
 * archival worker alongside the action_ledger partitions.
 */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('token_usage_logs', function (Blueprint $table) {
            $table->id();
            $table->uuid('agent_id');
            $table->string('source_ip', 45);       // IPv4 or IPv6
            $table->string('token_fingerprint', 16); // First 16 chars of pub_key_hash
            $table->timestamp('created_at')->useCurrent();

            $table->index(['agent_id', 'created_at']);
            $table->index('created_at'); // For archival cleanup
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('token_usage_logs');
    }
};
