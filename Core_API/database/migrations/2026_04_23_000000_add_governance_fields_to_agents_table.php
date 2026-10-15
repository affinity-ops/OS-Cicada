<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('agents', function (Blueprint $table) {
            // Ownership & business context
            $table->string('owner_name')->nullable()->after('tenant_id');
            $table->string('owner_email')->nullable()->after('owner_name');
            $table->string('business_unit')->nullable()->after('owner_email');
            
            // Purpose & criticality (declared by creator)
            $table->text('declared_purpose')->nullable()->after('description');
            $table->string('criticality_level')->default('medium')->after('declared_purpose');
            $table->string('data_classification')->default('internal')->after('criticality_level');
            
            // Expected behaviour (for drift detection)
            $table->unsignedInteger('expected_velocity')->nullable()->comment('expected calls per hour')->after('data_classification');
            
            // Financial governance
            $table->decimal('monthly_budget_usd', 12, 2)->nullable()->after('expected_velocity');
            $table->string('cost_center')->nullable()->after('monthly_budget_usd');
            
            // Compliance labels (JSON array)
            $table->jsonb('regulatory_frameworks')->nullable()->after('cost_center');
            
            // Registration intent (legal evidence)
            $table->text('registration_purpose_statement')->nullable()->after('regulatory_frameworks');
            
            // Impact assessment (JSON)
            $table->jsonb('potential_impact')->nullable()->after('registration_purpose_statement');
            
            // Audit timestamps for governance
            $table->timestamp('governance_updated_at')->nullable()->after('updated_at');
            
            // Indexes for hyper-scale filtering
            $table->index('owner_email');
            $table->index('business_unit');
            $table->index('criticality_level');
            $table->index('data_classification');
        });
    }

    public function down()
    {
        Schema::table('agents', function (Blueprint $table) {
            $table->dropColumn([
                'owner_name', 'owner_email', 'business_unit',
                'declared_purpose', 'criticality_level', 'data_classification',
                'expected_velocity', 'monthly_budget_usd', 'cost_center',
                'regulatory_frameworks', 'registration_purpose_statement',
                'potential_impact', 'governance_updated_at'
            ]);
        });
    }
};
