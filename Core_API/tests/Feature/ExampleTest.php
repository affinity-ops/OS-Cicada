<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace Tests\Feature;

// use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    /**
     * A basic test example.
     */
    public function test_the_application_returns_a_successful_response(): void
    {
        $response = $this->get('/');

        $response->assertStatus(200);
    }
}
