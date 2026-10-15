<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Http\Controllers;

use OpenApi\Attributes as OA;

#[OA\Info(
    version: "1.0.0",
    description: "Secure API for the Cicada Agent Infrastructure.",
    title: "Cicada Core API",
    contact: new OA\Contact(email: "support@cicada.ai")
)]
#[OA\Server(
    url: "http://localhost:8000",
    description: "Local API Server"
)]
class SwaggerInfo
{
}
