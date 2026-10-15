<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * CIBA Authorization Request Email
 *
 * Sent to the operator when the Sentry Gateway escalates a high-risk
 * agent action that requires human approval. The email contains the
 * action summary, risk score, and a direct link to approve or deny.
 */
class CibaAuthorizationAlert extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public string $agentName,
        public string $traceId,
        public string $actionSummary,
        public float  $riskScore,
        public string $riskReason,
        public string $expiresAt,
        public string $targetUrl,
        public string $dashboardUrl,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: "[CICADA] Authorization Required — {$this->agentName}",
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'emails.ciba-authorization',
        );
    }
}
