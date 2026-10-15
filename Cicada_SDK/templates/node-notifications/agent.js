// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Notification Dispatcher Agent — Node.js + @cicada/sdk
 *
 * Sends emails via SendGrid and messages via Slack. All HTTP calls route
 * through the Cicada Sentry Gateway for enforcement and audit logging.
 *
 * Setup:
 *   1. npm install @cicada/sdk dotenv
 *   2. Copy .env.template to .env and fill in credentials
 *   3. node agent.js
 *
 * Architecture:
 *   Agent → @cicada/sdk → Sentry Gateway (7 layers) → SendGrid/Slack
 *                               ↓
 *                     Action Ledger (audit trail)
 */

require('dotenv').config();
const { CicadaClient } = require('@cicada/sdk');

// ── Initialize Cicada client ────────────────────────────────────────────────
const client = CicadaClient.fromYaml('cicada.yaml');

async function main() {
  const health = await client.healthCheck();
  console.log(`🛡️  Cicada Gateway: ${health.status || 'unknown'}`);
  console.log('\n📬 Notification Dispatcher Agent (Cicada-governed)');
  console.log('='.repeat(50));

  // ── Example: Send an email via SendGrid ─────────────────────────────────
  async function sendEmail(to, subject, body) {
    console.log(`\n📧 Sending email to ${to}...`);

    const response = await client.proxyCall(
      'POST',
      'https://api.sendgrid.com/v3/mail/send',
      {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: 'notifications@acme.com', name: 'Acme Notifications' },
        subject,
        content: [{ type: 'text/html', value: body }],
      },
      {
        provenance: 'developer',
        headers: { 'Authorization': `Bearer ${process.env.SENDGRID_API_KEY}` },
      }
    );

    if (response.status === 403) {
      const text = await response.text();
      console.log(`   ❌ Blocked by Cicada: ${text.slice(0, 200)}`);
      return false;
    } else if (response.status === 429) {
      console.log('   ⚠️  Velocity limit hit — too many emails');
      return false;
    } else if (response.ok) {
      console.log('   ✅ Email sent successfully');
      return true;
    } else {
      console.log(`   ❌ Error: ${response.status}`);
      return false;
    }
  }

  // ── Example: Post a Slack message ───────────────────────────────────────
  async function postSlack(channel, text) {
    console.log(`\n💬 Posting to Slack #${channel}...`);

    const response = await client.proxyCall(
      'POST',
      'https://slack.com/api/chat.postMessage',
      { channel, text },
      {
        provenance: 'developer',
        headers: { 'Authorization': `Bearer ${process.env.SLACK_BOT_TOKEN}` },
      }
    );

    if (response.status === 403) {
      const text = await response.text();
      console.log(`   ❌ Blocked by Cicada: ${text.slice(0, 200)}`);
      return false;
    } else if (response.ok) {
      const data = await response.json();
      console.log(`   ✅ Message posted (ts: ${data.ts || 'N/A'})`);
      return true;
    } else {
      console.log(`   ❌ Error: ${response.status}`);
      return false;
    }
  }

  // ── Process notification queue ──────────────────────────────────────────
  const notifications = [
    {
      type: 'email',
      to: 'user@example.com',
      subject: 'Your invoice is ready',
      body: '<h1>Invoice #1234</h1><p>Your monthly invoice is ready for review.</p>',
    },
    {
      type: 'slack',
      channel: 'engineering',
      text: '🚀 Deployment v2.4.1 completed successfully. All health checks passing.',
    },
    {
      type: 'email',
      to: 'admin@example.com',
      subject: 'Security Alert: New agent registered',
      body: '<p>A new agent "data-processor-v3" was registered in your tenant at 14:32 UTC.</p>',
    },
  ];

  console.log(`\n📋 Processing ${notifications.length} notifications...\n`);

  for (const notif of notifications) {
    if (notif.type === 'email') {
      await sendEmail(notif.to, notif.subject, notif.body);
    } else if (notif.type === 'slack') {
      await postSlack(notif.channel, notif.text);
    }
  }

  console.log('\n✅ Notification batch complete');
}

main().catch(err => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
