// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { getDb, initSchema, migrateFromJson } from '../../../../../lib/db';

export async function POST(request: Request) {
  try {
    initSchema();
    migrateFromJson();
    const db = getDb();

    const body = await request.json();
    const {
      gateway_id,
      version = '',
      uptime_seconds = 0,
      agents_registered = 0,
      postgres_healthy = true,
    } = body;

    if (!gateway_id) {
      return NextResponse.json({ error: 'Missing gateway_id' }, { status: 400 });
    }

    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO heartbeats (gateway_id, version, uptime_seconds, agents_registered, postgres_healthy, last_seen)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(gateway_id) DO UPDATE SET
        version = excluded.version,
        uptime_seconds = excluded.uptime_seconds,
        agents_registered = excluded.agents_registered,
        postgres_healthy = excluded.postgres_healthy,
        last_seen = excluded.last_seen
    `).run(gateway_id, version, uptime_seconds, agents_registered, postgres_healthy ? 1 : 0, now);

    return NextResponse.json({ success: true, received_at: now });
  } catch (error) {
    console.error('Failed to process heartbeat:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
