// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { getDb, initSchema, migrateFromJson } from '../../../../../lib/db';

export async function GET() {
  try {
    initSchema();
    migrateFromJson();
    const db = getDb();

    const rows = db.prepare('SELECT * FROM heartbeats ORDER BY last_seen DESC').all();

    return NextResponse.json(rows);
  } catch {
    return NextResponse.json({ error: 'Failed to read data' }, { status: 500 });
  }
}
