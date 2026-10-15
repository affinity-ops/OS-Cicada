// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { getDb, initSchema, migrateFromJson } from '../../../../lib/db';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const sessionId = searchParams.get('session_id');

  if (!sessionId) {
    return NextResponse.json({ error: 'Missing session_id' }, { status: 400 });
  }

  try {
    initSchema();
    migrateFromJson();
    const db = getDb();

    const row = db.prepare('SELECT status FROM challenges WHERE session_id = ?').get(sessionId) as { status: string } | undefined;

    if (!row) {
      return NextResponse.json({ error: 'Session not found or expired' }, { status: 404 });
    }

    return NextResponse.json({ status: row.status }, { status: 200 });
  } catch (error) {
    console.error('Error fetching auth status:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
