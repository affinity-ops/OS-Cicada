// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { getDb, initSchema, migrateFromJson } from '../../../../lib/db';

interface DeviceRow {
  id: string;
  name: string;
  type: string;
  status: string;
  paired_at: string;
  last_used: string;
  ed25519_pub: string;
  mldsa_pub: string;
}

export async function GET() {
  try {
    initSchema();
    migrateFromJson();
    const db = getDb();

    const rows = db.prepare('SELECT * FROM devices ORDER BY last_used DESC').all() as DeviceRow[];

    const devices = rows.map((row) => ({
      id: row.id,
      name: row.name,
      type: row.type,
      status: row.status,
      paired_at: row.paired_at,
      last_used: row.last_used,
      keys: {
        ed25519: row.ed25519_pub,
        mldsa: row.mldsa_pub,
      }
    }));

    return NextResponse.json({ devices });
  } catch (error) {
    console.error('Failed to read devices:', error);
    return NextResponse.json({ devices: [] });
  }
}
