// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { getDb, initSchema } from '../../../../lib/db';

export async function POST(request: Request) {
  try {
    // Ensure schema exists
    initSchema();
    const db = getDb();

    // Capture the IP address of the browser requesting the QR code
    const ip = request.headers.get('x-forwarded-for') || 
               request.headers.get('x-real-ip') || 
               '127.0.0.1';
    const browserIp = ip.split(',')[0].trim();

    // Clean up expired challenges (older than 30 seconds to mitigate Session Fixation)
    const thirtySecsAgo = new Date(Date.now() - 30 * 1000).toISOString();
    db.prepare('DELETE FROM challenges WHERE created_at < ?').run(thirtySecsAgo);

    // Generate cryptographic session and challenge IDs
    const sessionId = crypto.randomBytes(32).toString('hex');
    const challengeId = crypto.randomBytes(64).toString('base64url');

    // Insert the new challenge atomically
    db.prepare(
      'INSERT INTO challenges (session_id, challenge_id, browser_ip, status, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(sessionId, challengeId, browserIp, 'pending', new Date().toISOString());

    return NextResponse.json({
      session_id: sessionId,
      challenge_id: challengeId,
      expires_in: 30
    }, { status: 201 });

  } catch (error) {
    console.error('Error generating auth challenge:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
