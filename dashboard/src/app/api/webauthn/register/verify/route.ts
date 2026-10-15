// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { cookies } from 'next/headers';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export async function POST(request: Request) {
  const body = await request.json();
  const cookieStore = await cookies();
  const expectedChallenge = cookieStore.get('webauthn_challenge')?.value;

  if (!expectedChallenge) {
    return NextResponse.json({ error: 'Challenge expired' }, { status: 400 });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
      expectedRPID: process.env.WEBAUTHN_RP_ID || 'localhost',
      requireUserVerification: false,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  if (verification.verified && verification.registrationInfo) {
    // Send to Laravel Core API for persistent storage 
    const coreRes = await fetch(`${CORE_API}/api/v1/internal/operator/webauthn/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_id: verification.registrationInfo.credential.id,
        public_key: Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64'),
        sign_count: verification.registrationInfo.credential.counter,
        transports: verification.registrationInfo.credential.transports || ['internal'],
      }),
    });

    if (!coreRes.ok) {
       return NextResponse.json({ error: 'Failed to persist operator credential in bridging ledger' }, { status: 500 });
    }

    return NextResponse.json({ verified: true });
  }

  return NextResponse.json({ verified: false }, { status: 400 });
}
