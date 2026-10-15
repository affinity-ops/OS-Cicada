// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { cookies } from 'next/headers';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export async function POST(request: Request) {
  const body = await request.json();
  const cookieStore = await cookies();
  const expectedChallenge = cookieStore.get('webauthn_challenge')?.value;

  if (!expectedChallenge) {
    return NextResponse.json({ error: 'Challenge expired' }, { status: 400 });
  }

  const coreRes = await fetch(`${CORE_API}/api/v1/internal/operator/webauthn`);
  if (!coreRes.ok) {
     return NextResponse.json({ error: 'Operator key not found' }, { status: 404 });
  }
  const { data: credential } = await coreRes.json();

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
      expectedRPID: process.env.WEBAUTHN_RP_ID || 'localhost',
      requireUserVerification: false,
      credential: {
        id: credential.credential_id,
        publicKey: Buffer.from(credential.public_key, 'base64'),
        counter: parseInt(credential.sign_count),
        transports: JSON.parse(credential.transports || '[]'),
      }
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  if (verification.verified) {
      // Re-bridge with Laravel to mutate the security counter (prevents replay attacks)
      await fetch(`${CORE_API}/api/v1/internal/operator/webauthn/update-counter`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
           credential_id: credential.credential_id,
           sign_count: verification.authenticationInfo.newCounter,
        })
      });

      // Grant structural operator session bypassing login gates
      const isProduction = !['localhost', '127.0.0.1'].some(h => (process.env.WEBAUTHN_ORIGIN || '').includes(h));
      const cookieWriter = await cookies();
      cookieWriter.set('operator_session', 'authenticated', {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'lax',
          maxAge: 86400, // 24 Hours
          path: '/',
      });

      return NextResponse.json({ verified: true });
  }

  return NextResponse.json({ verified: false }, { status: 400 });
}
