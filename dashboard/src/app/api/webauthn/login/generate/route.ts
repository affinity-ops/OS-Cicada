// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { cookies } from 'next/headers';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

export async function GET() {
  // Pull the operator key representation securely from Laravel without holding DB credentials
  const coreRes = await fetch(`${CORE_API}/api/v1/internal/operator/webauthn`);
  if (!coreRes.ok) {
     return NextResponse.json({ error: 'Operator key not configured. Register first.' }, { status: 404 });
  }
  const { data: credential } = await coreRes.json();

  const allowCredentials = [{
     id: credential.credential_id,
     type: 'public-key' as const,
  }];

  const options = await generateAuthenticationOptions({
    rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
    allowCredentials,
    userVerification: 'discouraged',
  });

  const cookieStore = await cookies();
  cookieStore.set('webauthn_challenge', options.challenge, {
    httpOnly: true,
    maxAge: 60,
    path: '/',
  });

  return NextResponse.json(options);
}
