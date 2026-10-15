// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { cookies } from 'next/headers';

export async function GET() {
  const rpName = process.env.WEBAUTHN_RP_NAME || 'Cicada Aegis Operator';
  const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: new Uint8Array(Buffer.from('root_operator_001')),
    userName: 'root@cicada.internal',
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'discouraged',
      residentKey: 'discouraged'
    },
  });

  // Persist challenge via encrypted native cookie to verify the signed response later
  const cookieStore = await cookies();
  cookieStore.set('webauthn_challenge', options.challenge, {
    httpOnly: true,
    maxAge: 60, // Valid for 1 minute
    path: '/',
  });

  return NextResponse.json(options);
}
