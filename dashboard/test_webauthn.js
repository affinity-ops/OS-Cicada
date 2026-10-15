// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const { generateRegistrationOptions } = require('@simplewebauthn/server');

async function test() {
  const options = await generateRegistrationOptions({
    rpName: 'Cicada Aegis Operator',
    rpID: 'localhost',
    userID: new Uint8Array(Buffer.from('root_operator_001')),
    userName: 'root@cicada.internal',
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'required'
    },
  });
  console.log("OPTIONS:", JSON.stringify(options));
}

test().catch(console.error);
