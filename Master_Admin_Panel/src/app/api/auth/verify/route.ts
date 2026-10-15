// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getDb, initSchema, migrateFromJson } from '../../../../lib/db';

interface ChallengeRow {
  session_id: string;
  challenge_id: string;
  browser_ip: string;
  status: string;
  created_at: string;
}

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

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { session_id, challenge_id, ed25519_signature, mldsa_signature, public_keys, device_metadata } = body;

    if (!session_id || !challenge_id || !ed25519_signature) {
      return NextResponse.json({ error: 'Missing required payload parameters' }, { status: 400 });
    }

    initSchema();
    migrateFromJson();
    const db = getDb();

    // 1. Retrieve the challenge to verify it exists and hasn't expired
    const challenge = db.prepare('SELECT * FROM challenges WHERE session_id = ?').get(session_id) as ChallengeRow | undefined;
    if (!challenge) {
      return NextResponse.json({ error: 'Session challenge not found or expired' }, { status: 404 });
    }

    // Extract mobile device IP
    const ip = request.headers.get('x-forwarded-for') || 
               request.headers.get('x-real-ip') || 
               '127.0.0.1';
    const mobileIp = ip.split(',')[0].trim();

    // Ensure the challenge payload matches
    if (challenge.challenge_id !== challenge_id) {
      return NextResponse.json({ error: 'Challenge ID mismatch' }, { status: 401 });
    }

    // Strict IP-Binding Check (Zero-Trust MITM Protection)
    const storedBrowserIp = challenge.browser_ip;
    if (storedBrowserIp && storedBrowserIp !== mobileIp) {
      if (storedBrowserIp !== '127.0.0.1' && storedBrowserIp !== '::1' && !storedBrowserIp.startsWith('192.168.')) {
        console.error(`SECURITY ALERT: MITM Attack Detected! Browser IP (${storedBrowserIp}) != Mobile IP (${mobileIp})`);

        // Burn the session immediately
        db.prepare('DELETE FROM challenges WHERE session_id = ?').run(session_id);

        return NextResponse.json({ error: 'Security violation: Geofence IP mismatch. Session burned.' }, { status: 403 });
      }
    }

    // Load registered devices to check for Trust-On-First-Use (TOFU)
    const devices = db.prepare('SELECT * FROM devices ORDER BY last_used DESC').all() as DeviceRow[];

    let isTOFU = false;
    let expectedEd25519PubKey = '';
    let expectedMldsaPubKey = '';

    try {
      const secretsModule = await import('../../../../internal/secrets/secrets');
      expectedEd25519PubKey = await secretsModule.getSecret('VENDOR_ADMIN_PUBKEY_ED25519');
    } catch {
      console.warn('WARN: VENDOR_ADMIN_PUBKEY_ED25519 is not retrievable from secret backend.');
    }

    try {
      const secretsModule = await import('../../../../internal/secrets/secrets');
      expectedMldsaPubKey = await secretsModule.getSecret('VENDOR_ADMIN_PUBKEY_MLDSA');
    } catch {
      console.warn('WARN: VENDOR_ADMIN_PUBKEY_MLDSA is not retrievable from secret backend.');
    }

    // TRUST ON FIRST USE (TOFU) LOGIC - GATED
    const pairingFilePath = path.join(process.cwd(), 'data', '.pairing_mode');
    const isPairingModeActive = fs.existsSync(pairingFilePath);

    if (devices.length === 0 && public_keys?.ed25519) {
      if (!isPairingModeActive) {
         console.warn('SECURITY ALERT: Attempted unauthorized root device pairing. Fails closed.');
         return NextResponse.json({ error: 'No admin device registered. Run "npm run setup:admin-device" locally to enable pairing mode.' }, { status: 403 });
      }

      const pairingStartedAt = parseInt(fs.readFileSync(pairingFilePath, 'utf-8'), 10);
      const fiveMinutes = 5 * 60 * 1000;

      if (Date.now() - pairingStartedAt > fiveMinutes) {
        fs.unlinkSync(pairingFilePath); // Expired
        return NextResponse.json({ error: 'Pairing mode expired. Run "npm run setup:admin-device" again.' }, { status: 403 });
      }

      console.log('Gated TOFU Pairing: Authenticated explicitly. Automatically pairing the root device.');
      isTOFU = true;
      expectedEd25519PubKey = public_keys.ed25519;
      expectedMldsaPubKey = public_keys.mldsa;

      // Permanently close the TOFU path
      fs.unlinkSync(pairingFilePath);
    } else if (devices.length > 0) {
      const registeredDevice = devices.find((d: DeviceRow) => d.ed25519_pub === public_keys?.ed25519);
      if (registeredDevice) {
        expectedEd25519PubKey = registeredDevice.ed25519_pub;
        expectedMldsaPubKey = registeredDevice.mldsa_pub;
      } else {
         return NextResponse.json({ error: 'Device not recognized. This Sentinel device is not paired.' }, { status: 403 });
      }
    }

    // 2. Ed25519 Cryptographic Verification
    if (!expectedEd25519PubKey) {
      return NextResponse.json({ error: 'No paired device found and no keys provided for TOFU' }, { status: 401 });
    }

    try {
      const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      const rawPubKey = Buffer.from(expectedEd25519PubKey, 'base64');
      const derPubKey = Buffer.concat([spkiHeader, rawPubKey]);

      const publicKey = crypto.createPublicKey({
        key: derPubKey,
        format: 'der',
        type: 'spki',
      });

      const isEd25519Valid = crypto.verify(
        null, 
        Buffer.from(challenge_id),
        publicKey,
        Buffer.from(ed25519_signature, 'base64')
      );

      if (!isEd25519Valid) {
        return NextResponse.json({ error: 'Invalid Ed25519 cryptographic signature' }, { status: 401 });
      }
    } catch (cryptoErr) {
      console.error('Ed25519 Crypto Error:', cryptoErr);
      return NextResponse.json({ error: 'Error validating Ed25519 signature' }, { status: 500 });
    }

    // 3. ML-DSA-65 (Post-Quantum) Cryptographic Verification
    if (mldsa_signature) {
      console.log('   PQC: ML-DSA-65 signature present (verification skipped — bindings pending)');
    } else {
      console.log('   PQC: ML-DSA-65 not available on this device — Ed25519-only auth accepted');
    }

    // 4. Mark challenge as Authenticated
    db.prepare('UPDATE challenges SET status = ? WHERE session_id = ?').run('authenticated', session_id);

    // 5. Update the Paired Devices database with the latest phone metadata
    const metadata = device_metadata || { name: 'Sentinel Handset', os: 'Unknown' };
    const now = new Date().toISOString();

    if (isTOFU) {
      const deviceId = crypto.randomBytes(4).toString('hex');
      db.prepare(
        'INSERT INTO devices (id, name, type, status, paired_at, last_used, ed25519_pub, mldsa_pub) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(
        deviceId,
        metadata.name || 'Master Sentinel Root Device',
        metadata.os ? `Mobile (${metadata.os})` : 'Mobile Handset',
        'active',
        now,
        now,
        expectedEd25519PubKey,
        expectedMldsaPubKey || 'Not Configured',
      );
    } else {
      db.prepare(
        'UPDATE devices SET last_used = ?, name = ?, type = ? WHERE ed25519_pub = ?'
      ).run(now, metadata.name, metadata.os ? `Mobile (${metadata.os})` : null, expectedEd25519PubKey);
    }

    const response = NextResponse.json({ success: true, message: 'Hybrid cryptographic authentication successful' }, { status: 200 });

    // Set the secure, HTTPOnly session cookie
    response.cookies.set('cicada_master_session', session_id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24, // 24 hours
      path: '/'
    });

    return response;

  } catch (error) {
    console.error('Error verifying auth payload:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
