const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const API_BASE = 'http://localhost:3005/api/auth';
const DEVICES_PATH = path.join(__dirname, '..', 'data', 'devices.json');

async function runTests() {
  console.log('--- Master Admin Panel: Authentication API Tests ---');
  let devicesBackup = null;

  try {
    // 1. Setup Test Device
    if (fs.existsSync(DEVICES_PATH)) {
      devicesBackup = fs.readFileSync(DEVICES_PATH, 'utf-8');
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    
    // The crypto module exports the public key in SPKI format by default for ed25519
    // But we need the raw 32 bytes base64 encoded for devices.json to match Flutter!
    const spkiBuffer = publicKey.export({ type: 'spki', format: 'der' });
    // The last 32 bytes of the SPKI buffer are the raw key
    const rawPubKeyBuffer = spkiBuffer.slice(spkiBuffer.length - 32);
    const pubKeyBase64 = rawPubKeyBuffer.toString('base64');

    const testDevice = {
      id: 'test-device-uuid',
      name: 'CI/CD Test Runner',
      type: 'script',
      status: 'active',
      paired_at: new Date().toISOString(),
      last_used: new Date().toISOString(),
      keys: {
        ed25519: pubKeyBase64,
        mldsa: 'stub_mldsa_pub'
      }
    };

    let currentDevices = devicesBackup ? JSON.parse(devicesBackup) : [];
    currentDevices.unshift(testDevice);
    fs.writeFileSync(DEVICES_PATH, JSON.stringify(currentDevices, null, 2));

    // Test 1: Challenge Generation
    const cRes = await fetch(`${API_BASE}/challenge`, { method: 'POST' });
    const cData = await cRes.json();
    if (!cData.session_id || !cData.challenge_id) {
      throw new Error(`Test 334 Failed: Missing session or challenge ID. Data: ${JSON.stringify(cData)}`);
    }
    console.log('✅ PASS | test_auth_challenge_generation');

    // Test 2: Status Polling (Pending)
    const sRes = await fetch(`${API_BASE}/status?session_id=${cData.session_id}`);
    const sData = await sRes.json();
    if (sData.status !== 'pending') {
      throw new Error(`Test 335 Failed: Expected status 'pending', got '${sData.status}'`);
    }
    console.log('✅ PASS | test_auth_status_polling');

    // Test 3: Verify Dual Signature
    // Sign the challenge directly using Node.js crypto
    const signatureBuffer = crypto.sign(null, Buffer.from(cData.challenge_id), privateKey);
    const ed25519Signature = signatureBuffer.toString('base64');

    const vPayload = {
      session_id: cData.session_id,
      challenge_id: cData.challenge_id,
      ed25519_signature: ed25519Signature,
      mldsa_signature: 'stub_mldsa_sig',
      public_keys: {
        ed25519: pubKeyBase64,
        mldsa: 'stub_mldsa_pub'
      },
      device_metadata: {
        name: 'CI/CD Test Runner',
        os: 'linux'
      }
    };

    const vRes = await fetch(`${API_BASE}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '127.0.0.1' }, // Ensure IP matches because of strict IP binding
      body: JSON.stringify(vPayload)
    });

    const vData = await vRes.json();
    if (vRes.status !== 200 || !vData.success) {
      throw new Error(`Test 336 Failed: Verification rejected. Status: ${vRes.status}, Error: ${vData.error}`);
    }

    // Check Set-Cookie for cicada_master_session
    const cookies = vRes.headers.get('set-cookie');
    if (!cookies || !cookies.includes('cicada_master_session=')) {
      throw new Error(`Test 336 Failed: HTTPOnly session cookie not established`);
    }

    console.log('✅ PASS | test_auth_verify_dual_signature');
    console.log('\nAll Master Admin Panel security tests passed successfully!');

  } catch (error) {
    console.error(`\n❌ TEST FAILED: ${error.message}`);
    process.exit(1);
  } finally {
    // Restore original devices
    if (devicesBackup) {
      fs.writeFileSync(DEVICES_PATH, devicesBackup);
    } else if (fs.existsSync(DEVICES_PATH)) {
      fs.unlinkSync(DEVICES_PATH);
    }
  }
}

runTests();
