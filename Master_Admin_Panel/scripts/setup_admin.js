const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const pairingFilePath = path.join(dataDir, '.pairing_mode');

try {
  // Write the current timestamp to indicate when pairing mode was activated
  fs.writeFileSync(pairingFilePath, Date.now().toString());
  console.log('\n======================================================');
  console.log('🔐 ADMIN DEVICE PAIRING MODE ENABLED');
  console.log('======================================================');
  console.log('You now have a 5-minute window to securely pair your Sentinel Device.');
  console.log('1. Open the Master Admin Panel in your browser.');
  console.log('2. Scan the QR code using the Sentinel Mobile App.');
  console.log('3. Your device\'s cryptographic identity will be permanently registered.');
  console.log('\nThis mode will automatically disable itself after a successful pairing.');
  console.log('======================================================\n');
} catch (err) {
  console.error('Failed to enable pairing mode:', err);
  process.exit(1);
}
