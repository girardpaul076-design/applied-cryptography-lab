const crypto = require('crypto');

// Shared secret between server and user's Authenticator App
const mfaSecret = crypto.randomBytes(20);

// RFC 6238 TOTP implementation (30-second time step, 6-digit code)
function generateTOTP(secret, timestampMs = Date.now()) {
  const timeStep = Math.floor(timestampMs / 1000 / 30);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigUInt64BE(BigInt(timeStep));

  const hmac = crypto.createHmac('sha1', secret).update(timeBuffer).digest();

  // Dynamic truncation (extract 4 bytes based on last 4 bits)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binaryCode % 1_000_000).toString().padStart(6, '0');
  return otp;
}

const now = Date.now();
const currentCode = generateTOTP(mfaSecret, now);
const nextWindowCode = generateTOTP(mfaSecret, now + 30_000); // 30 seconds later

console.log('--- TIME-BASED ONE-TIME PASSWORD (TOTP / 2FA) ---');
console.log(`Current 6-Digit 2FA Code:       ${currentCode}`);
console.log(`Code in Next 30-Sec Window:     ${nextWindowCode}`);
console.log(`User enters '${currentCode}':         ${currentCode === generateTOTP(mfaSecret, now) ? 'ACCESS GRANTED' : 'DENIED'}`);
console.log(`User enters '000000':           ${'000000' === generateTOTP(mfaSecret, now) ? 'ACCESS GRANTED' : 'DENIED'}`);
