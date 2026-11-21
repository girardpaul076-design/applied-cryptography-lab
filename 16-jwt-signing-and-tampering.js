const crypto = require('crypto');

const secretKey = crypto.randomBytes(32);

function base64UrlEncode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// 1. Create & Sign a JWT (Header.Payload.Signature)
function createJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('base64url');

  return `${dataToSign}.${signature}`;
}

// 2. Verify a JWT
function verifyJwt(token, secret) {
  const [encodedHeader, encodedPayload, receivedSig] = token.split('.');
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');

  if (receivedSig !== expectedSig) {
    return { valid: false, reason: 'Invalid signature! Token was tampered with.' };
  }
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
  return { valid: true, payload };
}

console.log('--- 1. ISSUING A LEGITIMATE JWT ---');
const token = createJwt({ sub: 'user_42', role: 'member', exp: 1893456000 }, secretKey);
console.log(`JWT: ${token}\n`);
console.log('Verification Result:', verifyJwt(token, secretKey));

console.log('\n--- 2. PRIVILEGE ESCALATION TAMPER ATTEMPT ---');
// Attacker decodes payload, changes role to "admin", and re-encodes without the secret key
const parts = token.split('.');
const hackedPayload = base64UrlEncode({ sub: 'user_42', role: 'admin', exp: 1893456000 });
const forgedToken = `${parts[0]}.${hackedPayload}.${parts[2]}`;

console.log('Tampered Token Verification:', verifyJwt(forgedToken, secretKey));
