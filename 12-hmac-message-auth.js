const crypto = require('crypto');

const sharedSecret = crypto.randomBytes(32); // Secret API signing key
const webhookPayload = JSON.stringify({ event: 'payment.succeeded', amount: 99 });

function createHmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// Constant-time comparison prevents timing side-channel attacks!
function verifyHmac(secret, data, receivedTag) {
  const expectedTag = createHmac(secret, data);
  return crypto.timingSafeEqual(
    Buffer.from(expectedTag, 'hex'),
    Buffer.from(receivedTag, 'hex')
  );
}

console.log('--- 1. LEGITIMATE API WEBHOOK ---');
const validSignature = createHmac(sharedSecret, webhookPayload);
console.log(`Payload:   ${webhookPayload}`);
console.log(`HMAC Tag:  ${validSignature}`);
console.log(`Verified:  ${verifyHmac(sharedSecret, webhookPayload, validSignature)}\n`);

console.log('--- 2. ATTACKER TAMPERS WITH PAYLOAD & RE-HASHES ---');
const fakePayload = JSON.stringify({ event: 'payment.succeeded', amount: 9999 });
// Attacker tries forging an HMAC using a guessed key
const forgedSignature = createHmac(Buffer.from('guessed-wrong-key'), fakePayload);

console.log(`Fake Payload: ${fakePayload}`);
console.log(`Verified with Real Secret: ${verifyHmac(sharedSecret, fakePayload, forgedSignature)} (Rejected!)`);
