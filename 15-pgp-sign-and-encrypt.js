const crypto = require('crypto');

console.log('--- PGP-STYLE SIGN-THEN-ENCRYPT PIPELINE ---\n');

// Setup identities: Alice has an ECDSA signing keypair; Bob has an ECDH encryption keypair
const aliceSignKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const bobCrypt = crypto.createECDH('prime256v1');
const bobPubKey = bobCrypt.generateKeys();

const secretMessage = 'Authorize deployment of production release v2.4.0';

// === ALICE'S SIDE: 1. SIGN -> 2. ENCRYPT ===
// Step 1: Alice signs the plaintext with her Private Signing Key
const signature = crypto.sign('sha256', Buffer.from(secretMessage), aliceSignKeys.privateKey);
const signedBundle = JSON.stringify({
  sender: 'Alice',
  message: secretMessage,
  signature: signature.toString('hex')
});

// Step 2: Alice derives a shared AES key using Bob's Public Key and encrypts the signed bundle
const aliceEphemeral = crypto.createECDH('prime256v1');
const aliceEphPub = aliceEphemeral.generateKeys();
const sharedSecret = aliceEphemeral.computeSecret(bobPubKey);
const aesKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'pgp-hybrid', 32));

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
const ciphertext = Buffer.concat([cipher.update(signedBundle), cipher.final()]);
const authTag = cipher.getAuthTag();

console.log('1. Alice sent encrypted + signed package over the network.');
console.log(`   Ciphertext: ${ciphertext.toString('hex').slice(0, 48)}...\n`);

// === BOB'S SIDE: 1. DECRYPT -> 2. VERIFY SIGNATURE ===
// Step 1: Bob derives the exact same AES key using his Private Key + Alice's Ephemeral Public Key
const bobSharedSecret = bobCrypt.computeSecret(aliceEphPub);
const bobAesKey = Buffer.from(crypto.hkdfSync('sha256', bobSharedSecret, Buffer.alloc(0), 'pgp-hybrid', 32));

const decipher = crypto.createDecipheriv('aes-256-gcm', bobAesKey, iv);
decipher.setAuthTag(authTag);
const decryptedBundle = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString());

// Step 2: Bob verifies Alice's signature using Alice's Public Signing Key
const isSignatureValid = crypto.verify(
  'sha256',
  Buffer.from(decryptedBundle.message),
  aliceSignKeys.publicKey,
  Buffer.from(decryptedBundle.signature, 'hex')
);

console.log('2. Bob decrypted the package and checked Alice\'s signature:');
console.log(`   Sender:             ${decryptedBundle.sender}`);
console.log(`   Signature Authentic: ${isSignatureValid} (Non-repudiation confirmed!)`);
console.log(`   Decrypted Message:  "${decryptedBundle.message}"`);
