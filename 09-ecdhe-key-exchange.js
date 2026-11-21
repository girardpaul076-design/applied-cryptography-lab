const crypto = require('crypto');

console.log('--- 1. ECDHE KEY EXCHANGE (How TLS 1.3 Derives Shared Secrets) ---');

// Alice (Client) and Bob (Server) each generate temporary (ephemeral) ECDH key pairs
const alice = crypto.createECDH('prime256v1');
const alicePublicKey = alice.generateKeys();

const bob = crypto.createECDH('prime256v1');
const bobPublicKey = bob.generateKeys();

console.log(`Alice sends Public Key over open network: ${alicePublicKey.toString('hex').slice(0, 32)}...`);
console.log(`Bob sends Public Key over open network:   ${bobPublicKey.toString('hex').slice(0, 32)}...\n`);

// Each side combines their OWN private key with the OTHER person's public key
const aliceSharedSecret = alice.computeSecret(bobPublicKey);
const bobSharedSecret = bob.computeSecret(alicePublicKey);

console.log(`Alice Derived Secret: ${aliceSharedSecret.toString('hex')}`);
console.log(`Bob Derived Secret:   ${bobSharedSecret.toString('hex')}`);
console.log(`Secrets Match Identically: ${aliceSharedSecret.equals(bobSharedSecret)}\n`);

console.log('--- 2. BRIDGING TO SYMMETRIC AES-256-GCM ---');
// Derive a clean 256-bit AES key from the shared secret using HKDF
const aesSessionKey = Buffer.from(
  crypto.hkdfSync('sha256', aliceSharedSecret, Buffer.alloc(0), 'tls13-session-key', 32)
);

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', aesSessionKey, iv);
const encrypted = Buffer.concat([cipher.update('Top secret data protected by ECDHE + AES-256-GCM!'), cipher.final()]);
const tag = cipher.getAuthTag();

// Bob decrypts using his identically derived key
const decipher = crypto.createDecipheriv('aes-256-gcm', aesSessionKey, iv);
decipher.setAuthTag(tag);
const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

console.log(`Encrypted with derived AES-256 key: ${encrypted.toString('hex').slice(0, 48)}...`);
console.log(`Decrypted by Bob: ${decrypted.toString()}`);
