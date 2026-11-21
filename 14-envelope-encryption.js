const crypto = require('crypto');

console.log('--- ENVELOPE ENCRYPTION (DEK + KEK Hybrid Architecture) ---\n');

// 1. Generate a Master Key Encryption Key (KEK) pair (Simulates Cloud KMS / Hardware Security Module)
const kek = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// 2. Generate a one-time symmetric Data Encryption Key (DEK) for the file
const dek = crypto.randomBytes(32); // 256-bit AES key
const iv = crypto.randomBytes(12);
const largeFilePayload = Buffer.from('Sensitive database backup: 10,000 customer records...');

// 3. Encrypt the actual data with the fast symmetric DEK (AES-256-GCM)
const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
const encryptedData = Buffer.concat([cipher.update(largeFilePayload), cipher.final()]);
const authTag = cipher.getAuthTag();

// 4. "Wrap" (encrypt) the tiny 32-byte DEK using the asymmetric KEK Public Key
const wrappedDek = crypto.publicEncrypt(
  { key: kek.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  dek
);

// Destroy plaintext DEK from memory after wrapping!
dek.fill(0);

const envelopePackage = {
  wrappedDek: wrappedDek.toString('base64'),
  iv: iv.toString('hex'),
  authTag: authTag.toString('hex'),
  ciphertext: encryptedData.toString('hex')
};

console.log('1. Packaged Digital Envelope (Safe to store in cloud/S3):');
console.log(`   Wrapped DEK (RSA-OAEP): ${envelopePackage.wrappedDek.slice(0, 44)}...`);
console.log(`   Ciphertext (AES-GCM):   ${envelopePackage.ciphertext.slice(0, 44)}...\n`);

// --- DECRYPTION FLOW ---
console.log('2. Unwrapping & Decrypting Envelope:');
// Step A: Use KEK Private Key to unwrap the DEK
const unwrappedDek = crypto.privateDecrypt(
  { key: kek.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  Buffer.from(envelopePackage.wrappedDek, 'base64')
);

// Step B: Use the recovered DEK to decrypt the data
const decipher = crypto.createDecipheriv('aes-256-gcm', unwrappedDek, Buffer.from(envelopePackage.iv, 'hex'));
decipher.setAuthTag(Buffer.from(envelopePackage.authTag, 'hex'));
const recoveredPayload = Buffer.concat([
  decipher.update(Buffer.from(envelopePackage.ciphertext, 'hex')),
  decipher.final()
]);

console.log(`   Recovered Plaintext: "${recoveredPayload.toString()}"`);
