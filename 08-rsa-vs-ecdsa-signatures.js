const crypto = require('crypto');

const document = Buffer.from('Certificate Serial #202 | Subject: authorized-client-01');

console.log('--- 1. RSA-2048 vs. ECDSA (P-256) KEY GENERATION ---');

console.time('RSA-2048 KeyGen');
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
console.timeEnd('RSA-2048 KeyGen');

console.time('ECDSA P-256 KeyGen');
const ecdsa = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
console.timeEnd('ECDSA P-256 KeyGen');

// Export public keys to compare byte sizes
const rsaPubPem = rsa.publicKey.export({ type: 'spki', format: 'pem' });
const ecdsaPubPem = ecdsa.publicKey.export({ type: 'spki', format: 'pem' });

console.log(`\nRSA-2048 Public Key Length:   ${rsaPubPem.length} chars`);
console.log(`ECDSA P-256 Public Key Length: ${ecdsaPubPem.length} chars (Much smaller for mobile/IoT!)\n`);

console.log('--- 2. DIGITAL SIGNATURES & TAMPER DETECTION ---');

// Sign the document with ECDSA private key
const signature = crypto.sign('sha256', document, ecdsa.privateKey);
console.log(`ECDSA Signature (hex): ${signature.toString('hex').slice(0, 64)}... (${signature.length} bytes)`);

// Verify original document with ECDSA public key
const isAuthentic = crypto.verify('sha256', document, ecdsa.publicKey, signature);
console.log(`Original Document Verified: ${isAuthentic}`);

// Tamper with 1 character in the document
const tamperedDoc = Buffer.from('Certificate Serial #202 | Subject: authorized-client-02');
const isTamperedAuthentic = crypto.verify('sha256', tamperedDoc, ecdsa.publicKey, signature);
console.log(`Tampered Document Verified: ${isTamperedAuthentic} (Caught!)`);
