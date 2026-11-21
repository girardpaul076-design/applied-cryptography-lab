const crypto = require('crypto');

console.log('--- POST-QUANTUM KEY ENCAPSULATION (ML-KEM-768) ---\n');

// Check if current Node.js runtime includes NIST Post-Quantum ML-KEM
if (typeof crypto.encapsulate !== 'function') {
  console.log('Note: Upgrade to Node.js v24+ LTS to run native ML-KEM post-quantum encapsulation.');
  process.exit(0);
}

// 1. Bob generates a Post-Quantum ML-KEM-768 key pair
const bobKeys = crypto.generateKeyPairSync('ml-kem-768');

// 2. Alice encapsulates a brand-new shared secret using Bob's quantum-safe public key
const { ciphertext, sharedKey: aliceSharedKey } = crypto.encapsulate(bobKeys.publicKey);

// 3. Bob decapsulates the ciphertext using his quantum-safe private key
const bobSharedKey = crypto.decapsulate(bobKeys.privateKey, ciphertext);

console.log(`ML-KEM Ciphertext Size: ${ciphertext.length} bytes`);
console.log(`Alice Derived Secret:   ${aliceSharedKey.toString('hex')}`);
console.log(`Bob Derived Secret:     ${bobSharedKey.toString('hex')}`);
console.log(`Quantum-Safe Secrets Match: ${aliceSharedKey.equals(bobSharedKey)}`);
