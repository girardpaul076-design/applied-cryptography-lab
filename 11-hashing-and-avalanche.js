const crypto = require('crypto');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

console.log('--- 1. FIXED OUTPUT SIZE (Regardless of Input Length) ---');
const tinyInput = 'Hi';
const hugeInput = 'A'.repeat(1_000_000); // 1 MB string

console.log(`Tiny input (2 bytes):   ${sha256(tinyInput)} (${sha256(tinyInput).length} hex chars)`);
console.log(`Huge input (1,000,000): ${sha256(hugeInput)} (${sha256(hugeInput).length} hex chars)\n`);

console.log('--- 2. THE AVALANCHE EFFECT (1-Character Change) ---');
const original = 'Transfer $500.00 to Alice';
const tampered = 'Transfer $500.01 to Alice'; // Changed '0' to '1'

const hash1 = sha256(original);
const hash2 = sha256(tampered);

console.log(`Original: "${original}"\n  -> ${hash1}`);
console.log(`Tampered: "${tampered}"\n  -> ${hash2}`);

// Count how many hex characters changed out of 64
let diffs = 0;
for (let i = 0; i < hash1.length; i++) {
  if (hash1[i] !== hash2[i]) diffs++;
}
console.log(`\nCharacters changed: ${diffs} out of 64 (${Math.round((diffs / 64) * 100)}% completely scrambled!)`);
