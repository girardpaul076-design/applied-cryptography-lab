const crypto = require('crypto');

console.log('--- 1. WHY UNSALTED FAST HASHES FAIL ---');
// Two users with the same password get the EXACT same SHA-256 hash!
const user1Bad = crypto.createHash('sha256').update('Summer2026!').digest('hex');
const user2Bad = crypto.createHash('sha256').update('Summer2026!').digest('hex');
console.log(`User 1 (Unsalted SHA-256): ${user1Bad}`);
console.log(`User 2 (Unsalted SHA-256): ${user2Bad}`);
console.log(`Identical hashes expose duplicate passwords: ${user1Bad === user2Bad}\n`);

console.log('--- 2. SECURE PASSWORD HASHING (Unique Salt + Slow scrypt) ---');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex'); // Unique 16-byte random salt per user
  // scrypt is intentionally memory-hard and slow to defeat GPU cracking
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

function verifyPassword(password, storedRecord) {
  const [salt, originalKey] = storedRecord.split(':');
  const testKey = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(originalKey, 'hex'), testKey);
}

console.time('scrypt Hashing Time');
const user1Stored = hashPassword('Summer2026!');
console.timeEnd('scrypt Hashing Time');

const user2Stored = hashPassword('Summer2026!'); // Same password, different random salt!

console.log(`\nUser 1 Stored (salt:hash): ${user1Stored.slice(0, 55)}...`);
console.log(`User 2 Stored (salt:hash): ${user2Stored.slice(0, 55)}...`);
console.log(`Stored records are completely different: ${user1Stored !== user2Stored}\n`);

console.log('--- 3. LOGIN VERIFICATION ---');
console.log(`Login with 'WrongPass123': ${verifyPassword('WrongPass123', user1Stored)}`);
console.log(`Login with 'Summer2026!':  ${verifyPassword('Summer2026!', user1Stored)}`);
