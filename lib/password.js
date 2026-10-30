// Hash password / secret memakai scrypt (bawaan Node, tanpa dependensi native tambahan).
const crypto = require('crypto');

function hash(plain) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(plain), salt, 64);
  return `scrypt$${salt.toString('hex')}$${dk.toString('hex')}`;
}

function verify(plain, stored) {
  try {
    const [alg, saltHex, hashHex] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const dk = crypto.scryptSync(String(plain), Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(dk, expected);
  } catch {
    return false;
  }
}

// Hash tiruan: dipakai agar waktu respons sama baik user ada maupun tidak (anti user-enumeration).
const DUMMY_HASH = hash('dummy-password-for-timing');

module.exports = { hash, verify, DUMMY_HASH };
