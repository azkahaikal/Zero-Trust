// Policy Administrator: menerbitkan access token, token service, dan refresh token.
// Hanya modul ini (di gateway) yang memegang KUNCI PRIVAT.
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('../lib/config');

let privateKey;
const getPrivateKey = () => (privateKey ??= fs.readFileSync(cfg.keys.privatePath, 'utf8'));

function sign(sub, role, ttlSec) {
  return jwt.sign({ role }, getPrivateKey(), {
    algorithm: 'RS256',
    subject: String(sub),
    issuer: cfg.jwt.issuer,
    audience: cfg.jwt.audience,
    expiresIn: ttlSec,
  });
}

// Access token user: JWT 10 menit, berisi sub + role
const issueAccessToken = (user) => sign(user.id, user.role, cfg.jwt.accessTtlSec);
// Token service: 5 menit, role "service"
const issueServiceToken = (clientId) => sign(clientId, 'service', cfg.jwt.serviceTtlSec);

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

// Refresh token: string acak; yang disimpan di DB hanya hash-nya, berlaku 1 hari, dapat dicabut.
function issueRefreshToken(db, userId, device) {
  const raw = crypto.randomBytes(48).toString('base64url');
  const now = nowSec();
  db.prepare(`INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at, revoked, created_at)
              VALUES (?, ?, ?, ?, 0, ?)`).run(userId, sha256(raw), device || null, now + cfg.jwt.refreshTtlSec, now);
  return raw;
}

const findRefreshToken = (db, raw) =>
  db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(sha256(String(raw)));

module.exports = { issueAccessToken, issueServiceToken, issueRefreshToken, findRefreshToken, nowSec };
