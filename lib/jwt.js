// Verifikasi access token / token service (RS256). Hanya butuh KUNCI PUBLIK,
// sehingga service tidak mungkin menerbitkan token sendiri.
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cfg = require('./config');

let publicKey;
function getPublicKey() {
  if (!publicKey) publicKey = fs.readFileSync(cfg.keys.publicPath, 'utf8');
  return publicKey;
}

function verifyToken(token) {
  return jwt.verify(token, getPublicKey(), {
    algorithms: ['RS256'], // tolak 'none' dan algorithm-confusion (HS256)
    issuer: cfg.jwt.issuer,
    audience: cfg.jwt.audience,
  });
}

module.exports = { verifyToken };
