// Middleware "verifikasi ulang" yang dipakai KEDUA service (zero trust: service tidak
// mempercayai jaringan, hanya mempercayai bukti yang dapat diverifikasi sendiri).
//   1) requireGatewaySecret : request harus datang lewat gateway (X-Gateway-Secret)
//   2) requireToken         : tanda tangan + masa berlaku token diperiksa ulang
//   3) requireRole          : pembatasan role di level service (defense in depth)
const crypto = require('crypto');
const cfg = require('./config');
const { verifyToken } = require('./jwt');

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb); // perbandingan waktu-konstan
}

function requireGatewaySecret(req, res, next) {
  const secret = req.get('x-gateway-secret');
  if (!secret || !safeEqual(secret, cfg.gatewaySecret)) {
    return res.status(403).json({ error: 'Akses langsung ke service ditolak: X-Gateway-Secret tidak valid atau tidak ada' });
  }
  next();
}

function requireToken(req, res, next) {
  const m = (req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Token tidak ada (service memverifikasi ulang token)' });
  try {
    req.auth = verifyToken(m[1]);
    next();
  } catch (e) {
    const msg = e.name === 'TokenExpiredError' ? 'Token kedaluwarsa' : 'Token tidak valid';
    return res.status(401).json({ error: `${msg} (diverifikasi ulang oleh service)` });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.auth.role)) {
    return res.status(403).json({ error: `Role "${req.auth.role}" tidak diizinkan di service ini untuk endpoint tersebut` });
  }
  next();
};

module.exports = { requireGatewaySecret, requireToken, requireRole };
