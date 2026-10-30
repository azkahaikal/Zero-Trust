// ============================================================================
// Policy Enforcement Point (PEP) - satu-satunya pintu masuk untuk selain /auth/*.
// Urutan: (1) verifikasi access token -> (2) verifikasi konteks (user ada, role sesuai,
// device terdaftar) -> (3) minta keputusan Policy Engine -> (4) audit log ->
// (5) jika allow, teruskan ke service dengan X-Gateway-Secret.
// ============================================================================
const cfg = require('../lib/config');
const { verifyToken } = require('../lib/jwt');

const USER_ROLES = new Set(['mahasiswa', 'dosen', 'admin']);

module.exports = function createPep({ db, policy, audit, proxies }) {
  const getUser = db.prepare('SELECT id, role FROM users WHERE id = ?');
  const getDevice = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?');

  return function pep(req, res, next) {
    const device = req.get('x-device-id') || null;
    const base = { metode: req.method, endpoint: req.originalUrl, device, ip: req.socket.remoteAddress };

    const reject = (status, alasan, who = {}, publicMsg) => {
      audit({ ...base, subjek: who.subjek || 'anonymous', role: who.role, hasil: 'deny', alasan, status });
      return res.status(status).json({ error: publicMsg || alasan });
    };

    // 1) Access token wajib dan harus valid (tanda tangan + masa berlaku)
    const m = (req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
    if (!m) return reject(401, 'Access token tidak ada');
    let claims;
    try {
      claims = verifyToken(m[1]);
    } catch (e) {
      return e.name === 'TokenExpiredError'
        ? reject(401, 'Access token kedaluwarsa')
        : reject(401, `Access token tidak valid (${e.message})`, {}, 'Access token tidak valid');
    }
    const who = { subjek: claims.role === 'service' ? `service:${claims.sub}` : `user:${claims.sub}`, role: claims.role };

    // 2) Verifikasi konteks
    if (claims.role === 'service') {
      // Panggilan antar-service memakai token service (tanpa device)
      if (claims.sub !== cfg.serviceClientId) return reject(403, 'Subjek token service tidak dikenal', who);
    } else {
      if (!USER_ROLES.has(claims.role)) return reject(403, 'Role pada token tidak dikenal', who);
      const user = getUser.get(Number(claims.sub));
      if (!user) return reject(401, 'User pada token tidak ada di database', who, 'Access token tidak valid');
      if (user.role !== claims.role) return reject(403, 'Role pada token tidak sesuai dengan database', who);
      if (!device) return reject(403, 'Header X-Device-ID tidak ada', who);
      if (!getDevice.get(user.id, device)) return reject(403, 'Device tidak terdaftar untuk user ini', who);
    }

    // 3) Keputusan Policy Engine
    const d = policy.decide({
      subject: { sub: claims.sub, role: claims.role },
      method: req.method,
      path: req.path,
      query: req.query,
      now: new Date(),
    });
    if (!d.allow) return reject(d.status || 403, d.reason, who);

    // 4) Audit allow + 5) teruskan ke service
    audit({ ...base, ...who, hasil: 'allow', alasan: d.reason, status: 200 });
    return proxies[d.upstream](req, res, next);
  };
};
