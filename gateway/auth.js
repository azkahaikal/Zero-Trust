// Endpoint /auth/* ditangani langsung oleh gateway (Policy Engine / Policy Administrator):
// login, refresh, logout, dan token service.
const express = require('express');
const cfg = require('../lib/config');
const pwd = require('../lib/password');
const T = require('./tokens');

module.exports = function createAuthRouter(db, audit) {
  const router = express.Router();
  router.use(express.json({ limit: '10kb' })); // body hanya di-parse untuk /auth/*

  const meta = (req) => ({
    metode: req.method,
    endpoint: req.originalUrl,
    device: req.get('x-device-id') || null,
    ip: req.socket.remoteAddress,
  });

  // Mencatat audit + membalas dalam satu langkah
  function respond(req, res, { status, subjek = 'anonymous', role = null, alasan, body }) {
    audit({ ...meta(req), subjek, role, hasil: status < 400 ? 'allow' : 'deny', alasan, status });
    return res.status(status).json(body);
  }
  const fail = (req, res, status, alasan, publicMsg, who = {}) =>
    respond(req, res, { status, alasan, ...who, body: { error: publicMsg || alasan } });

  const issuePair = (user, device) => ({
    token_type: 'Bearer',
    access_token: T.issueAccessToken(user),
    expires_in: cfg.jwt.accessTtlSec,
    refresh_token: T.issueRefreshToken(db, user.id, device),
    refresh_expires_in: cfg.jwt.refreshTtlSec,
  });

  // ---- POST /auth/login : kredensial valid + device terdaftar ----
  router.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return fail(req, res, 400, 'username dan password wajib diisi (string)');
    }
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    const okPwd = pwd.verify(password, user ? user.password_hash : pwd.DUMMY_HASH);
    if (!user || !okPwd) {
      return fail(req, res, 401, user ? 'Password salah' : 'User tidak ditemukan', 'Kredensial tidak valid',
        { subjek: user ? `user:${user.id}` : `anonymous:${username.slice(0, 40)}` });
    }
    const who = { subjek: `user:${user.id}`, role: user.role };
    const device = req.get('x-device-id');
    if (!device) return fail(req, res, 403, 'Header X-Device-ID tidak ada', 'Header X-Device-ID wajib', who);
    const reg = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, device);
    if (!reg) return fail(req, res, 403, 'Device tidak terdaftar untuk user ini', 'Device tidak terdaftar', who);

    return respond(req, res, { status: 200, ...who, alasan: 'Login berhasil (kredensial valid, device terdaftar)', body: issuePair(user, device) });
  });

  // ---- POST /auth/refresh : refresh token valid & belum dicabut (dirotasi tiap pakai) ----
  router.post('/refresh', (req, res) => {
    const raw = (req.body || {}).refresh_token;
    if (typeof raw !== 'string') return fail(req, res, 400, 'refresh_token wajib diisi (string)');
    const row = T.findRefreshToken(db, raw);
    if (!row) return fail(req, res, 401, 'Refresh token tidak dikenal', 'Refresh token tidak valid');
    const who = { subjek: `user:${row.user_id}` };
    if (row.revoked === 2) {
      // Token lama dipakai ulang setelah dirotasi => indikasi pencurian. Asumsikan breach: cabut semua sesi user.
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(row.user_id);
      return fail(req, res, 401, 'Refresh token yang sudah dirotasi dipakai ulang; seluruh refresh token user dicabut', 'Refresh token tidak valid', who);
    }
    if (row.revoked) return fail(req, res, 401, 'Refresh token sudah dicabut', 'Refresh token tidak valid', who);
    if (row.expires_at <= T.nowSec()) return fail(req, res, 401, 'Refresh token kedaluwarsa', 'Refresh token tidak valid', who);

    const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(row.user_id);
    if (!user) return fail(req, res, 401, 'User tidak ditemukan', 'Refresh token tidak valid', who);
    db.prepare('UPDATE refresh_tokens SET revoked = 2 WHERE id = ?').run(row.id); // rotasi
    return respond(req, res, { status: 200, ...who, role: user.role, alasan: 'Refresh berhasil (token dirotasi)', body: issuePair(user, row.device_id) });
  });

  // ---- POST /auth/logout : mencabut refresh token ----
  router.post('/logout', (req, res) => {
    const raw = (req.body || {}).refresh_token;
    if (typeof raw !== 'string') return fail(req, res, 400, 'refresh_token wajib diisi (string)');
    const row = T.findRefreshToken(db, raw);
    if (!row || row.revoked || row.expires_at <= T.nowSec()) {
      return fail(req, res, 401, 'Refresh token tidak valid / sudah dicabut / kedaluwarsa', 'Refresh token tidak valid',
        row ? { subjek: `user:${row.user_id}` } : {});
    }
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(row.id);
    return respond(req, res, { status: 200, subjek: `user:${row.user_id}`, alasan: 'Logout: refresh token dicabut', body: { message: 'Logout berhasil, refresh token dicabut' } });
  });

  // ---- POST /auth/service : client ID + secret valid (khusus Service Nilai) ----
  router.post('/service', (req, res) => {
    const { client_id: clientId, client_secret: secret } = req.body || {};
    if (typeof clientId !== 'string' || typeof secret !== 'string') {
      return fail(req, res, 400, 'client_id dan client_secret wajib diisi (string)');
    }
    const row = db.prepare('SELECT * FROM service_clients WHERE client_id = ?').get(clientId);
    const ok = pwd.verify(secret, row ? row.secret_hash : pwd.DUMMY_HASH);
    if (!row || !ok) {
      return fail(req, res, 401, row ? 'Client secret salah' : 'Client ID tidak dikenal', 'Kredensial service tidak valid',
        { subjek: `service:${clientId.slice(0, 40)}` });
    }
    return respond(req, res, {
      status: 200, subjek: `service:${row.client_id}`, role: 'service', alasan: 'Token service diterbitkan',
      body: { token_type: 'Bearer', access_token: T.issueServiceToken(row.client_id), expires_in: cfg.jwt.serviceTtlSec },
    });
  });

  // ---- Fallback: path /auth/* lain & JSON rusak ----
  router.use((req, res) => fail(req, res, 404, `Endpoint ${req.method} ${req.originalUrl} tidak ada (default deny)`));
  // eslint-disable-next-line no-unused-vars
  router.use((err, req, res, next) =>
    fail(req, res, err.status === 413 ? 413 : 400, `Body request tidak valid: ${err.message}`, 'Body request tidak valid'));

  return router;
};
