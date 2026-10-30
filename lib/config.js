// Konfigurasi terpusat. Secret dibaca lewat getter agar hanya proses yang membutuhkannya
// yang wajib memilikinya, dan proses gagal-tertutup (fail closed) bila secret tidak diset.
const path = require('path');
const { loadEnv, ROOT } = require('./env');

loadEnv();

function required(name, minLen = 1) {
  const v = process.env[name];
  if (!v || v.length < minLen) {
    throw new Error(`Variabel lingkungan ${name} wajib diisi (min ${minLen} karakter). Lihat .env.example`);
  }
  return v;
}
const num = (name, def) => Number(process.env[name] || def);

const ports = {
  gateway: num('GATEWAY_PORT', 3000),
  nilai: num('NILAI_PORT', 3001),
  transkrip: num('TRANSKRIP_PORT', 3002),
};

module.exports = {
  ROOT,
  ports,
  host: process.env.BIND_HOST || '127.0.0.1',
  urls: {
    gateway: process.env.GATEWAY_URL || `http://localhost:${ports.gateway}`,
    nilai: process.env.NILAI_URL || `http://localhost:${ports.nilai}`,
    transkrip: process.env.TRANSKRIP_URL || `http://localhost:${ports.transkrip}`,
  },
  dbPath: path.resolve(ROOT, process.env.DB_PATH || 'data/sistem_nilai.db'),
  policyFile: path.resolve(ROOT, process.env.POLICY_FILE || 'config/policy.json'),
  keys: {
    privatePath: path.resolve(ROOT, 'keys/private.pem'), // hanya dipakai gateway (PE/PA)
    publicPath: path.resolve(ROOT, 'keys/public.pem'),   // dipakai gateway + kedua service
  },
  jwt: {
    issuer: 'zt-gateway',
    audience: 'sistem-nilai',
    accessTtlSec: 10 * 60,        // access token 10 menit
    serviceTtlSec: 5 * 60,        // token service 5 menit
    refreshTtlSec: 24 * 60 * 60,  // refresh token 1 hari
  },
  get gatewaySecret() { return required('GATEWAY_SECRET', 16); },
  get serviceClientId() { return process.env.SERVICE_CLIENT_ID || 'service-nilai'; },
  get serviceClientSecret() { return required('SERVICE_CLIENT_SECRET', 8); },
};
