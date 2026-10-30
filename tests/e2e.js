// Tes end-to-end: menyalakan sistem pada port/DB terpisah, lalu menguji tiap kebutuhan (bagian 4).
// Jalankan: npm test
const fs = require('fs');
const net = require('net');
const path = require('path');
const jwt = require('jsonwebtoken');

const ROOT = path.resolve(__dirname, '..');
const TEST_ENV = {
  GATEWAY_PORT: '4000', NILAI_PORT: '4001', TRANSKRIP_PORT: '4002',
  GATEWAY_URL: 'http://localhost:4000', NILAI_URL: 'http://localhost:4001', TRANSKRIP_URL: 'http://localhost:4002',
  DB_PATH: 'data/test.db', POLICY_FILE: 'config/policy.test.json',
  GATEWAY_SECRET: 'rahasia-gateway-untuk-tes-123', SERVICE_CLIENT_SECRET: 'rahasia-service-tes',
};
Object.assign(process.env, TEST_ENV);

const cfg = require('../lib/config');
const { setup } = require('../scripts/setup');
const { startAll } = require('../scripts/start-all');
const { openDb } = require('../lib/db');

const GW = cfg.urls.gateway;
const DEV = { admin: 'ADM-DEV-001', dosen1: 'DSN1-LAPTOP', dosen2: 'DSN2-LAPTOP', mhs1: 'MHS1-PHONE', mhs2: 'MHS2-PHONE', mhs3: 'MHS3-PHONE' };
const PASS = { admin: 'Admin#123', dosen1: 'Dosen1#123', dosen2: 'Dosen2#123', mhs1: 'Mhs1#123', mhs2: 'Mhs2#123', mhs3: 'Mhs3#123' };
const OPEN = { accessHours: { start: '00:00', end: '24:00', timezone: 'Asia/Jakarta' } };
const CLOSED = { accessHours: { start: '00:00', end: '00:00', timezone: 'Asia/Jakarta' } }; // selalu tutup

let passed = 0, failed = 0;
function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  \x1b[32m✔\x1b[0m ${name}`); }
  else { failed++; console.log(`  \x1b[31m✘ ${name}\x1b[0m ${extra}`); }
}
const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);
const setHours = (cfgObj) => fs.writeFileSync(cfg.policyFile, JSON.stringify(cfgObj));

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null;
  try { json = await r.json(); } catch { /* kosong */ }
  return { status: r.status, body: json };
}
const gw = (method, p, o) => call(method, GW + p, o);

async function login(u, device = DEV[u]) {
  return gw('POST', '/auth/login', { body: { username: u, password: PASS[u] }, device });
}
async function tokenOf(u) { return (await login(u)).body.access_token; }

function waitPort(port, tries = 50) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(); });
      s.once('error', () => { s.destroy(); n <= 0 ? reject(new Error(`port ${port} tidak aktif`)) : setTimeout(() => attempt(n - 1), 100); });
    };
    attempt(tries);
  });
}

async function main() {
  fs.writeFileSync(cfg.policyFile, JSON.stringify(OPEN));
  setup({ reset: true });
  const children = startAll({ ...process.env }, { quiet: true });
  try {
    await Promise.all([4000, 4001, 4002].map((p) => waitPort(p)));

    // ------------------------------------------------------------------
    section('4.1 Autentikasi & token');
    let r = await login('mhs1');
    check('login mhs1 (kredensial + device valid) -> 200', r.status === 200 && r.body.access_token && r.body.refresh_token);
    const dec = jwt.decode(r.body.access_token);
    check('access token berisi sub & role', dec.sub && dec.role === 'mahasiswa');
    check('access token berlaku 10 menit', dec.exp - dec.iat === 600);
    check('login password salah -> 401', (await gw('POST', '/auth/login', { body: { username: 'mhs1', password: 'x' }, device: DEV.mhs1 })).status === 401);
    check('login user tidak ada -> 401', (await gw('POST', '/auth/login', { body: { username: 'hantu', password: 'x' }, device: 'X' })).status === 401);

    const mhs1 = await tokenOf('mhs1');
    const dosen1 = await tokenOf('dosen1');
    const dosen2 = await tokenOf('dosen2');
    const admin = await tokenOf('admin');
    const mhs2 = await tokenOf('mhs2');

    check('tanpa token -> 401', (await gw('GET', '/nilai', { device: DEV.mhs1 })).status === 401);
    check('token sampah -> 401', (await gw('GET', '/nilai', { token: 'abc.def.ghi', device: DEV.mhs1 })).status === 401);
    const priv = fs.readFileSync(cfg.keys.privatePath, 'utf8');
    const expired = jwt.sign({ role: 'mahasiswa' }, priv, { algorithm: 'RS256', subject: dec.sub, issuer: cfg.jwt.issuer, audience: cfg.jwt.audience, expiresIn: -10 });
    r = await gw('GET', '/nilai', { token: expired, device: DEV.mhs1 });
    check('token kedaluwarsa -> 401', r.status === 401, JSON.stringify(r));
    const forged = jwt.sign({ role: 'admin' }, 'kunci-palsu', { algorithm: 'HS256', subject: '1', issuer: cfg.jwt.issuer, audience: cfg.jwt.audience });
    check('token dipalsukan (HS256) -> 401', (await gw('GET', '/transkrip/247006111087', { token: forged, device: DEV.admin })).status === 401);
    const noneTok = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' + Buffer.from(JSON.stringify({ sub: '1', role: 'admin', iss: cfg.jwt.issuer, aud: cfg.jwt.audience })).toString('base64url') + '.';
    check('token alg=none -> 401', (await gw('GET', '/transkrip/247006111087', { token: noneTok, device: DEV.admin })).status === 401);

    // refresh & logout
    const l1 = (await login('mhs3')).body;
    r = await gw('POST', '/auth/refresh', { body: { refresh_token: l1.refresh_token } });
    check('refresh -> 200 dan token baru', r.status === 200 && r.body.access_token && r.body.refresh_token !== l1.refresh_token);
    const l2 = r.body;
    r = await gw('POST', '/auth/refresh', { body: { refresh_token: l1.refresh_token } });
    check('refresh token lama dipakai ulang -> 401', r.status === 401);
    r = await gw('POST', '/auth/refresh', { body: { refresh_token: l2.refresh_token } });
    check('reuse terdeteksi -> seluruh refresh token user dicabut', r.status === 401);
    const l3 = (await login('mhs3')).body;
    check('logout -> 200', (await gw('POST', '/auth/logout', { body: { refresh_token: l3.refresh_token } })).status === 200);
    check('refresh setelah logout -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: l3.refresh_token } })).status === 401);
    check('refresh token palsu -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: 'palsu' } })).status === 401);
    const dbc = openDb();
    const stored = dbc.prepare('SELECT token_hash FROM refresh_tokens LIMIT 1').get();
    check('refresh token disimpan sebagai hash (bukan plaintext)', stored.token_hash.length === 64 && stored.token_hash !== l3.refresh_token);

    // token service
    r = await gw('POST', '/auth/service', { body: { client_id: cfg.serviceClientId, client_secret: 'salah' } });
    check('/auth/service secret salah -> 401', r.status === 401);
    r = await gw('POST', '/auth/service', { body: { client_id: cfg.serviceClientId, client_secret: cfg.serviceClientSecret } });
    const svcDec = jwt.decode(r.body.access_token || '');
    check('/auth/service valid -> token role service 5 menit', r.status === 200 && svcDec.role === 'service' && svcDec.exp - svcDec.iat === 300);
    const svc = r.body.access_token;

    // gateway secret + verifikasi ulang di service
    section('4.1 Gateway secret & verifikasi ulang di service');
    const direct = `http://localhost:${cfg.ports.nilai}/nilai`;
    r = await call('GET', direct, { token: mhs1 });
    check('akses langsung ke service tanpa X-Gateway-Secret -> 403', r.status === 403);
    r = await call('GET', direct, { token: mhs1, headers: { 'X-Gateway-Secret': 'tebakan-salah' } });
    check('akses langsung dengan secret salah -> 403', r.status === 403);
    r = await call('GET', direct, { headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
    check('secret benar TANPA token -> 401', r.status === 401);
    r = await call('GET', direct, { token: expired, headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
    check('secret benar + token kedaluwarsa -> 401', r.status === 401);
    r = await call('GET', direct, { token: forged, headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
    check('secret benar + token palsu -> 401', r.status === 401);
    r = await call('GET', `http://localhost:${cfg.ports.transkrip}/transkrip/247006111087`, { token: mhs1 });
    check('Service Transkrip langsung tanpa secret -> 403', r.status === 403);
    r = await gw('GET', '/nilai', { token: mhs1, device: DEV.mhs1, headers: { 'X-Gateway-Secret': 'dipalsukan-klien' } });
    check('klien mengirim X-Gateway-Secret palsu via gateway -> tetap diproses benar (ditimpa gateway)', r.status === 200);

    // ------------------------------------------------------------------
    section('4.2 Kebijakan akses (Tabel 3)');
    r = await gw('GET', '/nilai', { token: mhs1, device: DEV.mhs1 });
    check('mahasiswa GET /nilai -> hanya nilai miliknya', r.status === 200 && r.body.data.length === 2 && r.body.data.every((x) => x.nim === '247006111087'), JSON.stringify(r.body));
    r = await gw('GET', '/nilai?nim=247006111099', { token: mhs1, device: DEV.mhs1 });
    check('mahasiswa minta nilai NIM lain -> 403', r.status === 403);
    r = await gw('GET', '/nilai?kelas_id=A&kelas_id=B', { token: dosen1, device: DEV.dosen1 });
    check('parameter ganda (HPP) -> 400', r.status === 400);
    r = await gw('GET', '/nilai?kelas_id=A', { token: dosen1, device: DEV.dosen1 });
    check('dosen1 GET /nilai kelas A (diampu) -> 200, 3 baris', r.status === 200 && r.body.data.length === 3);
    r = await gw('GET', '/nilai?kelas_id=B', { token: dosen1, device: DEV.dosen1 });
    check('dosen1 GET /nilai kelas B (bukan miliknya) -> 403', r.status === 403);
    r = await gw('GET', '/nilai', { token: dosen2, device: DEV.dosen2 });
    check('dosen2 GET /nilai tanpa filter -> hanya kelasnya', r.status === 200 && r.body.data.length === 3 && r.body.data.every((x) => x.kelas_id === 'B'));
    check('kelas_id angka tidak diterima (kelas wajib huruf) -> 400', (await gw('GET', '/nilai?kelas_id=1', { token: dosen1, device: DEV.dosen1 })).status === 400);
    check('kelas tidak ada (Z) -> 404', (await gw('GET', '/nilai?kelas_id=Z', { token: dosen1, device: DEV.dosen1 })).status === 404);
    check('finalisasi kelas berangka (/kelas/1) -> 403 default deny', (await gw('POST', '/kelas/1/finalisasi', { token: dosen1, device: DEV.dosen1 })).status === 403);
    check('admin GET /nilai -> 403 (role tidak diizinkan)', (await gw('GET', '/nilai', { token: admin, device: DEV.admin })).status === 403);
    check('mahasiswa PUT /nilai/1 -> 403', (await gw('PUT', '/nilai/1', { token: mhs1, device: DEV.mhs1, body: { nilai: 100 } })).status === 403);
    check('admin finalisasi -> 403', (await gw('POST', '/kelas/A/finalisasi', { token: admin, device: DEV.admin })).status === 403);
    check('endpoint tidak terdaftar -> 403 (default deny)', (await gw('GET', '/admin/secret', { token: admin, device: DEV.admin })).status === 403);
    check('metode tidak terdaftar -> 403 (default deny)', (await gw('DELETE', '/nilai/1', { token: dosen1, device: DEV.dosen1 })).status === 403);
    check('path berhuruf besar tidak lolos -> 403', (await gw('GET', '/NILAI', { token: mhs1, device: DEV.mhs1 })).status === 403);

    r = await gw('PUT', '/nilai/1', { token: dosen1, device: DEV.dosen1, body: { nilai: 90 } });
    check('dosen1 PUT /nilai/1 (kelas diampu, belum final) -> 200', r.status === 200, JSON.stringify(r.body));
    r = await gw('GET', '/nilai?kelas_id=A', { token: dosen1, device: DEV.dosen1 });
    check('nilai benar-benar berubah menjadi 90', r.body.data.find((x) => x.id === 1).nilai === 90);
    check('dosen2 PUT /nilai/1 (bukan kelasnya) -> 403', (await gw('PUT', '/nilai/1', { token: dosen2, device: DEV.dosen2, body: { nilai: 10 } })).status === 403);
    check('dosen1 PUT /nilai/4 (kelas dosen2) -> 403', (await gw('PUT', '/nilai/4', { token: dosen1, device: DEV.dosen1, body: { nilai: 10 } })).status === 403);
    check('PUT /nilai/999 -> 404', (await gw('PUT', '/nilai/999', { token: dosen1, device: DEV.dosen1, body: { nilai: 10 } })).status === 404);
    check('PUT nilai > 100 -> 400 (validasi service)', (await gw('PUT', '/nilai/1', { token: dosen1, device: DEV.dosen1, body: { nilai: 1000 } })).status === 400);

    // ------------------------------------------------------------------
    section('4.3 Verifikasi konteks');
    check('login dari device tak terdaftar -> 403', (await login('mhs1', 'DEVICE-ASING')).status === 403);
    check('login tanpa X-Device-ID -> 403', (await login('mhs1', null)).status === 403);
    check('request dengan device milik user lain -> 403', (await gw('GET', '/nilai', { token: mhs1, device: DEV.mhs2 })).status === 403);
    check('request tanpa X-Device-ID -> 403', (await gw('GET', '/nilai', { token: mhs1 })).status === 403);

    setHours(CLOSED);
    r = await gw('PUT', '/nilai/1', { token: dosen1, device: DEV.dosen1, body: { nilai: 91 } });
    check('PUT nilai di luar jam akses -> 403', r.status === 403 && /jam akses/i.test(r.body.error), JSON.stringify(r.body));
    r = await gw('POST', '/kelas/A/finalisasi', { token: dosen1, device: DEV.dosen1 });
    check('finalisasi di luar jam akses -> 403', r.status === 403 && /jam akses/i.test(r.body.error));
    check('GET /nilai tetap boleh di luar jam akses', (await gw('GET', '/nilai', { token: dosen1, device: DEV.dosen1 })).status === 200);
    setHours(OPEN);

    // ------------------------------------------------------------------
    section('Alur finalisasi -> sinkron transkrip via gateway');
    check('transkrip mhs1 masih kosong sebelum finalisasi', (await gw('GET', '/transkrip/247006111087', { token: mhs1, device: DEV.mhs1 })).body.mata_kuliah.length === 0);
    check('dosen2 finalisasi kelas A -> 403', (await gw('POST', '/kelas/A/finalisasi', { token: dosen2, device: DEV.dosen2 })).status === 403);
    r = await gw('POST', '/kelas/A/finalisasi', { token: dosen1, device: DEV.dosen1 });
    check('dosen1 finalisasi kelas A -> 200 + sinkron', r.status === 200 && r.body.transkrip.jumlah === 3, JSON.stringify(r.body));
    check('finalisasi ulang -> 409', (await gw('POST', '/kelas/A/finalisasi', { token: dosen1, device: DEV.dosen1 })).status === 409);
    r = await gw('PUT', '/nilai/1', { token: dosen1, device: DEV.dosen1, body: { nilai: 50 } });
    check('PUT nilai yang sudah final -> 403', r.status === 403 && /final/i.test(r.body.error));

    // ------------------------------------------------------------------
    section('Transkrip & token service');
    r = await gw('GET', '/transkrip/247006111087', { token: mhs1, device: DEV.mhs1 });
    check('mahasiswa melihat transkrip sendiri -> 200 berisi nilai final', r.status === 200 && r.body.mata_kuliah.length === 1 && r.body.mata_kuliah[0].nilai === 90, JSON.stringify(r.body));
    check('mahasiswa melihat transkrip NIM lain -> 403', (await gw('GET', '/transkrip/247006111099', { token: mhs1, device: DEV.mhs1 })).status === 403);
    r = await gw('GET', '/transkrip/247006111099', { token: admin, device: DEV.admin });
    check('admin melihat transkrip NIM mana pun -> 200', r.status === 200 && r.body.nim === '247006111099');
    check('dosen GET /transkrip/:nim -> 403', (await gw('GET', '/transkrip/247006111087', { token: dosen1, device: DEV.dosen1 })).status === 403);

    const forgedSync = { kelas: { id: 'A', kode: 'KP70065004', nama: 'Keamanan Informasi', sks: 3 }, nilai: [{ nim: '247006111087', nilai: 100 }] };
    for (const [nama, tok, dev] of [['admin', admin, DEV.admin], ['dosen1', dosen1, DEV.dosen1], ['mhs1', mhs1, DEV.mhs1]]) {
      check(`token user (${nama}) ke /transkrip/sinkron -> 403`, (await gw('POST', '/transkrip/sinkron', { token: tok, device: dev, body: forgedSync })).status === 403);
    }
    r = await gw('POST', '/transkrip/sinkron', { token: svc, body: forgedSync });
    check('token service lolos gateway, tapi data palsu ditolak verifikasi silang (422)', r.status === 422, JSON.stringify(r.body));
    check('token service ke /nilai -> 403', (await gw('GET', '/nilai', { token: svc })).status === 403);
    check('token service ke /transkrip/:nim -> 403', (await gw('GET', '/transkrip/247006111087', { token: svc })).status === 403);
    check('transkrip tidak berubah oleh data palsu', (await gw('GET', '/transkrip/247006111087', { token: mhs1, device: DEV.mhs1 })).body.mata_kuliah[0].nilai === 90);

    // ------------------------------------------------------------------
    section('4.4 Audit log');
    const total = dbc.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
    const allows = dbc.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='allow'").get().c;
    const denies = dbc.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='deny'").get().c;
    check(`audit log terisi (${total} entri: ${allows} allow, ${denies} deny)`, total > 50 && allows > 0 && denies > 0);
    const sample = dbc.prepare("SELECT * FROM audit_log WHERE hasil='deny' AND subjek LIKE 'user:%' AND device IS NOT NULL ORDER BY id DESC LIMIT 1").get();
    check('entri berisi waktu, subjek, endpoint, device, hasil, alasan', sample && sample.waktu && sample.subjek && sample.endpoint && sample.device && sample.hasil && sample.alasan);
    check('panggilan antar-service tercatat (subjek service:service-nilai)', dbc.prepare("SELECT COUNT(*) c FROM audit_log WHERE subjek='service:service-nilai' AND endpoint='/transkrip/sinkron' AND hasil='allow'").get().c >= 1);
    check('percobaan login gagal tercatat', dbc.prepare("SELECT COUNT(*) c FROM audit_log WHERE endpoint='/auth/login' AND hasil='deny'").get().c >= 3);
    dbc.close();
  } finally {
    children.forEach((c) => c.kill());
    fs.rmSync(cfg.policyFile, { force: true });
  }
  console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}Hasil: ${passed} lulus, ${failed} gagal\x1b[0m`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
