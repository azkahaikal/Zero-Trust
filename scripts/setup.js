// Menyiapkan: .env, pasangan kunci RSA, skema database, dan data awal (seed).
//   node scripts/setup.js            -> siapkan yang belum ada (seed hanya jika DB masih kosong)
//   node scripts/setup.js --reset    -> hapus DB lalu seed ulang
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function ensureEnv() {
  const root = path.resolve(__dirname, '..');
  const env = path.join(root, '.env');
  if (!fs.existsSync(env) && fs.existsSync(path.join(root, '.env.example'))) {
    fs.copyFileSync(path.join(root, '.env.example'), env);
    console.log('[setup] .env dibuat dari .env.example');
  }
}

function ensureKeys(cfg) {
  if (fs.existsSync(cfg.keys.privatePath) && fs.existsSync(cfg.keys.publicPath)) return;
  fs.mkdirSync(path.dirname(cfg.keys.privatePath), { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(cfg.keys.privatePath, privateKey, { mode: 0o600 });
  fs.writeFileSync(cfg.keys.publicPath, publicKey);
  console.log('[setup] pasangan kunci RS256 dibuat di keys/ (private.pem hanya untuk gateway)');
}

function seed(db, cfg, pwd) {
  const insUser = db.prepare('INSERT INTO users (username, password_hash, nama, role, nim) VALUES (?,?,?,?,?)');
  const insDev = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?,?)');
  const insKelas = db.prepare('INSERT INTO kelas (id, kode, nama, sks, dosen_id) VALUES (?,?,?,?,?)');
  const insNilai = db.prepare('INSERT INTO nilai (kelas_id, mahasiswa_id, nilai, final) VALUES (?,?,?,0)');

  const users = [
    // username, password, nama, role, nim, device
    ['admin', 'Admin#123', 'Administrator Prodi', 'admin', null, 'ADM-DEV-001'],
    ['dosen1', 'Dosen1#123', 'Dr. Budi Santoso', 'dosen', null, 'DSN1-LAPTOP'],
    ['dosen2', 'Dosen2#123', 'Dr. Sari Wulandari', 'dosen', null, 'DSN2-LAPTOP'],
    ['mhs1', 'Mhs1#123', 'Azka', 'mahasiswa', '247006111087', 'MHS1-PHONE'],
    ['mhs2', 'Mhs2#123', 'Abil', 'mahasiswa', '247006111099', 'MHS2-PHONE'],
    ['mhs3', 'Mhs3#123', 'Kamal', 'mahasiswa', '247006111122', 'MHS3-PHONE'],
  ];
  const id = {};
  db.transaction(() => {
    for (const [u, p, nama, role, nim, dev] of users) {
      id[u] = Number(insUser.run(u, pwd.hash(p), nama, role, nim).lastInsertRowid);
      insDev.run(id[u], dev); // setiap user memiliki 1 device terdaftar
    }
    insKelas.run('A', 'KP70065004', 'Keamanan Informasi', 3, id.dosen1);
    insKelas.run('B', 'KP70065002', 'Basis Data', 3, id.dosen2);
    const k1 = 'A';
    const k2 = 'B';
    const skor = { [k1]: [88, 75, 62], [k2]: [91, 68, 80] };
    for (const k of [k1, k2]) ['mhs1', 'mhs2', 'mhs3'].forEach((m, i) => insNilai.run(k, id[m], skor[k][i]));

    db.prepare('INSERT INTO service_clients (client_id, secret_hash, nama) VALUES (?,?,?)')
      .run(cfg.serviceClientId, pwd.hash(cfg.serviceClientSecret), 'Service Nilai');
  })();
  console.log('[setup] data awal dimasukkan: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas, 1 service client');
}

function setup({ reset = false } = {}) {
  ensureEnv();
  const cfg = require('../lib/config'); // setelah .env ada
  const { openDb, initSchema } = require('../lib/db');
  const pwd = require('../lib/password');

  ensureKeys(cfg);
  if (reset) {
    for (const suffix of ['', '-journal', '-wal', '-shm']) fs.rmSync(cfg.dbPath + suffix, { force: true });
    console.log('[setup] database lama dihapus');
  }
  const db = openDb({ create: true });
  initSchema(db);
  if (db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0) seed(db, cfg, pwd);
  else console.log('[setup] database sudah berisi data (gunakan --reset untuk mengulang)');
  db.close();
  console.log(`[setup] selesai. DB: ${cfg.dbPath}`);
}

if (require.main === module) setup({ reset: process.argv.includes('--reset') });
module.exports = { setup };
