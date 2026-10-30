// Service Transkrip (port 3002) - data transkrip mahasiswa.
// Wajib lewat gateway (X-Gateway-Secret) dan memverifikasi ulang token.
const express = require('express');
const cfg = require('../lib/config');
const { openDb } = require('../lib/db');
const { requireGatewaySecret, requireToken, requireRole } = require('../lib/serviceGuard');

const db = openDb();
const app = express();
app.disable('x-powered-by');

app.use(requireGatewaySecret);
app.use(requireToken);
app.use(express.json({ limit: '100kb' }));

const grade = (n) => (n >= 85 ? ['A', 4] : n >= 70 ? ['B', 3] : n >= 55 ? ['C', 2] : n >= 40 ? ['D', 1] : ['E', 0]);

// ---------------------------------------------------------------------------
// GET /transkrip/:nim - mahasiswa (NIM sendiri) atau admin (semua)
// ---------------------------------------------------------------------------
app.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const mhs = db.prepare("SELECT id, nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'").get(req.params.nim);
  if (req.auth.role === 'mahasiswa' && (!mhs || mhs.id !== Number(req.auth.sub))) {
    return res.status(403).json({ error: 'Mahasiswa hanya boleh melihat transkrip miliknya sendiri' });
  }
  if (!mhs) return res.status(404).json({ error: 'Mahasiswa tidak ditemukan' });

  const rows = db.prepare('SELECT kode_mk, nama_mk, sks, nilai, updated_at FROM transkrip WHERE nim = ? ORDER BY kode_mk').all(mhs.nim);
  const mataKuliah = rows.map((r) => { const [huruf, bobot] = grade(r.nilai); return { ...r, huruf, bobot }; });
  const totalSks = mataKuliah.reduce((a, r) => a + r.sks, 0);
  const ipk = totalSks ? mataKuliah.reduce((a, r) => a + r.bobot * r.sks, 0) / totalSks : 0;
  res.json({ nim: mhs.nim, nama: mhs.nama, total_sks: totalSks, ipk: Number(ipk.toFixed(2)), mata_kuliah: mataKuliah });
});

// ---------------------------------------------------------------------------
// POST /transkrip/sinkron - hanya token service (Service Nilai)
// ---------------------------------------------------------------------------
app.post('/transkrip/sinkron', requireRole('service'), (req, res) => {
  const { kelas, nilai } = req.body || {};
  const bad = (msg) => res.status(400).json({ error: msg });
  if (!kelas || typeof kelas.id !== 'string' || !/^[A-Za-z]+$/.test(kelas.id) || typeof kelas.kode !== 'string' || typeof kelas.nama !== 'string'
      || !Number.isInteger(kelas.sks) || kelas.sks < 1 || kelas.sks > 6) return bad('Field "kelas" tidak valid');
  if (!Array.isArray(nilai) || nilai.length === 0 || nilai.length > 500) return bad('Field "nilai" harus array 1-500 item');
  for (const n of nilai) {
    if (!n || typeof n.nim !== 'string' || typeof n.nilai !== 'number' || n.nilai < 0 || n.nilai > 100) {
      return bad('Setiap item nilai harus berisi nim (string) dan nilai (0-100)');
    }
  }

  // Verifikasi silang (assume breach): hanya nilai FINAL yang ada di database yang boleh masuk transkrip
  const k = db.prepare('SELECT id, kode FROM kelas WHERE id = ?').get(kelas.id);
  if (!k || k.kode !== kelas.kode) return res.status(422).json({ error: 'Kelas tidak dikenal' });
  const finalRow = db.prepare(`SELECT n.nilai FROM nilai n JOIN users u ON u.id = n.mahasiswa_id
                               WHERE n.kelas_id = ? AND u.nim = ? AND n.final = 1`);
  for (const n of nilai) {
    const f = finalRow.get(kelas.id, n.nim);
    if (!f || f.nilai !== n.nilai) {
      return res.status(422).json({ error: `Nilai untuk NIM ${n.nim} tidak cocok dengan nilai final di database` });
    }
  }

  const upsert = db.prepare(`
    INSERT INTO transkrip (nim, kelas_id, kode_mk, nama_mk, sks, nilai, updated_at)
    VALUES (@nim, @kelas_id, @kode_mk, @nama_mk, @sks, @nilai, @updated_at)
    ON CONFLICT (nim, kelas_id) DO UPDATE SET nilai = excluded.nilai, updated_at = excluded.updated_at`);
  const ts = new Date().toISOString();
  db.transaction(() => {
    for (const n of nilai) {
      upsert.run({ nim: n.nim, kelas_id: kelas.id, kode_mk: kelas.kode, nama_mk: kelas.nama, sks: kelas.sks, nilai: n.nilai, updated_at: ts });
    }
  })();
  res.json({ message: 'Transkrip disinkronkan', jumlah: nilai.length });
});

app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));

if (require.main === module) {
  cfg.gatewaySecret; // fail closed
  app.listen(cfg.ports.transkrip, cfg.host, () => console.log(`[service-transkrip] aktif di http://${cfg.host}:${cfg.ports.transkrip}`));
}
module.exports = app;
