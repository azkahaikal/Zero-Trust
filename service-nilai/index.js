// Service Nilai (port 3001) - data nilai dan kelas.
// Tidak pernah dipanggil langsung oleh klien: wajib lewat gateway (X-Gateway-Secret)
// dan membawa token yang diverifikasi ulang di sini.
const express = require('express');
const cfg = require('../lib/config');
const { openDb } = require('../lib/db');
const { requireGatewaySecret, requireToken, requireRole } = require('../lib/serviceGuard');

const db = openDb();
const app = express();
app.disable('x-powered-by');

app.use(requireGatewaySecret);          // 1) harus lewat gateway
app.use(requireToken);                  // 2) verifikasi ulang tanda tangan + masa berlaku token
app.use(express.json({ limit: '10kb' }));

const isId = (v) => typeof v === 'string' && /^\d+$/.test(v);        // id nilai (angka)
const isKelas = (v) => typeof v === 'string' && /^[A-Za-z]+$/.test(v); // id kelas (huruf: A, B)
const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// GET /nilai  - data di-scope berdasarkan sub pada token (defense in depth)
// ---------------------------------------------------------------------------
app.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const where = [];
  const params = [];
  if (req.auth.role === 'mahasiswa') {
    where.push('n.mahasiswa_id = ?'); params.push(Number(req.auth.sub));
  } else {
    where.push('k.dosen_id = ?'); params.push(Number(req.auth.sub));
  }
  if (isKelas(req.query.kelas_id)) { where.push('n.kelas_id = ?'); params.push(req.query.kelas_id); }

  const rows = db.prepare(`
    SELECT n.id, n.kelas_id, k.kode AS kode_mk, k.nama AS nama_mk, u.nim, u.nama AS mahasiswa,
           n.nilai, n.final, n.updated_at
    FROM nilai n
    JOIN kelas k ON k.id = n.kelas_id
    JOIN users u ON u.id = n.mahasiswa_id
    WHERE ${where.join(' AND ')}
    ORDER BY n.kelas_id, u.nim`).all(...params);
  res.json({ data: rows });
});

// ---------------------------------------------------------------------------
// PUT /nilai/:id  - ubah nilai (dosen pengampu, belum final)
// ---------------------------------------------------------------------------
app.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const { nilai } = req.body || {};
  if (typeof nilai !== 'number' || !Number.isFinite(nilai) || nilai < 0 || nilai > 100) {
    return res.status(400).json({ error: 'Field "nilai" wajib berupa angka 0-100' });
  }
  if (!isId(req.params.id)) return res.status(400).json({ error: 'id tidak valid' });

  const row = db.prepare(`SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`)
    .get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Data nilai tidak ditemukan' });
  if (row.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Bukan dosen pengampu kelas ini' });
  if (row.final) return res.status(403).json({ error: 'Nilai sudah final' });

  db.prepare('UPDATE nilai SET nilai = ?, updated_at = ? WHERE id = ? AND final = 0').run(nilai, now(), row.id);
  res.json({ message: 'Nilai diperbarui', data: { id: row.id, nilai } });
});

// ---------------------------------------------------------------------------
// Token service: Service Nilai memperoleh token dari POST /auth/service (via gateway)
// ---------------------------------------------------------------------------
let cachedToken = null;
async function getServiceToken(force = false) {
  if (!force && cachedToken && cachedToken.expMs - 30_000 > Date.now()) return cachedToken.token;
  const r = await fetch(`${cfg.urls.gateway}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: cfg.serviceClientId, client_secret: cfg.serviceClientSecret }),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error(`POST /auth/service gagal (${r.status})`);
  const j = await r.json();
  cachedToken = { token: j.access_token, expMs: Date.now() + j.expires_in * 1000 };
  return cachedToken.token;
}

// Panggilan antar-service SELALU melalui gateway (bukan langsung ke Service Transkrip)
async function syncTranskrip(payload) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await getServiceToken(attempt > 0);
    const r = await fetch(`${cfg.urls.gateway}/transkrip/sinkron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000),
    });
    if (r.status === 401 && attempt === 0) continue; // token kedaluwarsa/ditolak -> minta token baru sekali
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`Sinkron transkrip ditolak (${r.status}): ${body.error || 'tanpa detail'}`);
    return body;
  }
  throw new Error('Sinkron transkrip gagal');
}

// ---------------------------------------------------------------------------
// POST /kelas/:id/finalisasi - finalisasi lalu sinkron ke Service Transkrip via gateway
// ---------------------------------------------------------------------------
app.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  if (!isKelas(req.params.id)) return res.status(400).json({ error: 'id kelas tidak valid (gunakan huruf, mis. A atau B)' });
  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(req.params.id);
  if (!kelas) return res.status(404).json({ error: 'Kelas tidak ditemukan' });
  if (kelas.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Bukan dosen pengampu kelas ini' });

  const rows = db.prepare(`SELECT n.nilai, n.final, u.nim FROM nilai n JOIN users u ON u.id = n.mahasiswa_id WHERE n.kelas_id = ?`)
    .all(kelas.id);
  if (rows.length === 0) return res.status(422).json({ error: 'Kelas belum memiliki data nilai' });
  if (rows.some((r) => r.nilai === null)) return res.status(422).json({ error: 'Masih ada nilai yang kosong' });
  if (rows.every((r) => r.final)) return res.status(409).json({ error: 'Kelas sudah difinalisasi' });

  // Kunci nilai (final=1) dulu agar tidak bisa diubah saat sinkron berlangsung
  db.prepare('UPDATE nilai SET final = 1, updated_at = ? WHERE kelas_id = ?').run(now(), kelas.id);
  try {
    const result = await syncTranskrip({
      kelas: { id: kelas.id, kode: kelas.kode, nama: kelas.nama, sks: kelas.sks },
      nilai: rows.map((r) => ({ nim: r.nim, nilai: r.nilai })),
    });
    res.json({ message: 'Kelas difinalisasi dan nilai disinkronkan ke transkrip', kelas_id: kelas.id, transkrip: result });
  } catch (err) {
    // Sinkron gagal -> batalkan finalisasi agar data tetap konsisten
    db.prepare('UPDATE nilai SET final = 0 WHERE kelas_id = ?').run(kelas.id);
    res.status(502).json({ error: 'Finalisasi dibatalkan: sinkron ke Service Transkrip gagal', detail: err.message });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));

if (require.main === module) {
  cfg.gatewaySecret; // fail closed
  app.listen(cfg.ports.nilai, cfg.host, () => console.log(`[service-nilai] aktif di http://${cfg.host}:${cfg.ports.nilai}`));
}
module.exports = app;
