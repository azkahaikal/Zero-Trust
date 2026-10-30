// ============================================================================
// Policy Engine (PE) - memutuskan allow/deny berdasarkan Tabel 3 + atribut di database.
// Prinsip: DEFAULT DENY. Endpoint/metode yang tidak terdaftar di bawah otomatis ditolak.
// Kebijakan kepemilikan (kelas yang diampu, NIM milik mahasiswa) tidak bisa diputuskan
// dari isi token saja, sehingga PE membaca users / kelas / nilai dari database.
// ============================================================================
const fs = require('fs');
const cfg = require('../lib/config');

const DEFAULT_HOURS = { start: '07:00', end: '21:00', timezone: 'Asia/Jakarta' };

// Konfigurasi dibaca ulang setiap keputusan -> jam akses bisa diubah saat demo tanpa restart.
function readAccessHours() {
  try {
    const j = JSON.parse(fs.readFileSync(cfg.policyFile, 'utf8'));
    return { ...DEFAULT_HOURS, ...(j.accessHours || {}) };
  } catch {
    return DEFAULT_HOURS;
  }
}

const toMinutes = (hhmm) => {
  const m = String(hhmm).match(/^(\d{1,2}):(\d{2})$/);
  if (!m) throw new Error('format jam harus HH:MM');
  return Number(m[1]) * 60 + Number(m[2]);
};

// Rentang [start, end). Mendukung rentang lintas tengah malam. end "24:00" = akhir hari.
function withinAccessHours(now = new Date(), hours = readAccessHours()) {
  let h = hours;
  try { toMinutes(h.start); toMinutes(h.end); new Intl.DateTimeFormat('en-GB', { timeZone: h.timezone }); }
  catch { h = DEFAULT_HOURS; }
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: h.timezone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(now);
  const cur = Number(parts.find((p) => p.type === 'hour').value) * 60 + Number(parts.find((p) => p.type === 'minute').value);
  const s = toMinutes(h.start);
  const e = toMinutes(h.end);
  const ok = s <= e ? cur >= s && cur < e : cur >= s || cur < e;
  return { ok, label: `${h.start}-${h.end} ${h.timezone}` };
}

const allow = (reason) => ({ allow: true, reason });
const deny = (reason, status = 403) => ({ allow: false, reason, status });

module.exports = function createPolicy(db) {
  const q = {
    user: db.prepare('SELECT id, role, nim FROM users WHERE id = ?'),
    kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),  // id kelas berupa huruf (A, B)
    nilai: db.prepare(`SELECT n.id, n.final, n.kelas_id, k.dosen_id
                       FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`),
  };

  const hoursCheck = (now) => {
    const r = withinAccessHours(now);
    return r.ok ? null : deny(`Di luar jam akses (${r.label})`);
  };

  // --- Daftar kebijakan (Tabel 3) ---
  const rules = [
    {
      // GET /nilai : mahasiswa (hanya miliknya), dosen (hanya kelas yang diampu)
      method: 'GET', re: /^\/nilai\/?$/, roles: ['mahasiswa', 'dosen'], upstream: 'nilai',
      check({ subject, query }) {
        const { kelas_id: kelasId, nim } = query;
        for (const v of [kelasId, nim]) {
          if (v !== undefined && typeof v !== 'string') return deny('Parameter query tidak valid', 400);
        }
        if (kelasId !== undefined && !/^[A-Za-z]+$/.test(kelasId)) return deny('kelas_id harus berupa huruf (mis. A atau B)', 400);

        if (subject.role === 'mahasiswa') {
          const me = q.user.get(subject.sub);
          if (nim !== undefined && nim !== me.nim) return deny('Mahasiswa hanya boleh melihat nilai miliknya sendiri');
          return allow('Mahasiswa mengakses nilai miliknya sendiri');
        }
        // dosen
        if (kelasId !== undefined) {
          const k = q.kelas.get(kelasId);
          if (!k) return deny('Kelas tidak ditemukan', 404);
          if (k.dosen_id !== Number(subject.sub)) return deny('Dosen bukan pengampu kelas ini');
        }
        return allow('Dosen mengakses nilai kelas yang diampu');
      },
    },
    {
      // PUT /nilai/:id : dosen pengampu, nilai belum final, dalam jam akses
      method: 'PUT', re: /^\/nilai\/(\d+)\/?$/, roles: ['dosen'], upstream: 'nilai',
      check({ subject, params, now }) {
        const n = q.nilai.get(Number(params[0]));
        if (!n) return deny('Data nilai tidak ditemukan', 404);
        if (n.dosen_id !== Number(subject.sub)) return deny('Dosen bukan pengampu kelas dari nilai ini');
        if (n.final) return deny('Nilai sudah final dan tidak dapat diubah');
        return hoursCheck(now) || allow('Dosen pengampu, nilai belum final, dalam jam akses');
      },
    },
    {
      // POST /kelas/:id/finalisasi : dosen pengampu, dalam jam akses
      method: 'POST', re: /^\/kelas\/([A-Za-z]+)\/finalisasi\/?$/, roles: ['dosen'], upstream: 'nilai',
      check({ subject, params, now }) {
        const k = q.kelas.get(params[0]);
        if (!k) return deny('Kelas tidak ditemukan', 404);
        if (k.dosen_id !== Number(subject.sub)) return deny('Dosen bukan pengampu kelas ini');
        return hoursCheck(now) || allow('Dosen pengampu kelas, dalam jam akses');
      },
    },
    {
      // GET /transkrip/:nim : mahasiswa (NIM sendiri), admin (semua NIM)
      method: 'GET', re: /^\/transkrip\/([A-Za-z0-9_-]+)\/?$/, roles: ['mahasiswa', 'admin'], upstream: 'transkrip',
      check({ subject, params }) {
        if (subject.role === 'admin') return allow('Admin dapat melihat transkrip semua NIM');
        const me = q.user.get(subject.sub);
        if (params[0] !== me.nim) return deny('Mahasiswa hanya boleh melihat transkrip dengan NIM sendiri');
        return allow('Mahasiswa mengakses transkrip NIM sendiri');
      },
    },
    {
      // POST /transkrip/sinkron : hanya token service
      method: 'POST', re: /^\/transkrip\/sinkron\/?$/, roles: ['service'], upstream: 'transkrip',
      check: () => allow('Token service sah untuk sinkron transkrip'),
    },
  ];

  /**
   * ctx: { subject:{sub,role}, method, path, query, now }
   * return: { allow, reason, status?, upstream? }
   */
  function decide(ctx) {
    const now = ctx.now || new Date();
    let pathMatched = false;
    for (const rule of rules) {
      const m = ctx.path.match(rule.re);
      if (!m) continue;
      pathMatched = true;
      if (rule.method !== ctx.method) continue;
      if (!rule.roles.includes(ctx.subject.role)) {
        return deny(`Role "${ctx.subject.role}" tidak diizinkan untuk ${rule.method} ${ctx.path}`);
      }
      const r = rule.check({ subject: ctx.subject, params: m.slice(1), query: ctx.query || {}, now });
      return r.allow ? { ...r, upstream: rule.upstream } : r;
    }
    return deny(pathMatched
      ? `Metode ${ctx.method} tidak diizinkan untuk endpoint ini (default deny)`
      : 'Tidak ada kebijakan untuk endpoint ini (default deny)');
  }

  return { decide, withinAccessHours };
};
