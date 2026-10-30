// Audit log (4.4): setiap keputusan akses dicatat gateway ke tabel audit_log
// (waktu, subjek, endpoint, device, hasil allow/deny, alasan) dan ke konsol.
module.exports = function createAudit(db) {
  const insert = db.prepare(`
    INSERT INTO audit_log (waktu, subjek, role, metode, endpoint, device, hasil, alasan, status, ip)
    VALUES (@waktu, @subjek, @role, @metode, @endpoint, @device, @hasil, @alasan, @status, @ip)`);

  return function audit(e) {
    const row = {
      waktu: new Date().toISOString(),
      subjek: e.subjek || 'anonymous',
      role: e.role || null,
      metode: e.metode,
      endpoint: String(e.endpoint).slice(0, 300),
      device: e.device ? String(e.device).slice(0, 100) : null,
      hasil: e.hasil,
      alasan: e.alasan,
      status: e.status ?? null,
      ip: e.ip || null,
    };
    try { insert.run(row); } catch (err) { console.error('[audit] gagal menulis log:', err.message); }
    const tag = row.hasil === 'allow' ? 'ALLOW' : 'DENY ';
    console.log(`[audit] ${tag} ${row.subjek.padEnd(14)} ${row.metode.padEnd(6)} ${row.endpoint} device=${row.device || '-'} :: ${row.alasan}`);
  };
};
