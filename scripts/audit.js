// Menampilkan audit log: node scripts/audit.js [jumlah=30] [allow|deny]
const { openDb } = require('../lib/db');
const limit = Number(process.argv[2]) || 30;
const hasil = ['allow', 'deny'].includes(process.argv[3]) ? process.argv[3] : null;
const db = openDb();
const rows = db.prepare(`SELECT * FROM audit_log ${hasil ? 'WHERE hasil = ?' : ''} ORDER BY id DESC LIMIT ?`)
  .all(...(hasil ? [hasil, limit] : [limit])).reverse();
console.table(rows.map((r) => ({
  waktu: r.waktu.replace('T', ' ').slice(0, 19), subjek: r.subjek, role: r.role, metode: r.metode,
  endpoint: r.endpoint, device: r.device, hasil: r.hasil, status: r.status, alasan: r.alasan,
})));
