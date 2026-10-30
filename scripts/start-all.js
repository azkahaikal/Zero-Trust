// Menjalankan Service Nilai, Service Transkrip, dan Gateway sebagai tiga proses terpisah.
const { spawn } = require('child_process');
const path = require('path');
const { setup } = require('./setup');

const ROOT = path.resolve(__dirname, '..');
const PROCS = [
  ['service-nilai', 'service-nilai/index.js'],
  ['service-transkrip', 'service-transkrip/index.js'],
  ['gateway', 'gateway/index.js'],
];

function startAll(env = process.env, { quiet = false } = {}) {
  const children = PROCS.map(([name, file]) => {
    const child = spawn(process.execPath, [path.join(ROOT, file)], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
    const pipe = (stream, out) => stream.on('data', (d) => {
      if (quiet) return;
      String(d).split('\n').filter(Boolean).forEach((l) => out.write(l.startsWith('[') ? l + '\n' : `[${name}] ${l}\n`));
    });
    pipe(child.stdout, process.stdout);
    pipe(child.stderr, process.stderr);
    child.on('exit', (code) => { if (code) console.error(`[${name}] berhenti dengan kode ${code}`); });
    return child;
  });
  return children;
}

if (require.main === module) {
  setup(); // idempotent: siapkan .env, kunci, dan database bila belum ada
  const children = startAll();
  const stop = () => { children.forEach((c) => c.kill()); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
module.exports = { startAll };
