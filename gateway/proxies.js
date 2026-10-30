// Meneruskan request yang sudah di-allow ke service, dengan menyisipkan X-Gateway-Secret.
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../lib/config');

module.exports = function createProxies(audit) {
  const make = (name, target) =>
    createProxyMiddleware({
      target,
      proxyTimeout: 15000,
      on: {
        proxyReq(proxyReq) {
          // setHeader menimpa X-Gateway-Secret apa pun yang dikirim klien
          proxyReq.setHeader('X-Gateway-Secret', cfg.gatewaySecret);
        },
        error(err, req, res) {
          audit({ metode: req.method, endpoint: req.originalUrl, subjek: 'gateway', hasil: 'deny',
            alasan: `Service ${name} tidak dapat dihubungi: ${err.code || err.message}`, status: 502 });
          if (res && typeof res.writeHead === 'function' && !res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Service ${name} tidak tersedia` }));
          }
        },
      },
    });

  return {
    nilai: make('nilai', cfg.urls.nilai),
    transkrip: make('transkrip', cfg.urls.transkrip),
  };
};
