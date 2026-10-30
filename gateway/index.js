// API Gateway (PEP) + Policy Engine/Administrator - port 3000
const express = require('express');
const cfg = require('../lib/config');
const { openDb } = require('../lib/db');
const createAudit = require('./audit');
const createPolicy = require('./policy');
const createAuthRouter = require('./auth');
const createProxies = require('./proxies');
const createPep = require('./pep');

function createGateway() {
  const db = openDb();
  const audit = createAudit(db);
  const policy = createPolicy(db);
  const proxies = createProxies(audit);

  const app = express();
  app.disable('x-powered-by');

  app.use('/auth', createAuthRouter(db, audit)); // dilayani gateway sendiri
  app.use(createPep({ db, policy, audit, proxies })); // semua yang lain: PEP -> service

  return app;
}

if (require.main === module) {
  cfg.gatewaySecret; // gagal-tertutup bila secret belum diset
  createGateway().listen(cfg.ports.gateway, cfg.host, () =>
    console.log(`[gateway] PEP + Policy Engine aktif di http://${cfg.host}:${cfg.ports.gateway}`));
}

module.exports = { createGateway };
