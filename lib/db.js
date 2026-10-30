// Satu database SQLite bersama untuk gateway, Service Nilai, dan Service Transkrip.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const cfg = require('./config');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nama          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim           TEXT UNIQUE            -- hanya untuk mahasiswa
);
CREATE TABLE IF NOT EXISTS devices (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id   INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id       TEXT PRIMARY KEY,                       -- kelas berupa huruf: 'A', 'B'
  kode     TEXT NOT NULL,
  nama     TEXT NOT NULL,
  sks      INTEGER NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)   -- dosen pengampu
);
CREATE TABLE IF NOT EXISTS nilai (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id     TEXT NOT NULL REFERENCES kelas(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai        REAL,
  final        INTEGER NOT NULL DEFAULT 0,
  updated_at   TEXT,
  UNIQUE (kelas_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS transkrip (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  nim        TEXT NOT NULL,
  kelas_id   TEXT NOT NULL,
  kode_mk    TEXT NOT NULL,
  nama_mk    TEXT NOT NULL,
  sks        INTEGER NOT NULL,
  nilai      REAL NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (nim, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,   -- hanya hash SHA-256 yang disimpan
  device_id  TEXT,
  expires_at INTEGER NOT NULL,       -- epoch detik
  revoked    INTEGER NOT NULL DEFAULT 0,  -- 0 aktif, 1 dicabut (logout), 2 sudah dirotasi
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id   TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  nama        TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  waktu    TEXT NOT NULL,
  subjek   TEXT NOT NULL,
  role     TEXT,
  metode   TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device   TEXT,
  hasil    TEXT NOT NULL CHECK (hasil IN ('allow','deny')),
  alasan   TEXT NOT NULL,
  status   INTEGER,
  ip       TEXT
);
`;

function openDb({ create = false } = {}) {
  if (!create && !fs.existsSync(cfg.dbPath)) {
    throw new Error(`Database tidak ditemukan di ${cfg.dbPath}. Jalankan "npm run setup" terlebih dahulu.`);
  }
  fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
  const db = new Database(cfg.dbPath);
  db.pragma('busy_timeout = 5000'); // beberapa proses berbagi satu file DB
  db.pragma('foreign_keys = ON');
  return db;
}

function initSchema(db) { db.exec(SCHEMA); }

module.exports = { openDb, initSchema };
