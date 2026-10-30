# Sistem Nilai — Zero Trust Security

Tugas Praktikum Individu · Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi

Sistem Nilai dengan prinsip **zero trust** (*never trust, always verify; least privilege; assume breach*) di level aplikasi. API gateway berperan sebagai **Policy Enforcement Point (PEP)** yang terpisah dari service, sesuai NIST SP 800-207.

```
 Client (curl / Postman)
   │  Authorization: Bearer <access token> + X-Device-ID
   ▼
┌──────────────────────────────────────────────┐        ┌───────────┐
│ API Gateway :3000  (PEP)                     │───────▶│ Audit Log │
│  ├─ Policy Engine / Administrator (modul)    │        └───────────┘
│  │   login, token, keputusan allow/deny      │
│  └─ proxy + X-Gateway-Secret                 │
└──────────┬──────────────────────┬────────────┘
           │ jika allow           │ jika allow
           ▼                      ▼
   Service Nilai :3001     Service Transkrip :3002
           │  finalisasi: POST /transkrip/sinkron + token service
           └──────────▶ (kembali ke gateway, bukan langsung) ──▶ Service Transkrip
                       └──────────── Database SQLite bersama ────────────┘
```

## 1. Menjalankan

Prasyarat: Node.js ≥ 18 (diuji di Node 22). Tanpa server database — memakai SQLite (`better-sqlite3`).

### Langsung (tanpa Docker)
```bash
npm install
npm start          # otomatis: buat .env, kunci RS256, database + seed, lalu jalankan 3 proses
```
Gateway di `http://localhost:3000`, Service Nilai `:3001`, Service Transkrip `:3002`.
Perintah lain: `npm run seed` (reset DB + seed ulang), `npm run audit` (lihat audit log), `npm test` (74 tes otomatis).

## 2. Akun dan device ID (data awal / seed)

| Role | Username | Password | NIM | X-Device-ID |
|---|---|---|---|---|
| Admin | `admin` | `Admin#123` | – | `ADM-DEV-001` |
| Dosen 1 (pengampu kelas A) | `dosen1` | `Dosen1#123` | – | `DSN1-LAPTOP` |
| Dosen 2 (pengampu kelas B) | `dosen2` | `Dosen2#123` | – | `DSN2-LAPTOP` |
| Mahasiswa (Azka) | `mhs1` | `Mhs1#123` | `247006111087` | `MHS1-PHONE` |
| Mahasiswa (Abil) | `mhs2` | `Mhs2#123` | `247006111099` | `MHS2-PHONE` |
| Mahasiswa (Kamal) | `mhs3` | `Mhs3#123` | `247006111122` | `MHS3-PHONE` |

Kelas dinyatakan dengan **huruf**: **A** = KP70065004 Keamanan Informasi (dosen1), **B** = KP70065002 Basis Data (dosen2). Tiap kelas punya 3 baris nilai (draft); `id` nilai (angka) 1–3 milik kelas A, 4–6 milik kelas B. Contoh: `GET /nilai?kelas_id=A`, `POST /kelas/A/finalisasi`.
Service client: `service-nilai` (secret ada di `.env`, `SERVICE_CLIENT_SECRET`).

> Semua secret di `.env.example` hanya untuk demo. Password disimpan sebagai hash scrypt.

## 3. Pemetaan kebutuhan → kode (untuk video demo)

| Kebutuhan (bagian 4) | Letak di kode |
|---|---|
| **4.1** Access token JWT 10 menit, berisi `sub` & `role`, header `Authorization: Bearer` | `gateway/tokens.js` → `issueAccessToken`; verifikasi di `lib/jwt.js` (RS256, tolak `none`/HS256) |
| **4.1** Refresh token 1 hari, di database, bisa dicabut; logout mencabut | `gateway/tokens.js` → `issueRefreshToken` (hanya hash SHA-256 disimpan); `gateway/auth.js` → `/refresh`, `/logout`. Rotasi tiap refresh + deteksi pemakaian ulang (semua sesi dicabut) |
| **4.1** Token service 5 menit, `role: service`, dari `POST /auth/service` | `gateway/auth.js` → `/service`; `service-nilai/index.js` → `getServiceToken` (cache + minta ulang) |
| **4.1** Gateway secret `X-Gateway-Secret`; service menolak tanpa header | `gateway/proxies.js` (`proxyReq` menimpa header); `lib/serviceGuard.js` → `requireGatewaySecret` (perbandingan waktu-konstan) |
| **4.1** Verifikasi ulang token di service (tanda tangan + masa berlaku) | `lib/serviceGuard.js` → `requireToken`, dipasang di `service-nilai/index.js` & `service-transkrip/index.js` |
| **4.2** Semua akses lewat gateway; kebijakan Tabel 3 + atribut dari database | `gateway/pep.js` (alur PEP) dan `gateway/policy.js` (`rules[]`, **default deny**, membaca `users`/`kelas`/`nilai`) |
| **4.2** Finalisasi → Service Nilai memanggil Service Transkrip **melalui gateway** | `service-nilai/index.js` → `syncTranskrip` ke `GATEWAY_URL/transkrip/sinkron`; endpoint hanya untuk token service di `policy.js` & `service-transkrip/index.js` |
| **4.3** Device terdaftar (`X-Device-ID`) | login: `gateway/auth.js`; tiap request: `gateway/pep.js` (langkah 2, tabel `devices`) |
| **4.3** Jam akses 07.00–21.00, dapat dikonfigurasi | `gateway/policy.js` → `withinAccessHours` + `config/policy.json` (dibaca ulang tiap request, **tanpa restart**) |
| **4.4** Audit log: waktu, subjek, endpoint, device, hasil, alasan | `gateway/audit.js` → tabel `audit_log` + konsol; dilihat dengan `npm run audit` |

Prinsip zero trust: *never trust, always verify* (token + device + policy diperiksa di setiap request, termasuk antar-service); *least privilege* (default deny, service hanya punya kunci publik, token service hanya boleh ke `/transkrip/sinkron`); *assume breach* (service memverifikasi ulang secret + token + role + kepemilikan data, Service Transkrip memverifikasi silang nilai dengan DB, deteksi reuse refresh token).

## 4. Ringkasan kebijakan (Tabel 3)

| Endpoint | Ditangani | Diizinkan | Kondisi |
|---|---|---|---|
| `POST /auth/login` | Gateway | semua | kredensial valid + device terdaftar |
| `POST /auth/refresh`, `/auth/logout` | Gateway | semua | refresh token valid & belum dicabut |
| `POST /auth/service` | Gateway | Service Nilai | client ID + secret valid |
| `GET /nilai` | Nilai | mahasiswa, dosen | mahasiswa: miliknya; dosen: kelas yang diampu (`?kelas_id=`) |
| `PUT /nilai/:id` | Nilai | dosen | kelas diampu, belum final, dalam jam akses |
| `POST /kelas/:id/finalisasi` | Nilai | dosen | kelas diampu, dalam jam akses → sinkron transkrip |
| `GET /transkrip/:nim` | Transkrip | mahasiswa, admin | mahasiswa: NIM sendiri; admin: semua |
| `POST /transkrip/sinkron` | Transkrip | Service Nilai | hanya token service |

Selain di atas → **403 (default deny)**. Alasan setiap penolakan tercatat di audit log.

## 5. Struktur repository

```
gateway/            PEP + Policy Engine/Administrator
  index.js          perakitan gateway          pep.js     alur verifikasi → keputusan → audit → proxy
  policy.js         kebijakan (Tabel 3), jam akses   auth.js    /auth/* (login, refresh, logout, service)
  tokens.js         penerbitan token (kunci privat)  audit.js   audit log     proxies.js  forward + X-Gateway-Secret
service-nilai/      Service Nilai (:3001)
service-transkrip/  Service Transkrip (:3002)
lib/                config, db (skema), jwt (verifikasi), serviceGuard (secret+token+role), password (scrypt)
scripts/            setup.js (kunci, DB, seed), start-all.js, audit.js
config/policy.json  jam akses            demo/demo.sh   skenario curl
tests/e2e.js        74 tes end-to-end    Dockerfile, docker-compose.yml
```

## 6. Catatan desain dan keterbatasan

- **JWT RS256**: gateway menandatangani dengan kunci privat; service hanya memegang kunci publik sehingga tidak bisa menerbitkan token.
- **Access token tidak dapat dicabut** sebelum kedaluwarsa (10 menit, sesuai spesifikasi); yang dicabut adalah refresh token. Konteks (user ada, role cocok dengan DB, device terdaftar) tetap diperiksa di setiap request.
- **Finalisasi atomik secara logis**: nilai dikunci (`final=1`) sebelum sinkron; bila sinkron gagal, finalisasi dibatalkan dan respons 502.
- Pesan galat login sengaja generik (anti user-enumeration); alasan rinci hanya ada di audit log.
- Belum ada TLS dan rate limiting — di luar lingkup tugas, tetapi wajib pada deployment nyata.
