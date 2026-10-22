# Demo Celah Runtime Integrasi API: PHP2Shell & Brotli Node.js

[![tests](https://github.com/nextmend/api-runtime-vulnerabilities-demo/actions/workflows/tests.yml/badge.svg)](https://github.com/nextmend/api-runtime-vulnerabilities-demo/actions/workflows/tests.yml)

Repo contoh dan pembuktian teknis untuk artikel [Celah Runtime di Integrasi API: Membedah PHP2Shell dan Brotli Node.js](https://nextmend.dev/artikel/celah-runtime-integrasi-api/?utm_source=github&utm_medium=readme&utm_campaign=artikel-runtime).

Banyak tim backend berasumsi bahwa validasi skema di layer aplikasi (`FormRequest` di Laravel, `Zod` di TypeScript) dan Web Application Firewall (WAF) di depan server sudah cukup untuk mengamankan integrasi API dan webhook. Kenyataannya, celah keamanan level runtime terjadi di layer interpreter C/C++ pada fase inisialisasi request atau native decompression sebelum kode controller sempat dieksekusi.

Repo ini mereproduksi dan menguji dua celah runtime kritis pada skenario **Layanan Integrasi Logistik & Pengiriman**:
1. **Node.js Brotli Decoder (CVE-2026-111497):** Out-of-bounds write pada dekompresi Brotli native di outbound `fetch()` (Undici) saat mengambil manifest/label pengiriman dari server eksternal yang terkompromi.
2. **PHP2Shell (CVE-2026-109618 & CVE-2026-109619):** Kebocoran state dan eksekusi memori korup pada worker PHP-FPM akibat kegagalan pembersihan memori OOM (`longjmp()`) dan fitur bawaan `session.upload_progress.enabled`.

---

## Struktur Proyek

| File | Penjelasan |
| --- | --- |
| `src/node/manifest-fetcher.mjs` | Implementasi client outbound fetch: perbandingan handler naif vs client defensif yang menolak `Content-Encoding: br` tak terduga |
| `tests/node/brotli-fetch.test.mjs` | Test otomatis Node.js (`node --test`) membuktikan jebakan `Accept-Encoding: identity` pada Undici dan mitigasi defensifnya |
| `tests/php/upload_progress_test.php` | Script audit versi PHP, inspeksi konfigurasi `session.upload_progress.enabled`, dan simulasi vektor multipart |
| `scripts/audit-ghost-binaries.sh` | Shell script untuk mendeteksi *ghost binary* (proses PHP-FPM / Node.js aktif yang masih me-load executable lama di RAM) |

---

## 1. Node.js Brotli Decoder (CVE-2026-111497)

### Masalah
Global `fetch()` bawaan Node.js (ditenagai oleh Undici) secara otomatis mendekompresi respons jika server lawan mengirim header `Content-Encoding: br`. Menyetel request header `Accept-Encoding: identity` **bukan** security boundary, karena dekompresi otomatis dipicu oleh respons server lawan.

### Menjalankan Pengujian
Syarat: Node.js 18+ (direkomendasikan Node.js v22.x).

```bash
npm test
```

Hasil test menunjukkan:
1. Client naif yang mengirim `Accept-Encoding: identity` tetap mendekompresi payload Brotli secara otomatis.
2. Respons dengan stream Brotli malformed memicu unhandled rejection / decompression error di layer native internal Undici.
3. Client defensif (`safeFetchManifest`) menolak header `Content-Encoding: br` sebelum dekompresi native sempat dipanggil.

---

## 2. PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

### Masalah & Mitigasi
Pada worker pool persistent (PHP-FPM / FrankenPHP), request multipart dengan field `PHP_SESSION_UPLOAD_PROGRESS` memicu inisialisasi sesi sebelum kode router berjalan. Jika terjadi kondisi OOM (Out-of-Memory), abort via `longjmp()` meninggalkan pointer memori yang tidak terinisialisasi bersih, yang kemudian dieksekusi oleh request berikutnya pada worker yang sama.

Mematikan `session.upload_progress.enabled = 0` di `php.ini` adalah **mitigasi darurat (blast-radius reduction)** untuk menutup vektor multipart, namun solusi permanen tetap memerlukan pembaruan binary PHP ke versi patch (`8.2.35`, `8.3.36`, `8.4.27`, atau `8.5.12`).

### Menjalankan Audit PHP
```bash
php tests/php/upload_progress_test.php
```

---

## 3. Deteksi Ghost Binary di Server Production

Sering kali tim melakukan update package (`apt upgrade`, `brew upgrade`) atau deploy container baru tanpa me-restart master process, sehingga proses worker yang berjalan di RAM tetap menggunakan inode file lama yang sudah berstatus `(deleted)`.

Jalankan script audit:
```bash
bash scripts/audit-ghost-binaries.sh
```

---

## Lisensi
MIT License. Dibuat oleh [Nextmend](https://nextmend.dev/?utm_source=github&utm_medium=readme&utm_campaign=artikel-runtime).
