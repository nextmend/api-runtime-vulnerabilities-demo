<?php

/**
 * Demonstrasi & Verifikasi Mitigasi PHP2Shell (CVE-2026-109618 & CVE-2026-109619)
 * Simulasi Persistent Worker PHP-FPM & Cross-Request Memory Exposure
 * 
 * Artikel: Celah Runtime di Integrasi API: Membedah PHP2Shell dan Brotli Node.js
 * Nextmend (https://nextmend.dev)
 */

echo "============================================================\n";
echo "  AUDIT RUNTIME PHP & SIMULASI CROSS-REQUEST WORKER POOL    \n";
echo "============================================================\n\n";

$currentPid = getmypid();
$currentVersion = PHP_VERSION;
$versionParts = explode('.', $currentVersion);
$majorMinor = $versionParts[0] . '.' . $versionParts[1];

$patchedVersions = [
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
];

// 1. Audit Versi Binary
echo "[1] Audit Versi Binary PHP (Host / Worker Process):\n";
echo "    PID Worker Aktif : $currentPid\n";
echo "    Versi Runtime    : PHP $currentVersion\n";

if (isset($patchedVersions[$majorMinor])) {
    $targetVersion = $patchedVersions[$majorMinor];
    $isPatched = version_compare($currentVersion, $targetVersion, '>=');
    if ($isPatched) {
        echo "    Status Patch     : [AMAN] Versi binary sudah >= $targetVersion\n";
    } else {
        echo "    Status Patch     : [RENTAN] Versi di bawah $targetVersion!\n";
        echo "    Rekomendasi      : Wajib upgrade ke PHP $targetVersion atau lebih baru.\n";
    }
} else {
    echo "    Status Patch     : [EOL] PHP $majorMinor sudah EOL dan rentan.\n";
}

echo "\n------------------------------------------------------------\n";

// 2. Audit Konfigurasi INI
echo "[2] Audit Konfigurasi session.upload_progress:\n";
$uploadProgressEnabled = ini_get('session.upload_progress.enabled');
$uploadProgressName = ini_get('session.upload_progress.name');
echo "    session.upload_progress.enabled : " . ($uploadProgressEnabled ? '1 (On - Default Rawan)' : '0 (Off - Mitigasi Aktif)') . "\n";
echo "    session.upload_progress.name    : $uploadProgressName\n";

echo "\n------------------------------------------------------------\n";

// 3. Simulasi 2 Request Beruntun pada Persistent Worker yang Sama
echo "[3] Simulasi 2 Request Konsekutif pada Worker PHP-FPM yang Sama (PID: $currentPid):\n\n";

function simulatePersistentWorkerLifecycle(int $pid, bool $progressEnabled): void
{
    echo "--- REQUEST #1: Attacker mengirim payload multipart khusus ---\n";
    echo "[Worker PID $pid] Menerima koneksi FastCGI dari Nginx...\n";
    echo "[Worker PID $pid] Header: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX\n";
    echo "[Worker PID $pid] Body membawa field: PHP_SESSION_UPLOAD_PROGRESS = 'payload_alloc_marker'\n";
    
    if ($progressEnabled) {
        echo "[Worker PID $pid] [SAPI Hook] session.upload_progress AKTIF: SAPI langsung menginisialisasi sesi!\n";
        echo "[Worker PID $pid] [SAPI Hook] Mengalokasikan tracking struct & pointer di heap worker.\n";
        echo "[Worker PID $pid] [Aplikasi] Request masuk ke router / FormRequest.\n";
        echo "[Worker PID $pid] [Aplikasi] Validasi controller gagal: endpoint hanya menerima JSON.\n";
        echo "[Worker PID $pid] [Aplikasi] Membalas HTTP 415 Unsupported Media Type.\n";
        echo "[Worker PID $pid] [BAHAYA - CVE-2026-109618/19] Jika terjadi abort OOM via longjmp(),\n";
        echo "                  pointer tracking struct tertinggal sebagai dangling/stale pointer di worker heap!\n";
    } else {
        echo "[Worker PID $pid] [SAPI Hook] session.upload_progress = 0 (Off): SAPI melewati hook sepenuhnya.\n";
        echo "[Worker PID $pid] [Aplikasi] Router membalas HTTP 415 tanpa ada inisialisasi sesi liar di heap.\n";
    }

    echo "\n--- REQUEST #2: Pembeli / Mitra Ekspedisi mengirim webhook JSON sah ---\n";
    echo "[Worker PID $pid] Worker yang SAMA (PID $pid) melayani request berikutnya...\n";
    echo "[Worker PID $pid] Header: Content-Type: application/json\n";
    echo "[Worker PID $pid] Body: {\"order_id\": \"ORD-9821-JKT\", \"status\": \"DELIVERED\"}\n";
    
    if ($progressEnabled) {
        echo "[Worker PID $pid] [EKSPLOITASI CROSS-REQUEST UAF] Worker mengeksekusi request baru di atas\n";
        echo "                  heap yang masih menyimpan pointer usang dari Request #1.\n";
        echo "[Worker PID $pid] Dampak di Production: Pembacaan memori acak (kebocoran DB password / token)\n";
        echo "                  atau kontrol instruksi proses (Remote Code Execution) di bawah user www-data.\n";
    } else {
        echo "[Worker PID $pid] [AMAN DARI VEKTOR UPLOAD PROGRESS] Worker bersih dari alokasi upload progress.\n";
    }
}

echo "SKENARIO A: Konfigurasi Default (session.upload_progress.enabled = 1)\n";
simulatePersistentWorkerLifecycle($currentPid, true);

echo "\n------------------------------------------------------------\n";
echo "SKENARIO B: Konfigurasi Hardened (session.upload_progress.enabled = 0)\n";
simulatePersistentWorkerLifecycle($currentPid, false);

echo "\n------------------------------------------------------------\n";
echo "[4] Kesimpulan Arsitektur:\n";
echo "    - Webhook JSON yang menolak multipart (HTTP 415) TETAP memicu SAPI hook jika upload_progress On.\n";
echo "    - Mematikan session.upload_progress.enabled = 0 berhasil memotong vektor multipart (CVE-2026-109619).\n";
echo "    - Tetapi celah pembersihan OOM core PHP (CVE-2026-109618) hanya bisa ditutup tuntas dengan\n";
echo "      meng-upgrade binary ke versi resmi (>= $patchedVersions[$majorMinor]) dan me-restart service master.\n\n";

echo "=== Selesai ===\n";
