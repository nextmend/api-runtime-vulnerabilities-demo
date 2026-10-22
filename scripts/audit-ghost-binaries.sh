#!/usr/bin/env bash

# Audit Script: Mendeteksi Ghost Binary (Proses PHP-FPM & Node.js yang masih menjalankan binary lama di RAM)
# Nextmend (https://nextmend.dev)

set -eo pipefail

echo "============================================================"
echo "  AUDIT GHOST BINARY: DETEKSI RUNTIME UNPATCHED DI MEMORI   "
echo "============================================================"
echo

OS="$(uname -s)"
echo "[i] Sistem Operasi terdeteksi: $OS"

FOUND_GHOST=0

if [ "$OS" = "Linux" ]; then
    echo "[i] Memeriksa /proc/*/exe untuk binary yang sudah dihapus/ditimpa (deleted)..."
    
    # Periksa link executable di /proc
    DELETED_PROCS=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '(php|node).*\(deleted\)' || true)
    
    if [ -n "$DELETED_PROCS" ]; then
        echo "🚨 PERINGATAN: Ditemukan proses yang masih menjalankan binary usang di RAM:"
        echo "$DELETED_PROCS" | awk '{print "   PID: " $9 " -> " $11}'
        FOUND_GHOST=1
    else
        echo "✅ Tidak ada link /proc/*/exe berstatus '(deleted)' pada proses php/node."
    fi

    # Pemeriksaan kedua lewat lsof jika terpasang
    if command -v lsof >/dev/null 2>&1; then
        echo "[i] Memeriksa open file descriptors via lsof..."
        LSOF_GHOST=$(lsof -nP 2>/dev/null | grep -E '(php-fpm|php|node)' | grep '(deleted)' || true)
        if [ -n "$LSOF_GHOST" ]; then
            echo "🚨 lsof mendeteksi library atau binary deleted yang masih ditahan proses:"
            echo "$LSOF_GHOST" | head -n 10 | awk '{print "   " $1 " (PID " $2 ") holding deleted file: " $9}'
            FOUND_GHOST=1
        fi
    fi
else
    echo "[i] Menjalankan pemeriksaan proses aktif (macOS / BSD)..."
    ACTIVE_PROCS=$(ps aux | grep -E '(php-fpm|php|node)' | grep -v 'grep' || true)
    
    if [ -n "$ACTIVE_PROCS" ]; then
        echo "ℹ️  Proses PHP / Node.js aktif yang ditemukan:"
        echo "$ACTIVE_PROCS" | awk '{print "   PID: " $2 " | COMMAND: " $11 " " $12}'
        echo "ℹ️  Pastikan me-restart proses-proses di atas setelah melakukan update runtime via brew/package manager."
    else
        echo "✅ Tidak ada proses PHP/Node background yang terdeteksi aktif saat ini."
    fi
fi

echo
echo "------------------------------------------------------------"
if [ "$FOUND_GHOST" -eq 1 ]; then
    echo "❌ KESIMPULAN: Ditemukan ghost binary aktif!"
    echo "   Binary di disk sudah diperbarui, tetapi proses di RAM MASIH VERSI LAMA."
    echo "   Tindakan Wajib:"
    echo "   1. Restart service PHP-FPM:  sudo systemctl restart php-fpm (atau php8.4-fpm)"
    echo "   2. Restart worker Node.js:   pm2 restart all / docker compose restart"
    exit 1
else
    echo "✅ KESIMPULAN: Tidak ditemukan proses ghost binary yang tertahan."
    echo "   Pastikan kebijakan deployment Anda selalu menyertakan restart service otomatis."
    exit 0
fi
