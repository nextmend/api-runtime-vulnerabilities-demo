import http from 'node:http';
import https from 'node:https';

/**
 * NAIF: Menggunakan global fetch() bawaan Node.js.
 * 
 * JEBAKAN KEAMANAN:
 * Mengirim header `Accept-Encoding: identity` BUKAN batas keamanan (security boundary).
 * Global fetch() di Node.js (ditenagai oleh Undici) secara otomatis mendekompresi
 * respons jika server lawan membalas dengan header `Content-Encoding: br`.
 * 
 * Jika endpoint pihak ketiga yang terkompromi membalas dengan stream Brotli malformed,
 * native Brotli decoder di C++ (node:zlib) akan otomatis dipanggil dan memicu
 * crash/memory corruption (CVE-2026-111497) sebelum aplikasi sempat memeriksa data.
 */
export async function naiveFetchManifest(manifestUrl, options = {}) {
  const headers = {
    'Accept-Encoding': 'identity', // Developer mengira ini mencegah dekompresi
    ...options.headers,
  };

  const response = await fetch(manifestUrl, {
    method: 'GET',
    headers,
    signal: options.signal,
  });

  // Saat response.json() dipanggil, data yang sudah didekompresi di layer native dibaca
  return await response.json();
}

/**
 * DEFENSIF: Client HTTP berbasis standard library tanpa auto-decompression implisit.
 * 
 * Mitigasi aplikasi sebelum upgrade runtime:
 * 1. Tidak mengizinkan dekompresi otomatis stream yang belum diperiksa.
 * 2. Memeriksa header `Content-Encoding` dan menolak `br` dari server pihak ketiga.
 * 3. Membatasi ukuran stream mentah sebelum diparsing.
 */
export function safeFetchManifest(manifestUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(manifestUrl);
    const client = urlObj.protocol === 'https:' ? https : http;

    const req = client.request(
      urlObj,
      {
        method: options.method || 'GET',
        headers: {
          'Accept': 'application/json',
          'Accept-Encoding': 'identity',
          ...(options.headers || {}),
        },
        timeout: options.timeout || 5000,
      },
      (res) => {
        const encoding = (res.headers['content-encoding'] || '').toLowerCase().trim();
        const contentType = (res.headers['content-type'] || '').toLowerCase();

        // Guard 1: Tolak Content-Encoding terkompresi yang tidak diminta
        if (encoding && encoding !== 'identity') {
          res.resume(); // Buang data stream agar soket tidak hanging
          return reject(
            new Error(
              `[SECURITY_VIOLATION] Unexpected Content-Encoding '${encoding}'. Rejecting untrusted compressed response before decompression.`
            )
          );
        }

        // Guard 2: Validasi Content-Type
        if (!contentType.includes('application/json')) {
          res.resume();
          return reject(
            new Error(
              `[INVALID_CONTENT_TYPE] Expected 'application/json' but received '${contentType}'.`
            )
          );
        }

        let rawData = '';
        let bytesRead = 0;
        const maxBytes = options.maxBytes || 2 * 1024 * 1024; // Maksimal 2MB

        res.setEncoding('utf8');

        res.on('data', (chunk) => {
          bytesRead += Buffer.byteLength(chunk);
          if (bytesRead > maxBytes) {
            res.destroy();
            return reject(
              new Error(`[PAYLOAD_TOO_LARGE] Manifest body exceeds ${maxBytes} bytes limit.`)
            );
          }
          rawData += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(rawData);
            resolve(parsed);
          } catch (err) {
            reject(new Error(`[JSON_PARSE_ERROR] Failed to parse response body: ${err.message}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('[TIMEOUT] Outbound request timed out.'));
    });

    req.end();
  });
}
