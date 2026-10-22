import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { naiveFetchManifest, safeFetchManifest } from '../../src/node/manifest-fetcher.mjs';

describe('Integrasi Logistik: Outbound Fetch & Celah Brotli Decoder (CVE-2026-111497)', () => {
  let server;
  let serverUrl;

  before(async () => {
    const validJson = JSON.stringify({
      orderId: 'ORD-9821-JKT',
      trackingNumber: 'NXT-LOG-882910',
      status: 'MANIFEST_CREATED',
      items: [{ sku: 'KEYBOARD-MECH-01', qty: 1 }],
    });
    const validBrotli = zlib.brotliCompressSync(Buffer.from(validJson));

    // Malformed Brotli payload yang bukan stream valid
    const malformedBrotli = Buffer.from('malformed non-brotli byte stream triggering decoder failure');

    server = http.createServer((req, res) => {
      const url = req.url;

      if (url === '/manifest/valid-clean') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
        });
        res.end(validJson);
        return;
      }

      if (url === '/manifest/valid-brotli') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Encoding': 'br',
        });
        res.end(validBrotli);
        return;
      }

      if (url === '/manifest/malformed-brotli') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Encoding': 'br',
        });
        res.end(malformedBrotli);
        return;
      }

      res.writeHead(404);
      res.end('Not Found');
    });

    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        serverUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  after((done) => {
    server.close(done);
  });

  test('Fakta: Client naif mengirim Accept-Encoding: identity, tetapi tetap mendekompresi br secara otomatis', async () => {
    // Client mengirim `Accept-Encoding: identity`, namun server membalas `Content-Encoding: br`
    const result = await naiveFetchManifest(`${serverUrl}/manifest/valid-brotli`);
    
    // Bukti: Undici mendekompresi respons secara implisit
    assert.equal(result.orderId, 'ORD-9821-JKT');
    assert.equal(result.trackingNumber, 'NXT-LOG-882910');
  });

  test('Kegagalan: Payload Brotli rusak memicu kegagalan dekompresi internal di Undici fetch()', async () => {
    await assert.rejects(
      async () => {
        await naiveFetchManifest(`${serverUrl}/manifest/malformed-brotli`);
      },
      (err) => {
        // Pada Node.js dengan Undici, error dekompresi melempar TypeError: terminated
        // dengan cause Error: Decompression failed dari BrotliDecoder.zlibOnError
        assert.ok(
          err.name === 'TypeError' ||
          err.message.includes('fetch failed') ||
          err.message.includes('terminated') ||
          err.cause?.message?.includes('Decompression failed'),
          `Error tidak terduga: ${err.message}`
        );
        return true;
      }
    );
  });

  test('Perbaikan Defensif: safeFetchManifest() menolak respons Content-Encoding: br sebelum dekompresi', async () => {
    await assert.rejects(
      async () => {
        await safeFetchManifest(`${serverUrl}/manifest/malformed-brotli`);
      },
      (err) => {
        assert.ok(
          err.message.includes('[SECURITY_VIOLATION] Unexpected Content-Encoding \'br\''),
          `Pesan error defensif: ${err.message}`
        );
        return true;
      }
    );
  });

  test('Perbaikan Defensif: safeFetchManifest() memproses payload JSON bersih tanpa masalah', async () => {
    const result = await safeFetchManifest(`${serverUrl}/manifest/valid-clean`);
    assert.equal(result.orderId, 'ORD-9821-JKT');
    assert.equal(result.status, 'MANIFEST_CREATED');
  });
});
