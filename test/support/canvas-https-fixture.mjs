// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

export async function httpsFixture({ ipAddressSan = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'canvas-rest-'));
  const run = promisify(execFile);
  try {
    await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'), '-days', '1',
      '-subj', '/CN=localhost', '-addext', ipAddressSan ? 'subjectAltName=DNS:localhost,IP:127.0.0.1' : 'subjectAltName=DNS:localhost']);
    const ca = await readFile(join(directory, 'cert.pem'), 'utf8');
    const key = await readFile(join(directory, 'key.pem'));
    const seen = [];
    let handler = (_req, res) => { res.writeHead(500); res.end(); };
    const server = createServer({ key, cert: ca }, (req, res) => {
      seen.push({ url: req.url, method: req.method, headers: { ...req.headers } });
      handler(req, res);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return { ca, key, origin: `https://localhost:${server.address().port}`, seen,
      setHandler(value) { seen.length = 0; handler = value; },
      async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); } };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}
export function json(res, body, status = 200, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}
