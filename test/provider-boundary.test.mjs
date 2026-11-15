// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const run = promisify(execFile);
for (const mutation of ['gateway-import', 'core-key', 'tls-bypass', 'unpinned-dns', 'write-method', 'removed-deadline', 'browser-export']) {
  test(`provider boundary rejects ${mutation}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'canvas-provider-boundary-'));
    try {
      for (const path of ['src', 'bin', 'scripts', 'package.json', 'package-lock.json']) await cp(path, join(directory, path), { recursive: true });
      const path = join(directory, 'src/canvas-rest-reader.mjs');
      let source = await readFile(path, 'utf8');
      if (mutation === 'gateway-import') source += "\nimport { createGatewayClient } from './gateway-client.mjs';\n";
      if (mutation === 'core-key') source = source.replace("'Authorization': `Bearer ${accessToken}`", "'X-API-Key': accessToken");
      if (mutation === 'tls-bypass') source = source.replace('rejectUnauthorized: true', 'rejectUnauthorized: false');
      if (mutation === 'unpinned-dns') source = source.replace('lookup: pinnedLookup', 'lookup: unreviewedLookup');
      if (mutation === 'write-method') source = source.replace("method: 'GET'", "method: 'POST'");
      if (mutation === 'removed-deadline') source = source.replace('controller.abort()', 'undefined');
      if (mutation === 'browser-export') {
        const pkgPath = join(directory, 'package.json');
        const pkg = JSON.parse(await readFile(pkgPath, 'utf8'));
        pkg.exports['./canvas-rest'].browser = './src/canvas-rest-reader.mjs';
        await writeFile(pkgPath, JSON.stringify(pkg));
      }
      await writeFile(path, source);
      await assert.rejects(run('python3', ['scripts/check_boundary.py'], { cwd: directory }), actual => {
        assert.match(actual.stderr, /Boundary check failed/); return true;
      });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
