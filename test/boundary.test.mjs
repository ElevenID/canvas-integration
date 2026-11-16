// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const run = promisify(execFile);
test('reviewed runtime passes the boundary gate', async () => {
  const result = await run('python3', ['scripts/check_boundary.py']);
  assert.match(result.stdout, /Boundary check passed/);
});
for (const mutation of ['internal-package', 'alternate-http', 'dynamic-network', 'dependency', 'browser-export', 'extra-module', 'tls-bypass', 'inbound-outbound', 'inbound-host', 'inbound-shutdown']) {
  test(`boundary gate rejects regression: ${mutation}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'canvas-boundary-'));
    try {
      for (const path of ['src', 'bin', 'scripts', 'package.json', 'package-lock.json']) {
        await cp(path, join(directory, path), { recursive: true });
      }
      const file = join(directory, 'src/operations.mjs');
      if (mutation === 'internal-package') await writeFile(file, "import internal from 'marty-issuance-service';\n");
      if (mutation === 'alternate-http') await writeFile(file, "import { request } from 'node:http';\n");
      if (mutation === 'dynamic-network') await writeFile(file, "const net = await import('node:net');\n");
      if (mutation === 'extra-module') await writeFile(join(directory, 'src/bypass.mjs'), '// unreviewed runtime\n');
      if (mutation.startsWith('inbound-')) {
        const path = join(directory, 'src/connector-https-service.mjs');
        let source = await readFile(path, 'utf8');
        if (mutation === 'inbound-outbound') source += "\nimport { request } from 'node:https';\n";
        if (mutation === 'inbound-host') source = source.replace('hosts[0] !== origin.host', 'false');
        if (mutation === 'inbound-shutdown') source = source.replace('await Promise.allSettled([...inFlight])', 'void 0');
        await writeFile(path, source);
      }
      if (mutation === 'tls-bypass') {
        const client = join(directory, 'src/gateway-client.mjs');
        await writeFile(client, (await readFile(client, 'utf8')).replace('rejectUnauthorized: true', 'rejectUnauthorized: false'));
      }
      if (mutation === 'dependency' || mutation === 'browser-export') {
        const path = join(directory, 'package.json');
        const pkg = JSON.parse(await readFile(path, 'utf8'));
        if (mutation === 'dependency') pkg.dependencies = { 'marty-internal': '*' };
        else pkg.exports['.'].browser = './src/gateway-client.mjs';
        await writeFile(path, JSON.stringify(pkg));
      }
      await assert.rejects(run('python3', ['scripts/check_boundary.py'], { cwd: directory }), actual => {
        assert.match(actual.stderr, /Boundary check failed/); return true;
      });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
