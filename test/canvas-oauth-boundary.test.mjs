// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const run = promisify(execFile);
const mutations = [
  ['oauth-tls-bypass', 'src/canvas-oauth-provider.mjs', source => source.replace('rejectUnauthorized: true', 'rejectUnauthorized: false')],
  ['oauth-unpinned-dns', 'src/canvas-oauth-provider.mjs', source => source.replace('lookup: pinnedLookup', 'lookup: unreviewedLookup')],
  ['oauth-core-import', 'src/canvas-oauth.mjs', source => source + "\nimport { createGatewayClient } from './gateway-client.mjs';\n"],
  ['oauth-state-hash-removed', 'src/canvas-oauth.mjs', source => source.replace('stateHash: stateHash(state),', 'stateHash: state,')],
  ['oauth-one-time-consume-removed', 'src/canvas-oauth.mjs', source => source.replace('repository.consumeAuthorization', 'repository.readAuthorization')],
];

for (const [name, path, mutate] of mutations) {
  test(`architecture gate rejects ${name}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'canvas-oauth-boundary-'));
    try {
      for (const item of ['src', 'bin', 'scripts', 'package.json', 'package-lock.json']) {
        await cp(item, join(directory, item), { recursive: true });
      }
      const target = join(directory, path);
      const original = await readFile(target, 'utf8');
      const changed = mutate(original);
      assert.notEqual(changed, original);
      await writeFile(target, changed);
      await assert.rejects(run('python3', ['scripts/check_boundary.py'], { cwd: directory }), error => {
        assert.match(error.stderr, /Boundary check failed/);
        return true;
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}

test('architecture gate rejects a browser-visible OAuth export', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'canvas-oauth-browser-boundary-'));
  try {
    for (const item of ['src', 'bin', 'scripts', 'package.json', 'package-lock.json']) {
      await cp(item, join(directory, item), { recursive: true });
    }
    const path = join(directory, 'package.json');
    const pkg = JSON.parse(await readFile(path, 'utf8'));
    pkg.exports['./canvas-oauth'].browser = './src/canvas-oauth.mjs';
    await writeFile(path, JSON.stringify(pkg));
    await assert.rejects(run('python3', ['scripts/check_boundary.py'], { cwd: directory }), error => {
      assert.match(error.stderr, /Boundary check failed/);
      return true;
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
