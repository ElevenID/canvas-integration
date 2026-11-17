// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, access } from 'node:fs/promises';
import { createGatewayClient, GatewayError } from '../src/gateway-client.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

test('retired compatibility API refuses opt-in without reading credentials or making requests', async () => {
  const gateway = await httpsFixture();
  try {
    gateway.setHandler((_req, res) => json(res, []));
    const configuration = { gatewayOrigin: gateway.origin, allowedOperations: ['createCanvasPlatform'], ca: gateway.ca,
      get apiKey() { assert.fail('retired API must not acquire credentials'); } };
    assert.throws(() => createGatewayClient(configuration), error => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, 'retired_gateway_api');
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(gateway.seen.length, 0);
    assert.throws(() => createGatewayClient(), { code: 'retired_gateway_api' });
  } finally { await gateway.close(); }
});

test('retired configuration and probe cannot be imported or invoked as package capabilities', async () => {
  await assert.rejects(import('@elevenid/canvas-integration/configuration'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
  const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.scripts.probe, undefined);
  for (const path of ['../src/operations.mjs', '../src/configuration.mjs', '../bin/probe.mjs']) {
    await assert.rejects(access(new URL(path, import.meta.url)), { code: 'ENOENT' });
  }
});

test('package root remains unavailable to browser consumers', async () => {
  await assert.rejects(promisify(execFile)(process.execPath, ['--conditions=browser', '--input-type=module', '-e',
    "await import('@elevenid/canvas-integration')"]), error => {
    assert.match(error.stderr, /server-only/);
    return true;
  });
});
