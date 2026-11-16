// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, chmod, symlink } from 'node:fs/promises';
import { resolve, dirname, basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { loadConnectorOAuthConfiguration } from '../src/oauth-service-config.mjs';
const run = promisify(execFile), posix = process.platform !== 'win32';
const denied = { message: 'connector_service_configuration_unavailable' };
async function fixture(t) {
  const root = resolve(tmpdir()), directory = await mkdtemp(join(root, 'canvas-service-config-'));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), root); assert.ok(basename(directory).startsWith('canvas-service-config-'));
    await rm(directory, { recursive: true, force: true });
  });
  const names = ['password', 'token', 'ca', 'key', 'certificate'];
  const values = ['synthetic database password', 'hvs.synthetic_scoped_token_000001', 'synthetic CA\n', 'synthetic private TLS key\n', 'synthetic certificate\n'];
  const files = Object.fromEntries(names.map(name => [name, join(directory, name)]));
  for (let i = 0; i < names.length; i++) await writeFile(files[names[i]], values[i], { mode: 0o600 });
  const path = join(directory, 'configuration.json');
  const configuration = { schemaVersion: 1,
    database: { host: 'database.example.test', port: 5432, database: 'connector', user: 'connector_http',
      passwordFile: files.password, caFile: files.ca },
    keyCustody: { openbaoOrigin: 'https://vault.example.test', mount: 'connector-kv', keyPath: 'canvas-envelope', keyNamespace: 'canvas', tokenFile: files.token },
    gatewayAuthentication: { gatewayOrigin: 'https://gateway.example.test', sessionCookieName: 'session' },
    http: { publicOrigin: 'https://connector.example.test', completionUrl: 'https://connector.example.test/complete',
      tlsKeyFile: files.key, tlsCertificateFile: files.certificate },
  };
  await writeFile(path, JSON.stringify(configuration), { mode: 0o600 });
  return { path, configuration, files };
}

test('private configuration maps separate file providers and TLS without ambient credential fallback', { skip: !posix }, async t => {
  const f = await fixture(t); const result = await loadConnectorOAuthConfiguration({ path: f.path });
  assert.equal(await result.database.credentialProvider.getPassword(), 'synthetic database password');
  assert.equal(await result.keyCustody.tokenProvider.getToken(), 'hvs.synthetic_scoped_token_000001');
  assert.equal(result.http.tls.key, 'synthetic private TLS key\n');
  assert.equal(result.database.ca, 'synthetic CA\n'); assert.equal(result.gatewayAuthentication.ca, undefined);
  assert.equal(result.database.passwordFile, undefined); assert.equal(result.keyCustody.tokenFile, undefined);
  assert.deepEqual(result.canvas, {});
});

test('unknown fields, raw credentials, missing versions and reused secret paths are rejected', { skip: !posix }, async t => {
  const f = await fixture(t);
  for (const change of [v => { delete v.schemaVersion; }, v => { v.schemaVersion = 2; },
    v => { v.database.password = 'plaintext'; }, v => { v.keyCustody.token = 'plaintext'; },
    v => { v.gatewayAuthentication.apiKey = 'forbidden'; }, v => { v.http.tls = { key: 'inline' }; },
    v => { v.keyCustody.tokenFile = v.database.passwordFile; }, v => { v.http.tlsKeyFile = f.path; },
    v => { v.database.host = '\ud800'; }]) {
    const configuration = structuredClone(f.configuration); change(configuration);
    await writeFile(f.path, JSON.stringify(configuration));
    await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
  }
});

test('duplicate and escaped keys, deep nesting, prototype fields and malformed JSON are rejected', { skip: !posix }, async t => {
  const f = await fixture(t); const json = JSON.stringify(f.configuration);
  for (const text of [json.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
    json.replace('"host":"database.example.test"', String.raw`"host":"database.example.test","ho\u0073t":"alternate.example.test"`),
    json.replace('{', '{"__proto__":{"polluted":true},'), '['.repeat(17) + 'null' + ']'.repeat(17),
    json.slice(0, -1), '\ufeff' + json]) {
    await writeFile(f.path, text); await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
    assert.equal({}.polluted, undefined);
  }
});

test('configuration, TLS and CA file permissions and cancellation fail closed', { skip: !posix }, async t => {
  const f = await fixture(t);
  await chmod(f.path, 0o644); await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
  await chmod(f.path, 0o600); await chmod(f.files.key, 0o644);
  await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
  await chmod(f.files.key, 0o600); await chmod(f.files.ca, 0o644);
  await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
  await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path, signal: AbortSignal.abort() }), denied);
});

test('parent-directory aliases cannot send one credential to both database and OpenBao', { skip: !posix }, async t => {
  const f = await fixture(t);
  const alias = join(dirname(f.path), 'alias'); await symlink(dirname(f.path), alias, 'dir');
  f.configuration.keyCustody.tokenFile = join(alias, basename(f.files.password));
  await writeFile(f.path, JSON.stringify(f.configuration));
  await assert.rejects(loadConnectorOAuthConfiguration({ path: f.path }), denied);
  f.configuration.keyCustody.tokenFile = join(alias, basename(f.files.token));
  await writeFile(f.path, JSON.stringify(f.configuration));
  const result = await loadConnectorOAuthConfiguration({ path: f.path });
  await rm(alias);
  // Providers retain canonical paths; removing the alias does not redirect them.
  assert.equal(await result.keyCustody.tokenProvider.getToken(), 'hvs.synthetic_scoped_token_000001');
});

for (const [label, args, env] of [['argv', ['forbidden-secret-argument'], {}],
  ['legacy credentials', [], { DATABASE_URL: 'forbidden-secret-uri' }], ['missing configuration', [], {}]]) {
  test(`service entry point rejects ${label} with redacted process output`, async () => {
    await assert.rejects(run(process.execPath, ['bin/serve-oauth.mjs', ...args], {
      env: { PATH: process.env.PATH, ...env }, timeout: 5000,
    }), error => {
      assert.equal(error.code, 1); assert.equal(error.stdout, '');
      assert.deepEqual(JSON.parse(error.stderr), { state: 'failed', code: 'connector_service_startup_failed' }); return true;
    });
  });
}
