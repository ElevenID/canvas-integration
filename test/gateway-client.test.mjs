// SPDX-License-Identifier: AGPL-3.0-only
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { mkdtemp, readFile, rm, writeFile, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createGatewayClient, GatewayError } from '../src/gateway-client.mjs';
import { loadConfiguration } from '../src/configuration.mjs';
import { OPERATIONS, READ_OPERATIONS } from '../src/operations.mjs';

const run = promisify(execFile);
const KEY = 'synthetic_gateway_test_key_0000000000000001';
const ORG = 'synthetic-org-one';
let directory, server, base, certificate, seen = [], handler;
before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'canvas-gateway-test-'));
  const key = join(directory, 'key.pem');
  const cert = join(directory, 'cert.pem');
  await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost']);
  certificate = await readFile(cert, 'utf8');
  server = createServer({ key: await readFile(key), cert: certificate }, async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const record = { method: request.method, url: request.url, headers: request.headers,
      body: Buffer.concat(chunks).toString('utf8') };
    seen.push(record);
    handler(record, response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `https://localhost:${server.address().port}`;
});
after(async () => {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
});
const client = (extra = {}) => createGatewayClient({ gatewayOrigin: base, organizationId: ORG,
  apiKey: KEY, ca: certificate, ...extra });
function reply(value, status = 200) {
  seen = [];
  handler = (_request, response) => {
    response.writeHead(status, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(value));
  };
}
function error(code) {
  return actual => {
    assert.ok(actual instanceof GatewayError);
    assert.equal(actual.code, code);
    assert.ok(!actual.message.includes(KEY));
    assert.ok(!actual.message.includes(base));
    return true;
  };
}

// Expected routes are literal source contracts, not generated from the registry under test.
const reads = [
  ['listCanvasPlatforms', `/v1/integrations/canvas/platforms?organization_id=${ORG}`, undefined, []],
  ['getCanvasPlatform', '/v1/integrations/canvas/platforms/id-one', 'id-one', {}],
  ['getCanvasLtiRegistrationConfig', '/v1/integrations/canvas/platforms/id-one/registration-config', 'id-one', {}],
  ['getCanvasPlatformReadiness', '/v1/integrations/canvas/platforms/id-one/readiness', 'id-one', {}],
  ['listCanvasProgramBindings', `/v1/integrations/canvas/program-bindings?organization_id=${ORG}`, undefined, []],
  ['getCanvasProgramBinding', '/v1/integrations/canvas/program-bindings/id-one', 'id-one', {}],
  ['getCanvasSyncJob', '/v1/integrations/canvas/canvas-sync-jobs/id-one', 'id-one', {}],
  ['listCanvasSyncJobs', `/v1/integrations/canvas/canvas-sync-jobs?organization_id=${ORG}`, undefined, []],
  ['listCanvasAwardCandidates', `/v1/integrations/canvas/canvas-award-candidates?organization_id=${ORG}`, undefined, []],
  ['listCanvasEvidencePolicyReviews', `/v1/integrations/canvas/evidence-policy-reviews?organization_id=${ORG}`, undefined, []],
  ['getCanvasMirrorProvenance', `/v1/issuance/delivery-records/canvas-credentials/provenance?organization_id=${ORG}`, undefined, {}],
  ['getCanvasMirrorHealth', `/v1/issuance/organizations/${ORG}/canvas-mirror-health`, undefined, {}],
];
for (const [name, path, id, result] of reads) test(`API-key-only HTTPS read: ${name}`, async () => {
  reply(result);
  assert.deepEqual(await client().execute(name, id ? { id } : {}), result);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, 'GET');
  assert.equal(seen[0].url, path);
  assert.equal(seen[0].headers['x-api-key'], KEY);
  assert.equal(seen[0].headers['x-organization-id'], ORG);
  assert.equal(seen[0].headers.authorization, undefined);
  assert.equal(seen[0].headers.cookie, undefined);
});
const writes = [
  ['createCanvasPlatform', 'POST', `/v1/integrations/canvas/platforms?organization_id=${ORG}`, undefined, { display_name: 'Synthetic' }, true],
  ['updateCanvasPlatform', 'PUT', '/v1/integrations/canvas/platforms/id-one', 'id-one', { enabled: false }],
  ['finalizeCanvasLtiInstallation', 'PUT', '/v1/integrations/canvas/platforms/id-one/lti-installation', 'id-one', { lti_client_id: 'synthetic' }],
  ['deleteCanvasPlatform', 'DELETE', '/v1/integrations/canvas/platforms/id-one', 'id-one'],
  ['createCanvasProgramBinding', 'POST', `/v1/integrations/canvas/platforms/id-one/program-bindings?organization_id=${ORG}`, 'id-one', { display_name: 'Synthetic' }, true],
  ['updateCanvasProgramBinding', 'PUT', '/v1/integrations/canvas/program-bindings/id-one', 'id-one', { display_name: 'Synthetic' }],
  ['deleteCanvasProgramBinding', 'DELETE', '/v1/integrations/canvas/program-bindings/id-one', 'id-one'],
  ['validateCanvasProgramBinding', 'POST', '/v1/integrations/canvas/program-bindings/id-one/validate', 'id-one', {}],
  ['activateCanvasProgramBinding', 'POST', '/v1/integrations/canvas/program-bindings/id-one/activate', 'id-one', {}],
  ['deactivateCanvasProgramBinding', 'POST', '/v1/integrations/canvas/program-bindings/id-one/deactivate', 'id-one', {}],
];
for (const [name, method, path, id, body, idempotent] of writes) test(`explicit management permission: ${name}`, async () => {
  reply({ accepted: true });
  const args = { ...(id ? { id } : {}), ...(body ? { body } : {}),
    ...(idempotent ? { idempotencyKey: 'synthetic-stable-request-0001' } : {}) };
  await assert.rejects(client().execute(name, args), error('operation_not_allowed'));
  assert.equal(seen.length, 0);
  await client({ allowedOperations: [name] }).execute(name, args);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, method);
  assert.equal(seen[0].url, path);
  assert.equal(seen[0].body, body ? JSON.stringify(body) : '');
  assert.equal(seen[0].headers['idempotency-key'], idempotent ? 'synthetic-stable-request-0001' : undefined);
});

test('literal tests cover every operation, and reads are the only default', () => {
  assert.deepEqual(new Set(Object.keys(OPERATIONS)), new Set([...reads, ...writes].map(row => row[0])));
  assert.deepEqual(new Set(READ_OPERATIONS), new Set(reads.map(row => row[0])));
});
for (const name of ['approve', 'sign', 'createCanvasIntegrationSecret', 'resolveCanvasEvidencePolicyReview',
  'runCanvasMirrorAutomationCycle', '/internal/issuance', 'https://example.test', 'toString']) {
  test(`unavailable authority cannot be opted into: ${name}`, () => {
    assert.throws(() => client({ allowedOperations: [name] }), error('invalid_operations'));
  });
}
for (const invalid of ['http://localhost', 'https://user:pass@example.test', 'https://example.test/internal',
  'https://example.test/?token=secret', 'https://example.test/#frag', 'https://issuance:8000',
  'https://api.namespace.svc.cluster.local', 'https://169.254.169.254', ' https://example.test',
  'https://example.test\\@evil.test']) {
  test(`reject invalid Gateway origin: ${invalid}`, () => {
    assert.throws(() => client({ gatewayOrigin: invalid }), error('invalid_gateway_origin'));
  });
}
for (const id of ['..', '.', '../foreign', '%2f', 'foreign/path', 'https://example.test', '', '\r\n']) {
  test(`reject resource traversal: ${JSON.stringify(id)}`, async () => {
    reply({});
    await assert.rejects(client().execute('getCanvasPlatform', { id }), error('invalid_resource_id'));
    assert.equal(seen.length, 0);
  });
}
test('caller cannot replace organization, credentials, origin or transport', async () => {
  reply([]);
  for (const args of [{ organizationId: 'other' }, { headers: { 'X-API-Key': KEY } }, { url: base }, { method: 'POST' }]) {
    await assert.rejects(client().execute('listCanvasPlatforms', args), error('invalid_arguments'));
  }
  await assert.rejects(client().execute('listCanvasPlatforms', { query: { organization_id: 'other' } }), error('invalid_query'));
  assert.throws(() => client({ rejectUnauthorized: false }), error('invalid_configuration'));
  assert.throws(() => client({ fetch: () => {} }), error('invalid_configuration'));
  assert.equal(seen.length, 0);
});
test('body cannot smuggle organization, issuer keys or JSON hooks', async () => {
  reply({});
  const scoped = client({ allowedOperations: ['updateCanvasProgramBinding'] });
  for (const body of [{ organization_id: 'other' }, { issuer_key: 'private' },
    { canvas_scope: { organization_id: 'other' } }, { canvas_scope: { toJSON() { return {}; } } },
    { canvas_scope: JSON.parse('{"__proto__":{"polluted":true}}') }]) {
    await assert.rejects(scoped.execute('updateCanvasProgramBinding', { id: 'binding', body }), error('invalid_body'));
  }
  assert.equal(seen.length, 0);
});
test('list response normalization does not silently hide schema failures', async () => {
  reply({ items: [{ id: 'synthetic' }] });
  assert.deepEqual(await client().execute('listCanvasSyncJobs'), [{ id: 'synthetic' }]);
  reply({ error: 'not a list' });
  await assert.rejects(client().execute('listCanvasSyncJobs'), error('invalid_response_shape'));
});
test('creates require stable caller-supplied idempotency; no automatic retry', async () => {
  reply({ id: 'synthetic' });
  const scoped = client({ allowedOperations: ['createCanvasPlatform'] });
  await assert.rejects(scoped.execute('createCanvasPlatform', { body: {} }), error('idempotency_key_required'));
  assert.equal(seen.length, 0);
  const args = { body: { display_name: 'Synthetic' }, idempotencyKey: 'stable-client-request-0001' };
  await scoped.execute('createCanvasPlatform', args);
  await scoped.execute('createCanvasPlatform', args);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].headers['idempotency-key'], seen[1].headers['idempotency-key']);
  reply({ error: KEY }, 503);
  await assert.rejects(scoped.execute('createCanvasPlatform', args), actual => {
    error('gateway_rejected')(actual); assert.equal(actual.status, 503); return true;
  });
  assert.equal(seen.length, 1);
});
for (const status of [301, 302, 303, 307, 308]) test(`redirect ${status} never forwards the key`, async () => {
  seen = [];
  handler = (_request, response) => {
    response.writeHead(status, { Location: 'https://example.invalid/key-theft' });
    response.end();
  };
  await assert.rejects(client().execute('listCanvasPlatforms'), error('redirect_denied'));
  assert.equal(seen.length, 1);
});
for (const status of [401, 403, 429, 500]) test(`upstream ${status} is preserved without echoing sensitive errors`, async () => {
  reply({ detail: `${KEY} private-fixture-payload` }, status);
  await assert.rejects(client().execute('listCanvasPlatforms'), actual => {
    error('gateway_rejected')(actual); assert.equal(actual.status, status);
    assert.ok(!JSON.stringify(actual).includes(KEY)); return true;
  });
});
test('invalid TLS chain fails before any authenticated HTTP request', async () => {
  reply([]);
  await assert.rejects(client({ ca: undefined }).execute('listCanvasPlatforms'), error('transport_error'));
  assert.equal(seen.length, 0);
});
test('TLS hostname verification cannot be disabled', async () => {
  reply([]);
  await assert.rejects(client({ gatewayOrigin: base.replace('localhost', '127.0.0.1') }).execute('listCanvasPlatforms'), error('transport_error'));
  assert.equal(seen.length, 0);
});
test('oversized response aborts the request', async () => {
  reply([{ value: 'x'.repeat(2000) }]);
  await assert.rejects(client({ maxResponseBytes: 128 }).execute('listCanvasPlatforms'), error('response_too_large'));
});
test('slow streaming body is bounded by absolute deadline', async () => {
  handler = (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.write('[');
    const interval = setInterval(() => response.write(' '), 10);
    response.on('close', () => clearInterval(interval));
  };
  await assert.rejects(client({ timeoutMs: 80 }).execute('listCanvasPlatforms'), error('timeout'));
});
test('unsupported content type and malformed JSON fail closed', async () => {
  for (const [type, body, code] of [['text/html', '<html>login</html>', 'invalid_content_type'],
    ['application/json', '{broken', 'invalid_json'], ['application/json', Buffer.from([0xff]), 'invalid_json']]) {
    handler = (_request, response) => { response.writeHead(200, { 'Content-Type': type }); response.end(body); };
    await assert.rejects(client().execute('listCanvasPlatforms'), error(code));
  }
});
test('optional deletion accepts 204', async () => {
  handler = (_request, response) => { response.writeHead(204); response.end(); };
  assert.equal(await client({ allowedOperations: ['deleteCanvasPlatform'] }).execute('deleteCanvasPlatform', { id: 'synthetic' }), null);
});
test('keys are absent from serialization and browser import is blocked', async () => {
  assert.equal(JSON.stringify(client()), '{}');
  await assert.rejects(run(process.execPath, ['--conditions=browser', '--input-type=module', '-e',
    "await import('@elevenid/canvas-integration')"]), actual => {
      assert.match(actual.stderr, /server-only/); return true;
    });
});
test('key files are private, non-symlink regular files with redacted errors', async () => {
  const path = join(directory, 'api-key');
  await writeFile(path, `${KEY}\n`, { mode: 0o600 });
  const environment = { MARTY_GATEWAY_ORIGIN: base, MARTY_ORGANIZATION_ID: ORG, MARTY_GATEWAY_API_KEY_FILE: path };
  assert.equal((await loadConfiguration(environment)).apiKey, KEY);
  await chmod(path, 0o644);
  await assert.rejects(loadConfiguration(environment), error('invalid_key_file'));
  await chmod(path, 0o600);
  const link = join(directory, 'link'); await symlink(path, link);
  await assert.rejects(loadConfiguration({ ...environment, MARTY_GATEWAY_API_KEY_FILE: link }), error('invalid_key_file'));
  await assert.rejects(loadConfiguration({ ...environment, MARTY_GATEWAY_API_KEY: KEY }), error('key_file_required'));
});
for (const name of ['DATABASE_URL', 'REDIS_URL', 'ISSUANCE_API_KEY', 'ISSUANCE_API_KEY_FILE',
  'SIGNING_KEYS_INTERNAL_URL', 'SIGNING_KEYS_ISSUER_SIGN_KEY', 'BAO_TOKEN', 'INTEGRATION_SECRET_MASTER_KEY']) {
  test(`CLI configuration refuses inherited internal authority: ${name}`, async () => {
    await assert.rejects(loadConfiguration({ [name]: 'synthetic' }), error('internal_configuration_forbidden'));
  });
}
test('read-only CLI executes against real TLS fixture and emits only a summary', async () => {
  reply([{ id: 'synthetic-private-record', display_name: 'synthetic-private-name' }]);
  const path = join(directory, 'cli-key'); await writeFile(path, KEY, { mode: 0o600 });
  const result = await run(process.execPath, ['bin/probe.mjs'], { env: { PATH: process.env.PATH,
    MARTY_GATEWAY_ORIGIN: base, MARTY_ORGANIZATION_ID: ORG, MARTY_GATEWAY_API_KEY_FILE: path,
    MARTY_GATEWAY_CA_FILE: join(directory, 'cert.pem') } });
  assert.deepEqual(JSON.parse(result.stdout), { gatewayAccess: 'verified', operation: 'listCanvasPlatforms', count: 1 });
  assert.equal(result.stderr, '');
  assert.ok(!result.stdout.includes(KEY));
  assert.ok(!result.stdout.includes('synthetic-private'));
  assert.equal(seen.length, 1);
});
