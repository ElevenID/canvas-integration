// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createOAuthAdminHandler } from '../src/oauth-admin-http.mjs';
import { createGatewayAdminAuthenticator } from '../src/gateway-admin-auth.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const origin = 'https://connector.example.test';
const form = 'client_id=client&client_secret_ref=opaque-ref&capabilities=catalog';
async function fixture(t, overrides = {}) {
  const calls = [];
  const server = createServer(createOAuthAdminHandler({
    adminOrigin: origin, rateLimiter: { consume: async () => true },
    authenticateAndAuthorize: async (_request, operation) => {
      assert.deepEqual(operation, { platformId: 'platform', action: 'integration-connector:edit' });
      return { organizationId: 'authenticated-org', authorized: true };
    },
    lifecycle: { async start(value) { calls.push(value); return { authorizationUrl: 'https://canvas.example.test/login/oauth2/auth?state=synthetic' }; } },
    ...overrides,
  }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const send = (body = form, headers = {}, method = 'POST') => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.address().port, method,
      path: '/platforms/platform/oauth/start', headers: { Origin: origin,
        'Content-Type': 'application/x-www-form-urlencoded', ...headers } }, res => {
      let output = ''; res.on('data', chunk => { output += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: output, headers: res.headers }));
    });
    req.on('error', reject); req.end(body);
  });
  return { calls, send };
}
test('admin start derives tenant from authenticated context and exposes only authorization URL', async t => {
  const f = await fixture(t);
  const response = await f.send(form, { 'X-Organization-ID': 'spoofed-org' });
  assert.equal(response.status, 200);
  assert.deepEqual(f.calls, [{ organizationId: 'authenticated-org', platformId: 'platform', clientId: 'client',
    clientSecretRef: 'opaque-ref', capabilities: ['catalog'] }]);
  assert.deepEqual(Object.keys(JSON.parse(response.body)), ['authorizationUrl']);
  assert.doesNotMatch(response.body, /opaque-ref|spoofed-org/);
  assert.equal(response.headers['cache-control'], 'no-store');
});
for (const [identity, status] of [[null, 401], [{ authorized: false, organizationId: 'org' }, 403],
  [{ authorized: true }, 403]]) test(`admin authority rejection ${status}`, async t => {
  const f = await fixture(t, { authenticateAndAuthorize: async () => identity });
  assert.equal((await f.send()).status, status); assert.equal(f.calls.length, 0);
});
for (const body of [form + '&organizationId=spoofed', form + '&client_secret=plaintext',
  form + '&client_id=duplicate', form + '&%63lient_id=alias', form + '&capabilities=catalog',
  'client_id=%FF', 'client_id=%ZZ', 'client_id=only', form.replace('catalog', 'catalog,catalog')]) {
  test('admin rejects malformed or authority-bearing form before lifecycle', async t => {
    const f = await fixture(t); assert.equal((await f.send(body)).status, 400); assert.equal(f.calls.length, 0);
  });
}
test('admin enforces origin, method, media type and streaming body bound', async t => {
  const f = await fixture(t);
  assert.equal((await f.send(form, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await f.send(form, { 'Content-Type': 'application/json' })).status, 415);
  assert.equal((await f.send('', {}, 'GET')).status, 405);
  assert.equal((await f.send('a'.repeat(8193))).status, 413);
  assert.equal(f.calls.length, 0);
});
test('admin provider failures redact details and fail closed', async t => {
  const authentication = await fixture(t, { authenticateAndAuthorize: async () => { throw Error('secret'); } });
  assert.equal((await authentication.send()).status, 503);
  const denied = await fixture(t, { rateLimiter: { consume: async () => false } });
  assert.equal((await denied.send()).status, 429);
  const lifecycle = await fixture(t, { lifecycle: { start: async () => { throw Error('secret'); } } });
  assert.deepEqual(JSON.parse((await lifecycle.send()).body), { error: 'authorization_start_failed' });
});

test('admin HTTP uses the concrete public Gateway session/permission authenticator', async t => {
  const gateway = await httpsFixture();
  try {
    const organizationId = '20000000-0000-4000-8000-000000000001';
    let permissions = ['integration-connector:edit'];
    gateway.setHandler((req, res) => json(res, req.url === '/v1/auth/me'
      ? { authenticated: true, user: { user_id: 'user', organization_id: organizationId } } : { permissions }));
    const f = await fixture(t, { authenticateAndAuthorize: createGatewayAdminAuthenticator({
      gatewayOrigin: gateway.origin, adminOrigin: origin, sessionCookieName: 'session', ca: gateway.ca,
    }) });
    const headers = { Cookie: 'session=synthetic-session-token', 'X-Organization-ID': 'spoofed' };
    assert.equal((await f.send(form, headers)).status, 200);
    assert.equal(f.calls[0].organizationId, organizationId);
    permissions = [];
    assert.equal((await f.send(form, headers)).status, 403);
    assert.equal(f.calls.length, 1, 'revoked permission must stop the next lifecycle start');
    assert.equal(gateway.seen.length, 4);
  } finally { await gateway.close(); }
});
