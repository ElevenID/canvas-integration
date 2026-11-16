// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayAdminAuthenticator } from '../src/gateway-admin-auth.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';
const org = '20000000-0000-4000-8000-000000000001';
const admin = 'https://connector.example.test';
const operation = { platformId: 'platform', action: 'integration-connector:edit' };
const incoming = cookie => ({ rawHeaders: ['Origin', admin, 'Cookie', cookie ?? 'session=synthetic-session-token; private=never-forward'] });
const session = { authenticated: true, user: { user_id: 'user-one', organization_id: org } };

test('authenticator uses only public Gateway session and current exact permissions', async () => {
  const fixture = await httpsFixture();
  try {
    let permitted = true;
    fixture.setHandler((req, res) => json(res, req.url === '/v1/auth/me' ? session
      : { permissions: permitted ? ['integration-connector:edit'] : [], is_owner: true }));
    const authenticate = createGatewayAdminAuthenticator({ gatewayOrigin: fixture.origin, adminOrigin: admin,
      sessionCookieName: 'session', ca: fixture.ca });
    assert.deepEqual(await authenticate(incoming(), operation), { organizationId: org, actorId:'user-one', authorized: true });
    permitted = false;
    assert.deepEqual(await authenticate(incoming(), operation), { organizationId: org, actorId:'user-one', authorized: false });
    assert.equal(fixture.seen.length, 4, 'authority must not be cached');
    assert.equal(fixture.seen[1].url, `/v1/organizations/${org}/members/me/permissions`);
    for (const entry of fixture.seen) {
      assert.equal(entry.method, 'GET');
      assert.equal(entry.headers.cookie, 'session=synthetic-session-token');
      assert.equal(entry.headers['x-api-key'], undefined);
      assert.equal(entry.headers['x-organization-id'], undefined);
    }
  } finally { await fixture.close(); }
});
test('authenticator rejects missing, duplicated and forged context before transport', async () => {
  const fixture = await httpsFixture();
  try {
    const authenticate = createGatewayAdminAuthenticator({ gatewayOrigin: fixture.origin, adminOrigin: admin,
      sessionCookieName: 'session', ca: fixture.ca });
    for (const request of [incoming('private=only'), incoming('session=one; session=two'),
      { rawHeaders: ['Origin', 'https://evil.example', 'Cookie', 'session=synthetic-session-token'] },
      { rawHeaders: ['Origin', admin, 'Origin', admin, 'Cookie', 'session=synthetic-session-token'] }]) {
      assert.equal(await authenticate(request, operation), null);
    }
    assert.equal(fixture.seen.length, 0);
  } finally { await fixture.close(); }
});
for (const permission of ['*', 'integrations:write', 'admin:full']) test(`no invented scope grant: ${permission}`, async () => {
  const fixture = await httpsFixture();
  try {
    fixture.setHandler((req, res) => json(res, req.url === '/v1/auth/me' ? session : { permissions: [permission], is_owner: true }));
    const authenticate = createGatewayAdminAuthenticator({ gatewayOrigin: fixture.origin, adminOrigin: admin,
      sessionCookieName: 'session', ca: fixture.ca });
    assert.equal((await authenticate(incoming(), operation)).authorized, false);
  } finally { await fixture.close(); }
});
test('Gateway redirects, invalid JSON, oversized responses, TLS failure and deadline fail closed', async () => {
  const fixture = await httpsFixture();
  try {
    const options = { gatewayOrigin: fixture.origin, adminOrigin: admin, sessionCookieName: 'session', ca: fixture.ca, timeoutMs: 100 };
    const authenticate = createGatewayAdminAuthenticator(options);
    for (const handler of [
      (_req, res) => { res.writeHead(302, { Location: 'https://evil.example' }); res.end(); },
      (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('bad'); },
      (_req, res) => json(res, { oversized: 'x'.repeat(65537) }),
      () => {},
    ]) {
      fixture.setHandler(handler);
      await assert.rejects(authenticate(incoming(), operation), /^Error: gateway_admin_auth_unavailable$/);
    }
    await assert.rejects(createGatewayAdminAuthenticator({ ...options, ca: undefined })(incoming(), operation), /gateway_admin_auth_unavailable/);
  } finally { await fixture.close(); }
});
test('private service origins cannot be configured as the Gateway', () => {
  for (const gatewayOrigin of ['http://gateway.example', 'https://issuance', 'https://auth.internal', 'https://169.254.169.254']) {
    assert.throws(() => createGatewayAdminAuthenticator({ gatewayOrigin, adminOrigin: admin, sessionCookieName: 'session' }));
  }
});
