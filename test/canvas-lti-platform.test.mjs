// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canvasLtiTrustProfile, createCanvasLtiPlatformReader } from '../src/canvas-lti-platform.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const C = 'https://purl.imsglobal.org/spec/lti/claim/';
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'platform-key', alg: 'RS256', use: 'sig' };
const nonce = 'n'.repeat(43);
function options(fixture, overrides = {}) {
  return { canvasOrigin: fixture.origin, trustProfile: 'self_managed_same_origin',
    selfManagedOriginAllowlist: [fixture.origin], clientId: 'tool-client', deploymentId: 'deployment-1',
    targetLinkUri: 'https://connector.example/lti/launch', allowedPrivateAddresses: ['127.0.0.1', '::1'],
    ca: fixture.ca, timeoutMs: 3000, ...overrides };
}
function token(issuer, changes = {}, headerChanges = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: 'tool-client', sub: 'provider-subject', nonce, iat: now - 1, exp: now + 120,
    [C + 'version']: '1.3.0', [C + 'message_type']: 'LtiResourceLinkRequest',
    [C + 'deployment_id']: 'deployment-1', [C + 'target_link_uri']: 'https://connector.example/lti/launch',
    [C + 'resource_link']: { id: 'resource-1' }, [C + 'roles']: [], ...changes };
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const body = `${encode({ alg: 'RS256', kid: 'platform-key', ...headerChanges })}.${encode(claims)}`;
  return `${body}.${sign('RSA-SHA256', Buffer.from(body), pair.privateKey).toString('base64url')}`;
}

test('hosted profiles pin issuer and services for explicit production/beta/test environments', () => {
  for (const environment of ['production', 'beta', 'test']) {
    const suffix = environment === 'production' ? '' : `.${environment}`;
    const profile = canvasLtiTrustProfile({ canvasOrigin: 'https://university.example', trustProfile: 'hosted_global', environment });
    assert.deepEqual(profile, { canvasOrigin: 'https://university.example', trustProfile: 'hosted_global', environment,
      issuer: `https://canvas${suffix}.instructure.com`,
      authorizationEndpoint: `https://sso${suffix}.canvaslms.com/api/lti/authorize_redirect`,
      jwksUri: `https://sso${suffix}.canvaslms.com/api/lti/security/jwks`,
      tokenEndpoint: 'https://university.example/login/oauth2/token' });
    assert.ok(Object.isFrozen(profile));
  }
});
test('self-managed origins require an exact independent server allowlist', () => {
  const origin = 'https://canvas.example:8443';
  const profile = canvasLtiTrustProfile({ canvasOrigin: origin + '/', trustProfile: 'self_managed_same_origin',
    selfManagedOriginAllowlist: [origin] });
  assert.equal(profile.issuer, origin);
  assert.equal(profile.jwksUri, origin + '/api/lti/security/jwks');
  for (const input of [
    { canvasOrigin: origin, trustProfile: 'self_managed_same_origin' },
    { canvasOrigin: origin, trustProfile: 'self_managed_same_origin', selfManagedOriginAllowlist: ['https://canvas.example'] },
    { canvasOrigin: origin, trustProfile: 'self_managed_same_origin', selfManagedOriginAllowlist: [origin], environment: 'production' },
    { canvasOrigin: origin, trustProfile: 'hosted_global' },
    { canvasOrigin: origin, trustProfile: 'hosted_global', environment: 'untrusted' },
    { canvasOrigin: 'http://canvas.example', trustProfile: 'hosted_global', environment: 'production' },
    { canvasOrigin: 'https://gateway.internal', trustProfile: 'hosted_global', environment: 'production' },
    { canvasOrigin: 'https://college.beta.instructure.com', trustProfile: 'hosted_global', environment: 'production' },
    { canvasOrigin: 'https://canvas.test.instructure.com', trustProfile: 'hosted_global', environment: 'beta' },
    { canvasOrigin: origin, trustProfile: 'hosted_global', environment: 'production', jwksUri: 'https://evil.example' },
  ]) assert.throws(() => canvasLtiTrustProfile(input), { message: 'invalid_lti_configuration' });
});
test('fresh pinned HTTPS JWKS validate exact registered issuer and never receive credentials or token', async () => {
  const fixture = await httpsFixture();
  try {
    fixture.setHandler((_req, res) => json(res, { keys: [key] }, 200, { 'Content-Type': 'application/jwk-set+json; charset=utf-8' }));
    const reader = createCanvasLtiPlatformReader(options(fixture));
    const signed = token(fixture.origin);
    assert.equal((await reader.validateResourceLink({ token: signed, nonce })).subject, 'provider-subject');
    await reader.validateResourceLink({ token: signed, nonce }); // Primitive intentionally consumes no nonce.
    assert.equal(fixture.seen.length, 2, 'fresh lookup on every validation, no JWKS cache');
    for (const seen of fixture.seen) {
      assert.equal(seen.method, 'GET'); assert.equal(seen.url, '/api/lti/security/jwks');
      for (const header of ['authorization', 'cookie', 'x-api-key', 'x-organization-id']) assert.equal(seen.headers[header], undefined);
      assert.ok(!JSON.stringify(seen).includes(signed));
    }
    await assert.rejects(reader.validateResourceLink({ token: token('https://canvas.instructure.com'), nonce }), { message: 'invalid_lti_launch' });
  } finally { await fixture.close(); }
});
test('registration and per-request inputs are copied before awaiting the platform', async () => {
  const fixture = await httpsFixture();
  try {
    const config = options(fixture, { trustedAdditionalAudiences: ['trusted'] });
    const reader = createCanvasLtiPlatformReader(config);
    config.clientId = 'other'; config.trustedAdditionalAudiences[0] = 'untrusted';
    fixture.setHandler((_req, res) => setTimeout(() => json(res, { keys: [key] }), 10));
    const input = { token: token(fixture.origin, { aud: ['tool-client', 'trusted'], azp: 'tool-client' }), nonce };
    const pending = reader.validateResourceLink(input); input.token = 'mutated'; input.nonce = 'mutated';
    assert.equal((await pending).clientId, 'tool-client');
    await assert.rejects(reader.validateResourceLink({ token: token(fixture.origin, { aud: ['tool-client', 'untrusted'], azp: 'tool-client' }), nonce }), { message: 'invalid_lti_launch' });
  } finally { await fixture.close(); }
});
test('invalid request shape, authority and JWT-selected discovery fail before networking', async () => {
  const fixture = await httpsFixture();
  try {
    const reader = createCanvasLtiPlatformReader(options(fixture)), signed = token(fixture.origin);
    for (const input of [{ token: signed, nonce, issuer: fixture.origin }, { token: signed, nonce, jwksUri: fixture.origin },
      { token: signed, nonce, apiKey: 'secret' }, { token: signed, nonce: '' }, { token: 'bad', nonce }]) {
      await assert.rejects(reader.validateResourceLink(input), { message: 'invalid_lti_request' });
    }
    assert.equal(fixture.seen.length, 0);
    fixture.setHandler((_req, res) => json(res, { keys: [key] }));
    await assert.rejects(reader.validateResourceLink({ token: token(fixture.origin, {}, { jku: 'https://evil.invalid/jwks' }), nonce }), { message: 'invalid_lti_launch' });
    assert.deepEqual(fixture.seen.map(seen => seen.url), ['/api/lti/security/jwks']);
  } finally { await fixture.close(); }
});
for (const [name, handler] of Object.entries({
  redirect: (_req, res) => { res.writeHead(302, { Location: 'https://evil.invalid/keys' }); res.end(); },
  unavailable: (_req, res) => { res.writeHead(503); res.end(); },
  unauthorized: (_req, res) => { res.writeHead(401); res.end(); },
  html: (_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html>'); },
  encoding: (_req, res) => json(res, { keys: [key] }, 200, { 'Content-Encoding': 'gzip' }),
  pagination: (_req, res) => json(res, { keys: [key] }, 200, { Link: '<https://evil.invalid>; rel="next"' }),
  advertisedOversize: (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '131073' }); res.end(); },
  streamedOversize: (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('x'.repeat(131073)); },
  utf8: (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(Buffer.from([0xff])); },
  duplicateType: (_req, res) => { res.writeHead(200, ['Content-Type', 'application/json', 'Content-Type', 'text/html']); res.end(JSON.stringify({ keys: [key] })); },
})) test(`JWKS ${name} is unavailable with one fixed request and no redirects/retries`, async () => {
  const fixture = await httpsFixture();
  try {
    fixture.setHandler(handler);
    await assert.rejects(createCanvasLtiPlatformReader(options(fixture)).validateResourceLink({ token: token(fixture.origin), nonce }), { message: 'canvas_lti_platform_unavailable' });
    assert.equal(fixture.seen.length, 1); assert.equal(fixture.seen[0].url, '/api/lti/security/jwks');
  } finally { await fixture.close(); }
});
test('ambiguous and private JWKS never authenticate a launch', async () => {
  const fixture = await httpsFixture();
  try {
    const reader = createCanvasLtiPlatformReader(options(fixture));
    for (const keys of ['{"keys":[],"keys":' + JSON.stringify([key]) + '}', JSON.stringify({ keys: [key, key] }),
      JSON.stringify({ keys: [{ ...key, d: 'private' }] })]) {
      fixture.setHandler((_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(keys); });
      await assert.rejects(reader.validateResourceLink({ token: token(fixture.origin), nonce }), { message: 'invalid_lti_launch' });
    }
  } finally { await fixture.close(); }
});
test('DNS private-address policy and TLS verification fail closed', async () => {
  const fixture = await httpsFixture();
  try {
    fixture.setHandler((_req, res) => json(res, { keys: [key] }));
    for (const overrides of [{ allowedPrivateAddresses: [] }, { ca: undefined }]) {
      await assert.rejects(createCanvasLtiPlatformReader(options(fixture, overrides)).validateResourceLink({ token: token(fixture.origin), nonce }), { message: 'canvas_lti_platform_unavailable' });
      assert.equal(fixture.seen.length, 0);
    }
  } finally { await fixture.close(); }
});
test('absolute deadline stops stalled or trickling key responses', async () => {
  const fixture = await httpsFixture();
  try {
    const reader = createCanvasLtiPlatformReader(options(fixture, { timeoutMs: 75 }));
    for (const handler of [() => {}, (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const timer = setInterval(() => res.write(' '), 5); res.on('close', () => clearInterval(timer));
    }]) {
      fixture.setHandler(handler); const started = performance.now();
      await assert.rejects(reader.validateResourceLink({ token: token(fixture.origin), nonce }), { message: 'canvas_lti_platform_unavailable' });
      assert.ok(performance.now() - started < 1500);
    }
  } finally { await fixture.close(); }
});
test('configuration rejects transports, credentials, unsafe trust and invalid limits', async () => {
  const fixture = await httpsFixture();
  try {
    for (const overrides of [{ ca: fixture.ca + '\nPRIVATE KEY' }, { clientId: '' }, { timeoutMs: 0 },
      { deploymentId: '' }, { targetLinkUri: 'https://user:secret@evil.test' }, { trustedAdditionalAudiences: ['a'.repeat(256)] },
      { transport: () => {} }, { jwksUri: fixture.origin }, { apiKey: 'secret' }]) {
      assert.throws(() => createCanvasLtiPlatformReader(options(fixture, overrides)), { message: 'invalid_lti_configuration' });
    }
  } finally { await fixture.close(); }
});
test('one final wall-clock sample rechecks launch age, future issued-at and not-before after validation', async () => {
  const fixture = await httpsFixture();
  const originalNow = Date.now;
  try {
    const base = Math.floor(originalNow() / 1000);
    fixture.setHandler((_req, res) => json(res, { keys: [key] }));
    const reader = createCanvasLtiPlatformReader(options(fixture));
    for (const [claims, finalSeconds] of [
      [{ iat: base - 300, exp: base + 3600 }, base + 1],
      [{ iat: base + 30, exp: base + 3600 }, base - 1],
      [{ nbf: base, exp: base + 3600 }, base - 1],
    ]) {
      Date.now = originalNow;
      const signed = token(fixture.origin, claims); let calls = 0;
      Date.now = () => (calls++ === 0 ? base : finalSeconds) * 1000;
      await assert.rejects(reader.validateResourceLink({ token: signed, nonce }), { message: 'invalid_lti_launch' });
      assert.equal(calls, 2, 'initial and final checks each capture one wall-clock sample');
    }
  } finally { Date.now = originalNow; await fixture.close(); }
});
