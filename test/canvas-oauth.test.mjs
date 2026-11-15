// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createCanvasOAuthLifecycle } from '../src/canvas-oauth.mjs';

const ORG = 'org-one';
const PLATFORM = 'platform-one';
const CLIENT_SECRET_REF = 'secret-client';
const CLIENT_SECRET = 'synthetic-canvas-client-secret';
const ACCESS_TOKEN = 'synthetic-canvas-access-token';
const REFRESH_TOKEN = 'synthetic-canvas-refresh-token';

function fixture(overrides = {}) {
  let now = 1_800_000_000_000;
  let sequence = 0;
  const authorizations = new Map();
  const connections = new Map();
  const secrets = new Map([[CLIENT_SECRET_REF, CLIENT_SECRET]]);
  const saved = [];
  const deleted = [];
  const revoked = [];
  const calls = [];
  const platform = {
    id: PLATFORM, organizationId: ORG, canvasOrigin: 'https://canvas.example.test',
    configVersion: 7, archived: false, enabled: true,
  };
  const repository = {
    async getPlatform(org, id) {
      calls.push(['getPlatform', org, id]);
      return org === ORG && id === PLATFORM ? { ...platform } : null;
    },
    async connection(org, id) { return connections.get(org + ':' + id) ?? null; },
    async saveAuthorization(value) {
      saved.push(value);
      if (authorizations.has(value.stateHash)) return false;
      authorizations.set(value.stateHash, value);
      return true;
    },
    async markAuthorizationPending(org, id, version, authorizationId) {
      calls.push(['pending', org, id, version, authorizationId]);
      return overrides.markPending ? overrides.markPending() : org === ORG && id === PLATFORM && version === platform.configVersion;
    },
    async cancelAuthorization(hash) { authorizations.delete(hash); },
    async consumeAuthorization(hash, time) {
      const value = authorizations.get(hash);
      if (!value || value.expiresAt <= time) return null;
      authorizations.delete(hash);
      return value;
    },
    async publishConnection(value, version) {
      calls.push(['publish', value, version]);
      if (overrides.publish) return overrides.publish(value, version);
      if (version !== platform.configVersion || connections.has(ORG + ':' + PLATFORM)) return false;
      connections.set(ORG + ':' + PLATFORM, value);
      return true;
    },
    async markConnected(org, id, version, clientId, capabilities, scopes) {
      calls.push(['connected', org, id, version, clientId, capabilities, scopes]);
      return overrides.markConnected ? overrides.markConnected() : version === platform.configVersion;
    },
    async markReauthorizationRequired(...args) { calls.push(['reauthorization', ...args]); },
    async recordAuthorizationError(...args) { calls.push(['error', ...args]); },
  };
  const vault = {
    async metadata(org, ref) {
      if (org !== ORG || ref !== CLIENT_SECRET_REF) return null;
      return { organizationId: ORG, enabled: true, provider: 'canvas', purpose: 'oauth_client_secret' };
    },
    async get(org, ref) { return org === ORG ? secrets.get(ref) ?? null : null; },
    async put(org, metadata, value) {
      assert.equal(org, ORG);
      assert.equal(metadata.provider, 'canvas');
      const ref = 'secret-token-' + (++sequence);
      secrets.set(ref, value);
      saved.push({ secretRef: ref, purpose: metadata.purpose, value });
      return ref;
    },
    async delete(org, ref) {
      assert.equal(org, ORG);
      deleted.push(ref);
      secrets.delete(ref);
    },
  };
  const provider = {
    async exchange(input) {
      calls.push(['exchange', input]);
      if (overrides.exchange) return overrides.exchange(input);
      return { accessToken: ACCESS_TOKEN, refreshToken: REFRESH_TOKEN, expiresInSeconds: 3600 };
    },
    async revoke(input) { revoked.push(input); },
  };
  const lifecycle = createCanvasOAuthLifecycle({
    publicOrigin: 'https://connector.example.test',
    completionUrl: 'https://console.example.test/integrations/canvas',
    repository, secretVault: vault, provider,
    clock: () => now,
    randomBytes: size => Buffer.alloc(size, 7),
  });
  return {
    lifecycle, repository, vault, provider, authorizations, connections,
    saved, deleted, revoked, calls, platform, secrets,
    setNow(value) { now = value; },
  };
}
async function started(value, capabilities = ['catalog', 'native_activity_scores']) {
  const result = await value.lifecycle.start({
    organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities,
  });
  const url = new URL(result.authorizationUrl);
  return { result, url, state: url.searchParams.get('state'), stored: [...value.authorizations.values()][0] };
}

test('start stores only a hash and constructs a fixed Canvas authorization URL', async () => {
  const f = fixture();
  const { result, url, state, stored } = await started(f);
  assert.equal(url.origin, 'https://canvas.example.test');
  assert.equal(url.pathname, '/login/oauth2/auth');
  assert.equal(url.searchParams.get('client_id'), 'canvas-client');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://connector.example.test/oauth/callback');
  assert.equal(url.searchParams.get('state'), state);
  assert.equal(state.length, 43);
  assert.equal(stored.stateHash, createHash('sha256').update(state).digest('hex'));
  assert.equal(Object.hasOwn(stored, 'state'), false);
  assert.equal(stored.expiresAt - stored.createdAt, 600000);
  assert.deepEqual(result.scopes, [
    'url:GET|/api/v1/courses',
    'url:GET|/api/v1/courses/:course_id/assignments',
    'url:GET|/api/v1/courses/:course_id/modules',
    'url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id',
    'url:GET|/api/v1/courses/:course_id/assignments/:id',
  ]);
  assert.equal(f.saved.some(item => item.value === state), false);
});

test('callback consumes state once, exchanges code and persists only secret references', async () => {
  const f = fixture();
  const { state, stored } = await started(f);
  const result = await f.lifecycle.callback({ state, code: 'synthetic-auth-code' });
  const location = new URL(result.location);
  assert.equal(location.origin, 'https://console.example.test');
  assert.equal(location.pathname, '/integrations/canvas');
  assert.equal(location.searchParams.get('outcome'), 'connected');
  assert.equal(location.searchParams.get('platform_id'), PLATFORM);
  assert.equal(location.searchParams.has('code'), false);
  assert.equal(location.searchParams.has('state'), false);
  const connection = f.connections.get(ORG + ':' + PLATFORM);
  assert.equal(connection.status, 'connected');
  assert.equal(connection.clientSecretRef, CLIENT_SECRET_REF);
  assert.equal(connection.accessTokenRef, 'secret-token-1');
  assert.equal(connection.refreshTokenRef, 'secret-token-2');
  assert.equal(connection.tokenExpiresAt, stored.createdAt + 3600000);
  assert.equal(JSON.stringify(connection).includes(ACCESS_TOKEN), false);
  assert.equal(JSON.stringify(connection).includes(REFRESH_TOKEN), false);
  const exchange = f.calls.find(item => item[0] === 'exchange')[1];
  assert.equal(exchange.clientSecret, CLIENT_SECRET);
  assert.equal(exchange.code, 'synthetic-auth-code');
  assert.equal(exchange.redirectUri, 'https://connector.example.test/oauth/callback');
  assert.equal(f.authorizations.size, 0);
  const replay = await f.lifecycle.callback({ state, code: 'synthetic-auth-code' });
  assert.equal(new URL(replay.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.filter(item => item[0] === 'exchange').length, 1);
});

test('state is bound to tenant, platform configuration and the fixed callback URI', async () => {
  const f = fixture();
  const { state } = await started(f);
  f.platform.configVersion += 1;
  const result = await f.lifecycle.callback({ state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_configuration_changed');
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('Canvas authorization denial consumes state and does not exchange a token', async () => {
  const f = fixture();
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ state, error: 'access_denied' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_authorization_denied');
  assert.equal(f.authorizations.size, 0);
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('expired, malformed and unknown states never reach the provider', async () => {
  const f = fixture();
  const { state, stored } = await started(f);
  f.setNow(stored.expiresAt);
  const expired = await f.lifecycle.callback({ state, code: 'synthetic-code' });
  assert.equal(new URL(expired.location).searchParams.get('error_code'), 'oauth_state_invalid');
  const malformed = await f.lifecycle.callback({ state: 'not-a-state', code: 'synthetic-code' });
  assert.equal(new URL(malformed.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('unsupported capabilities, missing client secret and existing connection fail before state creation', async () => {
  const f = fixture();
  await assert.rejects(f.lifecycle.start({
    organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities: ['admin:full'],
  }), { code: 'unsupported_capability' });
  await assert.rejects(f.lifecycle.start({
    organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: 'wrong-secret', capabilities: ['catalog'],
  }), { code: 'client_secret_unavailable' });
  f.connections.set(ORG + ':' + PLATFORM, { status: 'connected' });
  await assert.rejects(f.lifecycle.start({
    organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities: ['catalog'],
  }), { code: 'connection_exists' });
  assert.equal(f.authorizations.size, 0);
});

test('configuration race cancels the pending state', async () => {
  const f = fixture({ markPending: () => false });
  await assert.rejects(started(f), { code: 'platform_configuration_changed' });
  assert.equal(f.authorizations.size, 0);
});

test('token storage failure cleans earlier token refs and revokes exchanged access token', async () => {
  const f = fixture();
  const originalPut = f.vault.put;
  let count = 0;
  f.vault.put = async (...args) => {
    if (++count === 2) throw new Error('synthetic storage failure');
    return originalPut(...args);
  };
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_secret_storage_failed');
  assert.deepEqual(f.deleted, ['secret-token-1']);
  assert.equal(f.revoked.length, 1);
});

test('failed connection insert cleans secrets, but uncertain insert preserves them for reconciliation', async () => {
  const denied = fixture({ publish: async () => false });
  const first = await started(denied);
  const conflict = await denied.lifecycle.callback({ state: first.state, code: 'synthetic-code' });
  assert.equal(new URL(conflict.location).searchParams.get('error_code'), 'oauth_authorization_conflict');
  assert.deepEqual(denied.deleted, ['secret-token-1', 'secret-token-2']);
  assert.equal(denied.revoked.length, 1);

  const uncertain = fixture({ publish: async () => { throw new Error('commit acknowledgment lost'); } });
  const second = await started(uncertain);
  const result = await uncertain.lifecycle.callback({ state: second.state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_connection_reconciliation_required');
  assert.deepEqual(uncertain.deleted, []);
  assert.equal(uncertain.revoked.length, 0);
});

test('post-publication platform race preserves durable tokens and marks reauthorization', async () => {
  const f = fixture({ markConnected: () => false });
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_configuration_changed');
  assert.equal(f.connections.size, 1);
  assert.deepEqual(f.deleted, []);
  assert.equal(f.calls.some(item => item[0] === 'reauthorization'), true);
});

test('callback response never reflects caller-controlled redirect or error text', async () => {
  const f = fixture();
  const { state } = await started(f);
  const result = await f.lifecycle.callback({
    state, code: '', error: 'https://attacker.example/?token=secret',
  });
  const location = new URL(result.location);
  assert.equal(location.origin, 'https://console.example.test');
  assert.equal(location.searchParams.get('error_code'), 'oauth_authorization_denied');
  assert.equal(location.searchParams.has('token'), false);
});
