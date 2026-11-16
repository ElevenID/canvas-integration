// SPDX-License-Identifier: AGPL-3.0-only
// Test-only psql bridge: exercise actual parameterized repository SQL without
// adding a production driver dependency or connecting to any configured DB.
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createCanvasOAuthLifecycle } from '../src/canvas-oauth.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { createRevocationWorker } from '../src/revocation-worker.mjs';

const container = process.argv[2];
assert.match(container ?? '', /^canvas-storage-test-[a-f0-9]{32}$/);
const literal = value => value === null ? 'NULL' : Buffer.isBuffer(value) ? `decode('${value.toString('hex')}','hex')` : Array.isArray(value)
  ? `ARRAY[${value.map(literal).join(',')}]::text[]`
  : typeof value === 'number' ? String(value) : `'${String(value).replaceAll("'", "''")}'`;
function csv(source) {
  const rows = []; let row = [], value = '', quoted = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === '"') {
      if (quoted && source[i + 1] === '"') { value += '"'; i++; } else quoted = !quoted;
    } else if (!quoted && (char === ',' || char === '\n')) {
      row.push(value); value = '';
      if (char === '\n') { rows.push(row); row = []; }
    } else if (char !== '\r') value += char;
  }
  return rows;
}
const pool = { async query(sql, values) {
  const statement = values.length ? `PREPARE q AS ${sql}; EXECUTE q(${values.map(literal).join(',')});` : sql;
  const output = execFileSync('docker', ['exec', '-i', container, 'psql', '-X', '-q', '--csv',
    '-U', 'postgres', '-d', 'canvas_storage_test', '-v', 'ON_ERROR_STOP=1'],
  { input: statement, encoding: 'utf8' });
  const [names, ...records] = csv(output);
  return { rows: records.map(record => Object.fromEntries(names.map((name, index) => {
    let value = record[index];
    if (['enabled', 'archived', 'ok', 'revoked'].includes(name)) value = value === 't';
    else if (['configVersion', 'platformConfigVersion', 'createdAt', 'expiresAt', 'tokenExpiresAt'].includes(name)) value = value === '' ? null : Number(value);
    else if (['capabilities', 'scopes'].includes(name)) {
      // This fixture uses simple scope strings without array delimiters/escapes.
      assert.match(value, /^\{[^{}"\\]*\}$/);
      value = value.slice(1, -1) ? value.slice(1, -1).split(',') : [];
    }
    else if (['ciphertext', 'nonce', 'tag'].includes(name)) value = Buffer.from(value.slice(2), 'hex');
    return [name, value];
  }))) };
} };
const repository = createPostgresRepository(pool);
await pool.query("INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ('adapter-org','adapter-platform','https://canvas.example.test',true)", []);
assert.equal((await repository.getPlatform('adapter-org', 'adapter-platform')).configVersion, 1);
assert.equal(await repository.getPlatform('foreign', 'adapter-platform'), null);
const now = Date.now();
const authorization = { stateHash: 'd'.repeat(64), organizationId: 'adapter-org', platformId: 'adapter-platform',
  platformConfigVersion: 1, canvasOrigin: 'https://canvas.example.test', clientId: "client'quoted",
  clientSecretRef: 'vault-client', capabilities: ['catalog'], scopes: ['read'],
  redirectUri: 'https://connector.example.test/oauth/callback', createdAt: now, expiresAt: now + 600000 };
assert.equal(await repository.saveAuthorization(authorization), true);
assert.equal(await repository.saveAuthorization(authorization), false);
assert.equal(await repository.markAuthorizationPending('adapter-org', 'adapter-platform', 2, authorization.stateHash), false);
assert.equal(await repository.markAuthorizationPending('adapter-org', 'adapter-platform', 1, authorization.stateHash), true);
const consumed = await repository.consumeAuthorization(authorization.stateHash);
assert.equal(consumed.clientId, authorization.clientId);
assert.equal(consumed.expiresAt, authorization.expiresAt);
assert.equal(await repository.consumeAuthorization(authorization.stateHash), null);
const connection = { ...authorization, accessTokenRef: 'vault-access', refreshTokenRef: 'vault-refresh', tokenExpiresAt: now + 3600000 };
assert.equal(await repository.publishConnection(connection, 2), false);
assert.equal(await repository.publishConnection(connection, 1), true);
assert.equal(await repository.publishConnection(connection, 1), false);
assert.equal((await repository.connection('adapter-org', 'adapter-platform')).accessTokenRef, 'vault-access');
assert.equal(await repository.markConnected('adapter-org', 'adapter-platform', 1, authorization.clientId, ['catalog'], ['read']), true);
await pool.query("UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='adapter-org'", []);
assert.equal(await repository.markConnected('adapter-org', 'adapter-platform', 1, authorization.clientId, ['catalog'], ['read']), false);
await repository.markReauthorizationRequired('adapter-org', 'adapter-platform');
assert.equal((await repository.connection('adapter-org', 'adapter-platform')).status, 'reauthorization_required');
await assert.rejects(createPostgresRepository({ query: async () => { throw Error('password=secret'); } }).publishConnection(connection, 1), /^Error: connector_database_unavailable$/);
console.log('Actual repository SQL passed persistence, tenant, replay, configuration and redaction contracts');

// Exercise the real lifecycle + repository. Only vault/provider are synthetic;
// no in-memory production repository or real OAuth grants are involved.
for (const uncertainCommit of [false, true]) {
  const org = uncertainCommit ? 'uncertain-org' : 'lifecycle-org';
  await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES ($1,'platform','https://canvas.example.test',true) RETURNING id`, [org]);
  const durablePool = uncertainCommit ? { async query(sql, values) {
    const result = await pool.query(sql, values);
    if (sql.startsWith('INSERT INTO canvas_connector.connections')) throw Error('lost commit acknowledgment');
    return result;
  } } : pool;
  const secrets = new Map([['client-secret-ref', 'synthetic-client-secret']]);
  let exchanges = 0;
  const lifecycle = createCanvasOAuthLifecycle({
    publicOrigin: 'https://connector.example.test',
    completionUrl: 'https://connector.example.test/complete',
    repository: createPostgresRepository(durablePool),
    secretVault: {
      async metadata(tenant, ref) { return tenant === org && ref === 'client-secret-ref'
        ? { organizationId: org, enabled: true, provider: 'canvas', purpose: 'oauth_client_secret' } : null; },
      async get(tenant, ref) { assert.equal(tenant, org); return secrets.get(ref); },
      async put(tenant, metadata, value) {
        assert.equal(tenant, org); const ref = 'vault-' + metadata.purpose; secrets.set(ref, value); return ref;
      },
      async delete(tenant, ref) { assert.equal(tenant, org); secrets.delete(ref); },
    },
    provider: { async exchange() {
      exchanges++;
      return { accessToken: 'synthetic-access-token', refreshToken: 'synthetic-refresh-token', expiresInSeconds: 3600 };
    } },
  });
  const start = await lifecycle.start({ organizationId: org, platformId: 'platform',
    clientId: 'client', clientSecretRef: 'client-secret-ref', capabilities: ['catalog'] });
  const state = new URL(start.authorizationUrl).searchParams.get('state');
  const callback = await lifecycle.callback({ state, code: 'synthetic-code' });
  const result = new URL(callback.location);
  if (uncertainCommit) assert.equal(result.searchParams.get('error_code'), 'oauth_connection_reconciliation_required');
  else assert.equal(result.searchParams.get('outcome'), 'connected');
  assert.equal(exchanges, 1);
  const persisted = await repository.connection(org, 'platform');
  assert.equal(persisted.accessTokenRef, 'vault-oauth_access_token');
  assert.equal(secrets.size, 3, 'committed or uncertain publication must retain both token references');
  const replay = await lifecycle.callback({ state, code: 'synthetic-code' });
  assert.equal(new URL(replay.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(exchanges, 1);
}
console.log('OAuth lifecycle + PostgreSQL passed fresh authorization, replay and lost-commit-acknowledgment contracts');

// Real encrypted vault persistence with a synthetic external key provider.
const key = Buffer.alloc(32, 17);
const keys = new Map([['test-key-v1', key], ['test-key-v2', Buffer.alloc(32, 23)]]);
let currentKey = 'test-key-v1';
const vault = createEncryptedVault({ pool, keyProvider: {
  async current() { return { id: currentKey, key: keys.get(currentKey) }; },
  async byId(id) { return keys.get(id); },
} });
const metadata = { platformId: 'adapter-platform', provider: 'canvas', purpose: 'oauth_client_secret' };
const secret = 'synthetic-private-client-secret';
const reference = await vault.put('adapter-org', metadata, secret);
assert.equal(await vault.get('adapter-org', reference), secret);
currentKey = 'test-key-v2';
assert.equal(await vault.rotate('adapter-org', reference), true);
assert.equal(await vault.get('adapter-org', reference), secret);
assert.equal((await pool.query('SELECT key_id FROM canvas_connector.secrets WHERE reference=$1', [reference])).rows[0].key_id, 'test-key-v2');
keys.delete('test-key-v1');
assert.equal(await vault.get('adapter-org', reference), secret, 'rotation must survive retirement of the old key');
const unavailableVault = createEncryptedVault({ pool, keyProvider: {
  async current() { throw Error('private key provider detail'); }, async byId() { return null; },
} });
await assert.rejects(unavailableVault.get('adapter-org', reference), /^Error: connector_vault_unavailable$/);
await assert.rejects(unavailableVault.put('adapter-org', metadata, secret), /^Error: connector_vault_unavailable$/);
assert.equal((await vault.metadata('adapter-org', reference)).purpose, 'oauth_client_secret');
assert.equal(await vault.metadata('foreign-org', reference), null);
await assert.rejects(vault.get('foreign-org', reference), /connector_vault_unavailable/);
const encrypted = (await pool.query('SELECT ciphertext,nonce,tag FROM canvas_connector.secrets WHERE reference=$1', [reference])).rows[0];
assert.equal(encrypted.ciphertext.includes(Buffer.from(secret)), false);
const other = await vault.put('adapter-org', metadata, secret);
const otherEncrypted = (await pool.query('SELECT ciphertext,nonce,tag FROM canvas_connector.secrets WHERE reference=$1', [other])).rows[0];
assert.notDeepEqual(encrypted.nonce, otherEncrypted.nonce);
assert.notDeepEqual(encrypted.ciphertext, otherEncrypted.ciphertext);
await pool.query("UPDATE canvas_connector.secrets SET purpose='oauth_access_token' WHERE reference=$1 RETURNING reference", [reference]);
await assert.rejects(vault.get('adapter-org', reference), /connector_vault_unavailable/);
await pool.query("UPDATE canvas_connector.secrets SET purpose='oauth_client_secret',ciphertext=$2 WHERE reference=$1 RETURNING reference", [reference, otherEncrypted.ciphertext]);
await assert.rejects(vault.get('adapter-org', reference), /connector_vault_unavailable/);
await pool.query('UPDATE canvas_connector.secrets SET enabled=false WHERE reference=$1 RETURNING reference', [other]);
await assert.rejects(vault.get('adapter-org', other), /connector_vault_unavailable/);
await vault.delete('foreign-org', other);
assert.notEqual(await vault.metadata('adapter-org', other), null);
await vault.delete('adapter-org', other);
assert.equal(await vault.metadata('adapter-org', other), null);
assert.deepEqual(key, Buffer.alloc(32, 17), 'vault must not mutate provider-owned key buffers');
console.log('Encrypted PostgreSQL vault passed roundtrip, ciphertext isolation, tenant isolation, tamper and disablement contracts');

await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
  VALUES ('worker-org','worker-platform','https://canvas.example.test',true) RETURNING id`, []);
const accessRef = await vault.put('worker-org', { platformId: 'worker-platform', provider: 'canvas', purpose: 'oauth_access_token' }, 'synthetic-worker-access');
const refreshRef = await vault.put('worker-org', { platformId: 'worker-platform', provider: 'canvas', purpose: 'oauth_refresh_token' }, 'synthetic-worker-refresh');
assert.equal(await repository.publishConnection({ ...connection, organizationId: 'worker-org', platformId: 'worker-platform',
  accessTokenRef: accessRef, refreshTokenRef: refreshRef }, 1), true);
assert.equal(await repository.disconnect('worker-org', 'worker-platform'), true);
let providerCalls = 0;
let injectCleanupFailure = true;
const worker = createRevocationWorker({ repository,
  secretVault: { get: vault.get, async delete(org, ref) {
    if (ref === refreshRef && injectCleanupFailure) { injectCleanupFailure = false; throw Error('synthetic storage outage'); }
    await vault.delete(org, ref);
  } },
  provider: { async revoke(input) {
    assert.deepEqual(input, { canvasOrigin: 'https://canvas.example.test', accessToken: 'synthetic-worker-access' });
    providerCalls++; return true;
  } },
});
assert.equal(await worker.runOnce(), 'retry');
assert.equal(await vault.metadata('worker-org', accessRef), null, 'first cleanup step completed');
assert.notEqual(await vault.metadata('worker-org', refreshRef), null, 'failed cleanup must retain remaining secret');
await pool.query("UPDATE canvas_connector.revocation_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id='worker-org' RETURNING id", []);
assert.equal(await worker.runOnce(), 'completed');
assert.equal(providerCalls, 1, 'durable confirmation must resume cleanup without a deleted access token');
assert.equal(await vault.metadata('worker-org', refreshRef), null);
assert.equal(await worker.runOnce(), 'idle');
console.log('Durable revocation worker passed provider confirmation, partial cleanup recovery and completion contracts');
