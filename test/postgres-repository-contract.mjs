// SPDX-License-Identifier: AGPL-3.0-only
// Test-only psql bridge: exercise actual parameterized repository SQL without
// adding a production driver dependency or connecting to any configured DB.
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createCanvasOAuthLifecycle } from '../src/canvas-oauth.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { createRevocationWorker } from '../src/revocation-worker.mjs';
import { createRefreshWorker } from '../src/refresh-worker.mjs';
import { createCanvasOAuthProvider } from '../src/canvas-oauth-provider.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';
import { createServer, request as httpRequest } from 'node:http';
import { createOAuthAdminHandler } from '../src/oauth-admin-http.mjs';
import { createOAuthCallbackHandler } from '../src/oauth-callback-http.mjs';
import { createGatewayAdminAuthenticator } from '../src/gateway-admin-auth.mjs';

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
const authorization = { browserBindingHash:'e'.repeat(64), stateHash: 'd'.repeat(64), organizationId: 'adapter-org', platformId: 'adapter-platform',
  platformConfigVersion: 1, canvasOrigin: 'https://canvas.example.test', clientId: "client'quoted",
  clientSecretRef: 'vault-client', capabilities: ['catalog'], scopes: ['read'],
  redirectUri: 'https://connector.example.test/oauth/callback', createdAt: now, expiresAt: now + 600000 };
assert.equal(await repository.saveAuthorization(authorization), true);
assert.equal(await repository.saveAuthorization(authorization), false);
assert.equal(await repository.markAuthorizationPending('adapter-org', 'adapter-platform', 2, authorization.stateHash), false);
assert.equal(await repository.markAuthorizationPending('adapter-org', 'adapter-platform', 1, authorization.stateHash), true);
assert.equal(await repository.consumeAuthorization(authorization.stateHash,now,'f'.repeat(64)),null);
const consumed = await repository.consumeAuthorization(authorization.stateHash,now,authorization.browserBindingHash);
assert.equal(consumed.browserBindingHash,authorization.browserBindingHash);
assert.equal(consumed.clientId, authorization.clientId);
assert.equal(consumed.expiresAt, authorization.expiresAt);
assert.equal(await repository.consumeAuthorization(authorization.stateHash,now,authorization.browserBindingHash), null);
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
        ? { organizationId: org, platformId:'platform', enabled: true, provider: 'canvas', purpose: 'oauth_client_secret' } : null; },
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
  const start = await lifecycle.start({ browserBinding:Buffer.alloc(32,9).toString('base64url'), organizationId: org, platformId: 'platform',
    clientId: 'client', clientSecretRef: 'client-secret-ref', capabilities: ['catalog'] });
  const state = new URL(start.authorizationUrl).searchParams.get('state');
  const callback = await lifecycle.callback({ browserBinding:Buffer.alloc(32,9).toString('base64url'), state, code: 'synthetic-code' });
  const result = new URL(callback.location);
  if (uncertainCommit) assert.equal(result.searchParams.get('error_code'), 'oauth_connection_reconciliation_required');
  else assert.equal(result.searchParams.get('outcome'), 'connected');
  assert.equal(exchanges, 1);
  const persisted = await repository.connection(org, 'platform');
  assert.equal(persisted.accessTokenRef, 'vault-oauth_access_token');
  assert.equal(secrets.size, 3, 'committed or uncertain publication must retain both token references');
  const replay = await lifecycle.callback({ browserBinding:Buffer.alloc(32,9).toString('base64url'), state, code: 'synthetic-code' });
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

const https = await httpsFixture();
try {
  https.setHandler((req, res) => {
    assert.equal(req.method, 'DELETE'); assert.equal(req.url, '/login/oauth2/token');
    assert.equal(req.headers.authorization, 'Bearer synthetic-https-access');
    assert.equal(req.headers['x-api-key'], undefined);
    json(res, {});
  });
  await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES ('http-worker-org','platform',$1,true) RETURNING id`, [https.origin]);
  const access = await vault.put('http-worker-org', { platformId: 'platform', provider: 'canvas', purpose: 'oauth_access_token' }, 'synthetic-https-access');
  const refresh = await vault.put('http-worker-org', { platformId: 'platform', provider: 'canvas', purpose: 'oauth_refresh_token' }, 'synthetic-https-refresh');
  assert.equal(await repository.publishConnection({ ...connection, organizationId: 'http-worker-org', platformId: 'platform',
    canvasOrigin: https.origin, accessTokenRef: access, refreshTokenRef: refresh }, 1), true);
  assert.equal(await repository.disconnect('http-worker-org', 'platform'), true);
  const concreteWorker = createRevocationWorker({ repository, secretVault: vault,
    provider: createCanvasOAuthProvider({ allowedPrivateAddresses: ['127.0.0.1', '::1'], ca: https.ca }) });
  assert.equal(await concreteWorker.runOnce(), 'completed');
  assert.equal(https.seen.length, 1);
  assert.equal(await vault.metadata('http-worker-org', access), null);
  assert.equal(await vault.metadata('http-worker-org', refresh), null);
  assert.equal(await concreteWorker.runOnce(), 'idle');
} finally { await https.close(); }
console.log('PostgreSQL + encrypted vault + concrete pinned HTTPS revocation passed');

for (const outcome of ['success', 'lost-commit-ack', 'provider-failure', 'configuration-change','lost-stage-ack']) {
  const fixture = await httpsFixture();
  try {
    const organizationId = 'refresh-' + outcome;
    await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
      VALUES ($1,'platform',$2,true) RETURNING id`, [organizationId, fixture.origin]);
    const put = (purpose, value) => vault.put(organizationId, { platformId: 'platform', provider: 'canvas', purpose }, value);
    const client = await put('oauth_client_secret', 'synthetic-refresh-client-secret');
    const oldAccess = await put('oauth_access_token', 'synthetic-old-access');
    const refresh = await put('oauth_refresh_token', 'synthetic-stable-refresh');
    assert.equal(await repository.publishConnection({ ...connection, organizationId, platformId: 'platform',
      canvasOrigin: fixture.origin, clientSecretRef: client, accessTokenRef: oldAccess,
      refreshTokenRef: refresh, tokenExpiresAt: Date.now()+60000 }, 1), true);
    if (outcome === 'success') {
      const claimed = await repository.claimRefresh(organizationId, 'platform');
      assert.equal(await repository.claimRefresh(organizationId, 'platform'), null);
      await pool.query('UPDATE canvas_connector.refresh_attempts SET lease_until=clock_timestamp()-interval \'1 second\' WHERE id=$1 RETURNING id', [claimed.id]);
      const replacement = await repository.claimRefresh(organizationId, 'platform');
      assert.notEqual(replacement.id, claimed.id);
      assert.equal(await repository.beginRefreshExchange(claimed.id, claimed.leaseId), false);
      assert.equal(await repository.abandonUnstartedRefresh(replacement.id, replacement.leaseId), true);
    }
    let calls = 0;
    fixture.setHandler(async (req, res) => {
      calls++; assert.equal(req.method, 'POST'); assert.equal(req.url, '/login/oauth2/token');
      assert.equal(req.headers['x-api-key'], undefined);
      if (outcome === 'configuration-change') await pool.query(
        'UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1 RETURNING id', [organizationId]);
      if (outcome === 'provider-failure') { res.writeHead(500); res.end(); }
      else json(res, { access_token: 'synthetic-new-access', expires_in: 3600, token_type: 'Bearer' });
    });
    const refreshRepository = outcome === 'lost-commit-ack' ? { ...repository,
      async publishRefresh(...args) { await repository.publishRefresh(...args); throw Error('lost acknowledgment'); },
    } : repository;
    const refreshVault=outcome==='lost-stage-ack'?createEncryptedVault({pool:{async query(sql,values){
      const result=await pool.query(sql,values);
      if(sql.includes('FROM canvas_connector.stage_refresh_result')) throw Error('lost stage acknowledgment');
      return result;
    }},keyProvider:{async current(){return {id:currentKey,key:keys.get(currentKey)};},async byId(id){return keys.get(id);}}}):vault;
    const refreshWorker = createRefreshWorker({ repository: refreshRepository, secretVault: refreshVault,
      provider: createCanvasOAuthProvider({ allowedPrivateAddresses: ['127.0.0.1', '::1'], ca: fixture.ca }) });
    assert.equal(await refreshWorker.runOnce(organizationId, 'platform'), outcome === 'success' ? 'published' : 'reconciliation_required');
    assert.equal(calls, 1);
    if(['lost-stage-ack','configuration-change'].includes(outcome)) {
      const attempt=(await pool.query('SELECT new_access_token_ref,new_refresh_token_ref FROM canvas_connector.refresh_attempts WHERE organization_id=$1',[organizationId])).rows[0];
      assert.ok(attempt.new_access_token_ref);assert.equal(attempt.new_refresh_token_ref,refresh);
      assert.equal(await vault.get(organizationId,attempt.new_access_token_ref),'synthetic-new-access');
    }
    const current = await repository.connection(organizationId, 'platform');
    assert.equal(current.refreshTokenRef, refresh, 'Canvas refresh response may omit the reusable refresh token');
    if (['success', 'lost-commit-ack'].includes(outcome)) {
      assert.equal(await vault.get(organizationId, current.accessTokenRef), 'synthetic-new-access');
      assert.notEqual(current.accessTokenRef, oldAccess);
    } else assert.equal(current.accessTokenRef, oldAccess);
    assert.equal(await vault.get(organizationId, refresh), 'synthetic-stable-refresh');
    if (outcome === 'success') assert.equal(await vault.metadata(organizationId, oldAccess), null);
    else assert.notEqual(await vault.metadata(organizationId, oldAccess), null, 'uncertain outcomes must preserve old ciphertext');
    await pool.query('UPDATE canvas_connector.refresh_attempts SET lease_until=clock_timestamp()-interval \'1 second\' WHERE organization_id=$1 RETURNING id', [organizationId]);
    assert.equal(await refreshWorker.runOnce(organizationId, 'platform'), 'idle');
    assert.equal(calls, 1, 'expired in-flight attempts must not repeat exchanges automatically');
  } finally { await fixture.close(); }
}
console.log('Durable refresh passed concrete HTTPS exchange, reusable refresh token, uncertain commit and configuration-change contracts');
await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
  VALUES ('refresh-preflight','platform','https://canvas.example.test',true) RETURNING id`, []);
await repository.publishConnection({ ...connection, organizationId: 'refresh-preflight', platformId: 'platform',
  tokenExpiresAt: Date.now()+60000 }, 1);
const preflight = await repository.claimRefresh('refresh-preflight', 'platform');
await pool.query("UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='refresh-preflight' RETURNING id", []);
assert.equal(await repository.beginRefreshExchange(preflight.id, preflight.leaseId), false,
  'disablement between claim and exchange must prevent provider work');
console.log('Refresh revalidates current configuration before starting external exchange');

// Exact attempt custody must survive publication becoming ineligible.
async function refreshFixture(organizationId) {
  await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES ($1,'platform','https://canvas.example.test',true) RETURNING id`,[organizationId]);
  const put=(purpose,value)=>vault.put(organizationId,{platformId:'platform',provider:'canvas',purpose},value);
  const client=await put('oauth_client_secret','synthetic-stage-client');
  const access=await put('oauth_access_token','synthetic-stage-old-access');
  const refresh=await put('oauth_refresh_token','synthetic-stage-old-refresh');
  await repository.publishConnection({...connection,organizationId,platformId:'platform',clientSecretRef:client,
    accessTokenRef:access,refreshTokenRef:refresh,tokenExpiresAt:Date.now()+60000},1);
  const job=await repository.claimRefresh(organizationId,'platform');
  assert.equal(await repository.beginRefreshExchange(job.id,null),false,'NULL lease cannot begin an exchange');
  assert.equal(await repository.beginRefreshExchange(job.id,job.leaseId),true);
  return job;
}
const scope=(platformId,purpose)=>({platformId,provider:'canvas',purpose});
const bundle={accessToken:'synthetic-stage-new-access',refreshToken:'synthetic-stage-new-refresh'};
for (const outcome of ['disable','disconnect','lease-expired']) {
  const job=await refreshFixture('stage-'+outcome);
  if(outcome==='disable') await pool.query('UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1 RETURNING id',[job.organizationId]);
  if(outcome==='disconnect') assert.equal(await repository.disconnect(job.organizationId,job.platformId),true);
  if(outcome==='lease-expired') await pool.query("UPDATE canvas_connector.refresh_attempts SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1 RETURNING id",[job.id]);
  const result=await vault.stageRefreshResult(job,bundle,Date.now()+3600000);
  assert.equal(await repository.publishRefresh(job.id,job.leaseId),false);
  assert.equal(await repository.requireRefreshReconciliation(job.id,job.leaseId),true);
  const row=(await pool.query('SELECT new_access_token_ref,new_refresh_token_ref FROM canvas_connector.refresh_attempts WHERE id=$1',[job.id])).rows[0];
  assert.equal(row.new_access_token_ref,result.accessTokenRef);assert.equal(row.new_refresh_token_ref,result.refreshTokenRef);
  assert.equal(await vault.get(job.organizationId,result.accessTokenRef,scope(job.platformId,'oauth_access_token')),bundle.accessToken);
  assert.equal(await vault.get(job.organizationId,result.refreshTokenRef,scope(job.platformId,'oauth_refresh_token')),bundle.refreshToken);
  await assert.rejects(vault.stageRefreshResult(job,{...bundle,accessToken:'synthetic-conflicting-stage'},Date.now()+3600000),/connector_vault_unavailable/);
}
console.log('Staged ciphertext remains attempt-attributable after disablement, disconnect and lease expiry; conflicting restaging denied');
{
  const job=await refreshFixture('stage-atomic-rollback');
  const before=(await pool.query('SELECT count(*)::text AS count FROM canvas_connector.secrets WHERE organization_id=$1',[job.organizationId])).rows[0].count;
  await pool.query("ALTER TABLE canvas_connector.secrets ADD CONSTRAINT reject_second_stage_insert CHECK(organization_id<>'stage-atomic-rollback' OR purpose<>'oauth_refresh_token') NOT VALID",[]);
  try {await assert.rejects(vault.stageRefreshResult(job,bundle,Date.now()+3600000),/connector_vault_unavailable/);}
  finally {await pool.query('ALTER TABLE canvas_connector.secrets DROP CONSTRAINT reject_second_stage_insert',[]);}
  const after=(await pool.query('SELECT count(*)::text AS count FROM canvas_connector.secrets WHERE organization_id=$1',[job.organizationId])).rows[0].count;
  assert.equal(after,before,'second insert failure must roll back first ciphertext too');
  assert.equal((await pool.query('SELECT (new_access_token_ref IS NULL) AS ok FROM canvas_connector.refresh_attempts WHERE id=$1',[job.id])).rows[0].ok,true);
}
{
  const job=await refreshFixture('stage-lost-ack');let stagedParameters;let providerCalls=0;
  const unknownVault=createEncryptedVault({pool:{async query(sql,values){
    const result=await pool.query(sql,values);
    if(sql.includes('FROM canvas_connector.stage_refresh_result')){stagedParameters=values;throw Error('lost synthetic staging acknowledgment');}
    return result;
  }},keyProvider:{async current(){return {id:currentKey,key:keys.get(currentKey)};},async byId(id){return keys.get(id);}}});
  const worker=createRefreshWorker({repository:{...repository,async claimRefresh(){return job;}},secretVault:unknownVault,
    provider:{async refresh(){providerCalls++;return {...bundle,expiresInSeconds:3600};}}});
  // This fixture already started the exchange; drive staging fault directly.
  await assert.rejects(unknownVault.stageRefreshResult(job,bundle,Date.now()+3600000),/connector_vault_unavailable/);
  assert.equal(providerCalls,0);
  const row=(await pool.query('SELECT new_access_token_ref,new_refresh_token_ref FROM canvas_connector.refresh_attempts WHERE id=$1',[job.id])).rows[0];
  assert.ok(row.new_access_token_ref);assert.ok(row.new_refresh_token_ref);
  // Exact replay of the same encrypted SQL result is idempotent.
  const replay=await pool.query('SELECT id FROM canvas_connector.stage_refresh_result($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,to_timestamp($15::float8/1000))',stagedParameters);
  assert.equal(replay.rows.length,1);
  assert.equal(await repository.publishRefresh(job.id,null),false,'NULL lease cannot publish staged secrets');
  assert.equal(await repository.requireRefreshReconciliation(job.id,job.leaseId),true);
  assert.equal(await worker.runOnce(job.organizationId,job.platformId),'lease_lost');
  assert.equal(providerCalls,0,'reconciliation may not repeat provider refresh');
}
console.log('Staging rollback and committed-but-lost acknowledgment retain exact references; NULL leases and provider replay denied');
{
  const job=await refreshFixture('stage-scope');
  for(const changed of [{...job,platformId:'other-platform'},{...job,organizationId:'foreign-org'},{...job,leaseId:'00000000-0000-4000-8000-000000000001'}]) {
    await assert.rejects(vault.stageRefreshResult(changed,bundle,Date.now()+3600000),/connector_vault_unavailable/);
  }
  await assert.rejects(vault.get(job.organizationId,job.clientSecretRef,scope('other-platform','oauth_client_secret')),/connector_vault_unavailable/);
  await assert.rejects(vault.get(job.organizationId,job.clientSecretRef,scope(job.platformId,'oauth_refresh_token')),/connector_vault_unavailable/);
  await assert.rejects(vault.delete(job.organizationId,job.clientSecretRef,scope('other-platform','oauth_client_secret')),/connector_vault_unavailable/);
  await assert.rejects(vault.delete(job.organizationId,job.clientSecretRef,scope(job.platformId,'oauth_refresh_token')),/connector_vault_unavailable/);
  assert.notEqual(await vault.metadata(job.organizationId,job.clientSecretRef),null);
  const staged=await vault.stageRefreshResult(job,{accessToken:bundle.accessToken},Date.now()+3600000);
  assert.equal(staged.refreshTokenRef,job.refreshTokenRef,'omitted refresh result records old ref explicitly');
  assert.equal(await repository.publishRefresh(job.id,job.leaseId),true);
  assert.notEqual(await vault.metadata(job.organizationId,job.accessTokenRef),null,'a crash before cleanup retains old reference');
  await pool.query('UPDATE canvas_connector.secrets SET enabled=false WHERE organization_id=$1 AND reference=$2 RETURNING reference',[job.organizationId,job.accessTokenRef]);
  await vault.delete(job.organizationId,job.accessTokenRef,scope(job.platformId,'oauth_access_token'));
  await vault.delete(job.organizationId,job.accessTokenRef,scope(job.platformId,'oauth_access_token'));
  assert.equal(await vault.metadata(job.organizationId,job.accessTokenRef),null,'disabled/missing ciphertext cleanup is idempotent');
}
console.log('Staging and scoped vault reads/cleanup enforce exact tenant/platform/lease/purpose, retain omitted refresh refs and recover cleanup');

for(const mismatch of ['platform','purpose']) {
  const job=await refreshFixture('scope-worker-'+mismatch);
  await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ($1,'other','https://canvas.example.test',true) RETURNING id`,[job.organizationId]);
  const wrong=await vault.put(job.organizationId,{platformId:mismatch==='platform'?'other':job.platformId,provider:'canvas',purpose:mismatch==='purpose'?'oauth_access_token':'oauth_client_secret'},'synthetic-other-secret');
  let providerCalls=0;let deletions=0;
  const guardedVault={...vault,async delete(...args){deletions++;return vault.delete(...args);}};
  const worker=createRefreshWorker({repository:{...repository,async claimRefresh(){return {...job,clientSecretRef:wrong};}},secretVault:guardedVault,
    provider:{async refresh(){providerCalls++;throw Error('must not receive wrong secret');}}});
  assert.equal(await worker.runOnce(job.organizationId,job.platformId),'reconciliation_required');
  assert.equal(providerCalls,0);assert.equal(deletions,0);
  await repository.disconnect(job.organizationId,job.platformId);
  const wrongRevocation=await vault.put(job.organizationId,{platformId:mismatch==='platform'?'other':job.platformId,provider:'canvas',purpose:mismatch==='purpose'?'oauth_client_secret':'oauth_access_token'},'synthetic-wrong-revocation-secret');
  await pool.query('UPDATE canvas_connector.revocation_jobs SET access_token_ref=$1 WHERE organization_id=$2 RETURNING id',[wrongRevocation,job.organizationId]);
  const revoker=createRevocationWorker({repository:{...repository,async claimRevocation(){const value=await pool.query(`UPDATE canvas_connector.revocation_jobs SET lease_id=gen_random_uuid(),lease_until=clock_timestamp()+interval '1 minute' WHERE organization_id=$1 RETURNING id,lease_id AS "leaseId",organization_id AS "organizationId",platform_id AS "platformId",canvas_origin AS "canvasOrigin",access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef"`,[job.organizationId]);return value.rows[0];}},secretVault:guardedVault,
    provider:{async revoke(){providerCalls++;return true;}}});
  assert.equal(await revoker.runOnce(),'retry');
  assert.equal(providerCalls,0);assert.equal(deletions,0);
  assert.notEqual(await vault.metadata(job.organizationId,wrong),null);
}
console.log('Refresh/revocation workers never send wrong-platform or wrong-purpose secrets, and perform no deletion');

// Real composed adapter flow: public Gateway auth -> start HTTP -> PostgreSQL
// browser-bound state -> pinned Canvas HTTPS -> encrypted connection custody.
{
  const gateway=await httpsFixture();const canvas=await httpsFixture();let server;
  const org='60000000-0000-4000-8000-000000000001';const publicOrigin='https://connector.example.test';
  let permitted=true;let exchanges=0;
  try {
    gateway.setHandler((req,res)=>{
      assert.equal(req.headers.cookie,'session=synthetic-admin-session-token');
      assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers['x-organization-id'],undefined);
      if(req.url==='/v1/auth/me') json(res,{authenticated:true,user:{user_id:'synthetic-admin',organization_id:org}});
      else {assert.equal(req.url,`/v1/organizations/${org}/members/me/permissions`);json(res,{permissions:permitted?['integration-connector:edit']:[]});}
    });
    canvas.setHandler((req,res)=>{
      assert.equal(req.method,'POST');assert.equal(req.url,'/login/oauth2/token');
      assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
      let raw='';req.on('data',chunk=>{raw+=chunk;});req.on('end',()=>{
        const form=new URLSearchParams(raw);assert.equal(form.get('client_secret'),'synthetic-admin-client-secret');
        assert.equal(form.get('code'),'synthetic-browser-code');exchanges++;
        json(res,{access_token:'synthetic-admin-access-token',refresh_token:'synthetic-admin-refresh-token',expires_in:3600,token_type:'Bearer'});
      });
    });
    await pool.query(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ($1,'platform',$2,true) RETURNING id`,[org,canvas.origin]);
    const client=await vault.put(org,{platformId:'platform',provider:'canvas',purpose:'oauth_client_secret'},'synthetic-admin-client-secret');
    const lifecycle=createCanvasOAuthLifecycle({publicOrigin,completionUrl:publicOrigin+'/complete',repository,secretVault:vault,
      provider:createCanvasOAuthProvider({allowedPrivateAddresses:['127.0.0.1','::1'],ca:canvas.ca})});
    const start=createOAuthAdminHandler({lifecycle,adminOrigin:publicOrigin,rateLimiter:{consume:async()=>true},
      authenticateAndAuthorize:createGatewayAdminAuthenticator({gatewayOrigin:gateway.origin,adminOrigin:publicOrigin,sessionCookieName:'session',ca:gateway.ca})});
    const callback=createOAuthCallbackHandler({lifecycle,completionUrl:publicOrigin+'/complete',rateLimiter:{consume:async()=>true}});
    server=createServer((request,response)=>request.url.startsWith('/oauth/callback')?callback(request,response):start(request,response));
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const send=(path,method,headers,body='')=>new Promise((resolve,reject)=>{
      const request=httpRequest({host:'127.0.0.1',port:server.address().port,path,method,headers},response=>{
        let output='';response.on('data',chunk=>{output+=chunk;});response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:output}));
      });request.on('error',reject);request.end(body);
    });
    const form=new URLSearchParams({client_id:'synthetic-client',client_secret_ref:client,capabilities:'catalog'}).toString();
    const headers={Origin:publicOrigin,'Content-Type':'application/x-www-form-urlencoded',Cookie:'session=synthetic-admin-session-token'};
    permitted=false;
    const denied=await send('/platforms/platform/oauth/start','POST',headers,form);
    assert.equal(denied.status,403);assert.equal(denied.headers['set-cookie'],undefined);
    permitted=true;
    const result=await send('/platforms/platform/oauth/start','POST',headers,form);assert.equal(result.status,200);
    const authorization=new URL(JSON.parse(result.body).authorizationUrl);assert.equal(authorization.origin,canvas.origin);
    const state=authorization.searchParams.get('state');const cookie=result.headers['set-cookie'][0].split(';')[0];
    assert.equal(result.body.includes(cookie.split('=')[1]),false);
    const path='/oauth/callback?'+new URLSearchParams({state,code:'synthetic-browser-code'});
    const wrongBrowser=await send(path,'GET',{});assert.equal(wrongBrowser.status,400);assert.equal(exchanges,0);
    const completed=await send(path,'GET',{Cookie:cookie});assert.equal(completed.status,303);
    assert.equal(new URL(completed.headers.location).searchParams.get('outcome'),'connected');assert.equal(exchanges,1);
    const durable=await repository.connection(org,'platform');assert.ok(durable);
    assert.equal(await vault.get(org,durable.accessTokenRef,{platformId:'platform',provider:'canvas',purpose:'oauth_access_token'}),'synthetic-admin-access-token');
    const replay=await send(path,'GET',{Cookie:cookie});assert.equal(replay.status,303);
    assert.equal(new URL(replay.headers.location).searchParams.get('error_code'),'oauth_state_invalid');assert.equal(exchanges,1);
    permitted=false;assert.equal((await send('/platforms/platform/oauth/start','POST',headers,form)).status,403);
  } finally {
    if(server) await new Promise(resolve=>server.close(resolve));await gateway.close();await canvas.close();
  }
}
console.log('Public Gateway session/permission + HTTP start/callback + PostgreSQL browser binding + pinned Canvas + encrypted custody composition passed');
