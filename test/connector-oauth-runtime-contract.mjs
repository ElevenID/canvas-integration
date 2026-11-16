// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, basename, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { request } from 'node:https';
import { setImmediate } from 'node:timers/promises';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { createOAuthHttpRateLimiter } from '../src/oauth-http-rate-limiter.mjs';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';
import { createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile } from '../src/file-credentials.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';
const file = process.argv[2], container = process.argv[3], baoContainer = process.argv[4];
assert.match(file ?? '', /canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);
assert.match(container ?? '', /^canvas-pg-driver-[a-f0-9]{32}$/);
assert.match(baoContainer ?? '', /^canvas-pg-key-[a-f0-9]{32}$/);
assert.equal(container.slice('canvas-pg-driver-'.length), baoContainer.slice('canvas-pg-key-'.length));
const f = JSON.parse(await readFile(file, 'utf8'));
const directory = dirname(resolve(file));
assert.equal(dirname(directory), resolve(tmpdir())); assert.match(basename(directory), /^canvas-driver-contract-/);
const passwordFile = join(directory, 'agent-database-password'), httpPasswordFile = join(directory, 'agent-http-password');
const tokenFile = join(directory, 'agent-openbao-token');
const fileCustody = process.platform !== 'win32';
async function replacePrivate(path, value) {
  await writeFile(path + '.next', value + '\n', { mode: 0o600 }); await rename(path + '.next', path);
}
if (fileCustody) {
  assert.equal(typeof f.baoFileToken, 'string');
  await replacePrivate(passwordFile, 'synthetic-driver-runtime');
  await replacePrivate(httpPasswordFile, 'synthetic-oauth-http-password');
  await replacePrivate(tokenFile, f.baoFileToken);
}
// Windows does not qualify POSIX agent files. Its existing physical fixture
// retains explicit synthetic providers; production file providers never fall back.
const database = { host: 'localhost', port: f.port, database: 'canvas_driver_test', user: 'canvas_runtime', ca: f.ca,
  credentialProvider: fileCustody ? createConnectorDatabasePasswordFile({ path: passwordFile })
    : { getPassword: async () => 'synthetic-driver-runtime' }, maxConnections: 16,
  connectTimeoutMs: 1000, queryTimeoutMs: 5000 };
const keyCustody = { openbaoOrigin: f.baoOrigin, mount: 'connector-kv', keyPath: 'canvas-envelope', keyNamespace: 'canvas',
  ca: f.baoCa, tokenProvider: fileCustody ? createConnectorOpenBaoTokenFile({ path: tokenFile })
    : { getToken: async () => f.baoToken } };
const pool = createConnectorPostgresPool(database);
const vault = createEncryptedVault({ pool, keyProvider: createOpenBaoKeyProvider(keyCustody) });
const owner = sql => execFileSync('docker', ['exec', '-i', container, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'canvas_driver_test'], { input: sql, stdio: ['pipe', 'pipe', 'pipe'] });
const canvas = await httpsFixture(), gateway = await httpsFixture();
const org = '750e8400-e29b-41d4-a716-446655440001';
const CLIENT = 'synthetic_runtime_client_secret_00001';
const ACCESS = 'synthetic_runtime_access_token_000001', REFRESH = 'synthetic_runtime_refresh_token_00001';
const origin = 'https://localhost';
let permitted = true, exchanges = 0, requestBody;
let entered, release;
const exchangeEntered = new Promise(resolve => { entered = resolve; });
const exchangeRelease = new Promise(resolve => { release = resolve; });
gateway.setHandler((req, res) => {
  if (req.url === '/v1/auth/me') return json(res, { authenticated: true, user: { user_id: 'actor', organization_id: org } });
  if (req.url === `/v1/organizations/${org}/members/me/permissions`) return json(res, { permissions: permitted ? ['integration-connector:edit'] : [] });
  res.writeHead(404); res.end();
});
canvas.setHandler(async (req, res) => {
  assert.equal(req.url, '/login/oauth2/token'); assert.equal(req.method, 'POST');
  assert.equal(req.headers['x-api-key'], undefined); assert.equal(req.headers.cookie, undefined);
  const chunks = []; for await (const chunk of req) chunks.push(chunk);
  requestBody = new URLSearchParams(Buffer.concat(chunks).toString()); exchanges++; entered();
  await exchangeRelease;
  json(res, { access_token: ACCESS, refresh_token: REFRESH, expires_in: 3600, token_type: 'Bearer' });
});
const configuration = {
  database, keyCustody, canvas: { ca: canvas.ca, allowedPrivateAddresses: ['127.0.0.1', '::1'], timeoutMs: 10000 },
  gatewayAuthentication: { gatewayOrigin: gateway.origin, ca: gateway.ca, sessionCookieName: 'session' },
  http: { publicOrigin: origin, completionUrl: origin + '/complete', tls: { key: canvas.key, cert: canvas.ca }, port: 0 },
};
const runtimes = [];
async function runtime(overrides = {}) {
  const value = await createConnectorOAuthRuntime({ ...configuration, ...overrides }); runtimes.push(value); return value;
}
function send(address, { path = '/platforms/runtime-platform/oauth/start', method = 'POST', body, cookie = 'session=abcdefghijklmnop' } = {}) {
  let req;
  const response = new Promise((resolve, reject) => {
    req = request({ hostname: 'localhost', servername: 'localhost', family: 4, port: address.port, ca: canvas.ca, agent: false,
      method, path, headers: { Host: 'localhost', Origin: origin, Cookie: cookie,
        'Content-Type': 'application/x-www-form-urlencoded', 'X-Organization-ID': 'untrusted-org' } }, res => {
      let body = ''; res.setEncoding('utf8'); res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body })); res.on('error', reject);
    });
    req.on('error', reject); req.end(body);
  });
  return { request: req, response };
}
try {
  // Real concurrent callers, including a separate role/pool, share one budget.
  owner("UPDATE canvas_connector.oauth_http_limit SET request_limit=3,window_ms=60000,hits=0,window_started_at=clock_timestamp();");
  const limiter = createOAuthHttpRateLimiter(pool);
  const admitted = await Promise.all(Array.from({ length: 8 }, () => limiter.consume('ignored-client-address')));
  assert.equal(admitted.filter(Boolean).length, 3);
  assert.equal((await pool.query('SELECT hits FROM canvas_connector.oauth_http_limit')).rows[0].hits, 3);
  owner("CREATE ROLE canvas_counter LOGIN PASSWORD 'synthetic-counter-password'; GRANT CONNECT ON DATABASE canvas_driver_test TO canvas_counter; GRANT USAGE ON SCHEMA canvas_connector TO canvas_counter; GRANT SELECT ON canvas_connector.oauth_http_limit TO canvas_counter; GRANT UPDATE(hits,window_started_at) ON canvas_connector.oauth_http_limit TO canvas_counter; GRANT EXECUTE ON FUNCTION canvas_connector.consume_oauth_http_limit() TO canvas_counter;");
  const counterPool = createConnectorPostgresPool({ ...database, user: 'canvas_counter', credentialProvider: { getPassword: async () => 'synthetic-counter-password' } });
  try {
    assert.equal(await createOAuthHttpRateLimiter(counterPool).consume(), false);
    await assert.rejects(counterPool.query('SELECT * FROM canvas_connector.secrets'));
    await assert.rejects(counterPool.query('UPDATE canvas_connector.oauth_http_limit SET request_limit=1000'));
    await assert.rejects(counterPool.query('DELETE FROM canvas_connector.oauth_http_limit'));
    owner("UPDATE canvas_connector.oauth_http_limit SET window_started_at=clock_timestamp()+interval '10 seconds';");
    assert.equal(await limiter.consume(), false);
    owner("UPDATE canvas_connector.oauth_http_limit SET window_started_at=clock_timestamp()-interval '61 seconds';");
    assert.equal(await createOAuthHttpRateLimiter(counterPool).consume(), true);
    assert.equal((await pool.query('SELECT hits FROM canvas_connector.oauth_http_limit')).rows[0].hits, 1);
  } finally { await counterPool.close(); }
  owner("UPDATE canvas_connector.oauth_http_limit SET request_limit=60,hits=0,window_started_at=clock_timestamp();");
  await pool.query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ($1,$2,$3,true)', [org, 'runtime-platform', canvas.origin]);
  const scope = { platformId: 'runtime-platform', provider: 'canvas', purpose: 'oauth_client_secret' };
  const reference = await vault.put(org, scope, CLIENT);
  owner(`CREATE ROLE canvas_oauth_http LOGIN PASSWORD 'synthetic-oauth-http-password';
    GRANT CONNECT ON DATABASE canvas_driver_test TO canvas_oauth_http;
    GRANT USAGE ON SCHEMA canvas_connector TO canvas_oauth_http;
    GRANT SELECT ON canvas_connector.platforms,canvas_connector.oauth_http_limit TO canvas_oauth_http;
    GRANT SELECT,INSERT,DELETE ON canvas_connector.secrets,canvas_connector.authorizations TO canvas_oauth_http;
    GRANT SELECT,INSERT,UPDATE ON canvas_connector.oauth_status,canvas_connector.connections TO canvas_oauth_http;
    GRANT UPDATE(hits,window_started_at) ON canvas_connector.oauth_http_limit TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.consume_oauth_http_limit(),
      canvas_connector.consume_authorization(text,text),
      canvas_connector.mark_authorization_pending(text,text,bigint,text),
      canvas_connector.check_connection_configuration() TO canvas_oauth_http;`);
  const httpDatabase = { ...database, user: 'canvas_oauth_http',
    credentialProvider: fileCustody ? createConnectorDatabasePasswordFile({ path: httpPasswordFile })
      : { getPassword: async () => 'synthetic-oauth-http-password' } };
  const missingLockPrivilege = await runtime({ database: httpDatabase });
  await assert.rejects(missingLockPrivilege.listen(), { message: 'connector_oauth_runtime_unavailable' });
  // UPDATE(id) permits the required row locks. The immutable identity trigger
  // prevents changing id, and no platform definition column is updateable.
  owner('GRANT UPDATE(id) ON canvas_connector.platforms TO canvas_oauth_http;');
  configuration.database = httpDatabase;
  const httpPool = createConnectorPostgresPool(httpDatabase);
  try {
    await assert.rejects(httpPool.query("UPDATE canvas_connector.platforms SET canvas_origin='https://evil.example.test'"));
    await assert.rejects(httpPool.query("UPDATE canvas_connector.platforms SET id='renamed-platform' WHERE id='runtime-platform'"));
    await assert.rejects(httpPool.query('DELETE FROM canvas_connector.platforms'));
    await assert.rejects(httpPool.query('SELECT * FROM canvas_connector.refresh_attempts'));
    assert.equal((await httpPool.query("SELECT has_schema_privilege(current_user,'canvas_connector','CREATE') AS allowed")).rows[0].allowed, false);
  } finally { await httpPool.close(); }
  const server = await runtime(); const address = await server.listen();
  const started = await send(address, { body: new URLSearchParams({ client_id: 'runtime-client', client_secret_ref: reference, capabilities: 'catalog' }).toString() }).response;
  assert.equal(started.status, 200);
  const authorization = new URL(JSON.parse(started.body).authorizationUrl);
  assert.equal(authorization.origin, canvas.origin);
  const state = authorization.searchParams.get('state'), cookie = started.headers['set-cookie'][0].split(';')[0];
  const callback = `/oauth/callback?state=${state}&code=synthetic-runtime-code`;
  assert.equal((await send(address, { path: callback, method: 'GET' }).response).status, 400);
  const pending = await pool.query('SELECT organization_id,browser_binding_hash FROM canvas_connector.authorizations WHERE organization_id=$1', [org]);
  assert.equal(pending.rows.length, 1); assert.equal(pending.rows[0].organization_id, org);
  const completed = send(address, { path: callback, method: 'GET', cookie });
  const aborted = assert.rejects(completed.response);
  await exchangeEntered; completed.request.destroy(); await aborted;
  let closed = false; const stopping = server.close().then(() => { closed = true; });
  await setImmediate(); assert.equal(closed, false);
  release(); await stopping;
  const connection = (await pool.query('SELECT client_secret_ref,access_token_ref,refresh_token_ref FROM canvas_connector.connections WHERE organization_id=$1 AND platform_id=$2', [org, 'runtime-platform'])).rows[0];
  assert.ok(connection); assert.equal(connection.client_secret_ref, reference);
  assert.equal(await vault.get(org, connection.access_token_ref, { ...scope, purpose: 'oauth_access_token' }), ACCESS);
  assert.equal(await vault.get(org, connection.refresh_token_ref, { ...scope, purpose: 'oauth_refresh_token' }), REFRESH);
  assert.equal(requestBody.get('client_secret'), CLIENT); assert.equal(requestBody.get('code'), 'synthetic-runtime-code');
  assert.equal(requestBody.get('redirect_uri'), origin + '/oauth/callback');
  const second = await runtime(); const secondAddress = await second.listen();
  const replay = await send(secondAddress, { path: callback, method: 'GET', cookie }).response;
  assert.equal(replay.status, 303); assert.equal(new URL(replay.headers.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(exchanges, 1);
  assert.ok(gateway.seen.every(r => r.headers.cookie === 'session=abcdefghijklmnop' && !r.headers['x-api-key'] && !r.headers.authorization));
  assert.ok(gateway.seen.every(r => !r.url.includes(ACCESS) && !r.url.includes(CLIENT)));
  permitted = false;
  assert.equal((await send(secondAddress, { body: 'client_id=runtime-client' }).response).status, 403);
  const before = gateway.seen.length;
  owner('REVOKE EXECUTE ON FUNCTION canvas_connector.consume_oauth_http_limit() FROM canvas_oauth_http;');
  assert.equal((await send(secondAddress).response).status, 503); assert.equal(gateway.seen.length, before);
  owner('GRANT EXECUTE ON FUNCTION canvas_connector.consume_oauth_http_limit() TO canvas_oauth_http;');
  owner("UPDATE canvas_connector.oauth_http_limit SET request_limit=1,hits=1,window_started_at=clock_timestamp();");
  assert.equal((await send(secondAddress).response).status, 429); assert.equal(gateway.seen.length, before);
  await second.close();
  if (fileCustody) {
    owner("ALTER ROLE canvas_oauth_http PASSWORD 'synthetic-oauth-http-rotated';");
    await replacePrivate(httpPasswordFile, 'synthetic-oauth-http-rotated');
    const rotated = await runtime(); await rotated.listen(); await rotated.close();
    await replacePrivate(httpPasswordFile, 'synthetic-oauth-http-password');
    const stale = await runtime(); await assert.rejects(stale.listen(), { message: 'connector_oauth_runtime_unavailable' });
    await replacePrivate(httpPasswordFile, 'synthetic-oauth-http-rotated');
    execFileSync('docker', ['exec', '-e', 'BAO_ADDR=https://127.0.0.1:8200', '-e', 'BAO_CACERT=/tmp/canvas-tls/vault-ca.pem',
      '-e', 'BAO_TOKEN=synthetic-driver-key-bootstrap', baoContainer, 'bao', 'token', 'revoke', f.baoFileToken], { stdio: ['ignore', 'pipe', 'pipe'] });
    const revokedAgent = await runtime(); await assert.rejects(revokedAgent.listen(), { message: 'connector_oauth_runtime_unavailable' });
    await replacePrivate(tokenFile, f.baoToken);
    const renewed = await runtime(); await renewed.listen(); await renewed.close();
    console.log('Actual POSIX agent-file custody and PostgreSQL password/OpenBao token rotation contracts passed');
  } else console.log('POSIX agent-file rotation not qualified on this Windows host; explicit synthetic providers used in the physical fixture');
  const denied = await runtime({ keyCustody: { ...keyCustody, tokenProvider: { getToken: async () => 'synthetic-invalid-bao-token' } } });
  await assert.rejects(denied.listen(), { message: 'connector_oauth_runtime_unavailable' });
  const badPassword = await runtime({ database: { ...database, credentialProvider: { getPassword: async () => 'synthetic-wrong-password' } } });
  await assert.rejects(badPassword.listen(), { message: 'connector_oauth_runtime_unavailable' });
  owner('ALTER TABLE canvas_connector.oauth_http_limit RENAME TO oauth_http_limit_unavailable;');
  try { const missing = await runtime(); await assert.rejects(missing.listen(), { message: 'connector_oauth_runtime_unavailable' }); }
  finally { owner('ALTER TABLE canvas_connector.oauth_http_limit_unavailable RENAME TO oauth_http_limit;'); }
  console.log('Actual HTTPS OAuth runtime: PostgreSQL/OpenBao/encrypted vault/Canvas exchange, distributed rate limit, disconnected-client commit, replay and custody failure contracts passed');
} finally {
  release();
  for (const server of runtimes) await server.close();
  await pool.close(); await canvas.close(); await gateway.close();
}
