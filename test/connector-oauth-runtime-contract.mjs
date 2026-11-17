// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, basename, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { request } from 'node:https';
import { createConnection } from 'node:net';
import { randomUUID } from 'node:crypto';
import { setImmediate, setTimeout as pause } from 'node:timers/promises';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { createOAuthHttpRateLimiter } from '../src/oauth-http-rate-limiter.mjs';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';
import { createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile } from '../src/file-credentials.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';
import { captureRouteHttpContract } from './capture-route-http-contract.mjs';
import { ltiServiceHttpContract } from './lti-service-http-contract.mjs';
import { ltiRuntimeHttpContract } from './lti-runtime-http-contract.mjs';
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
const canvas = await httpsFixture(), gateway = await httpsFixture(), ltiPeer=await httpsFixture();
const org = '750e8400-e29b-41d4-a716-446655440001';
const CLIENT = 'synthetic_runtime_client_secret_00001';
const ACCESS = 'synthetic_runtime_access_token_000001', REFRESH = 'synthetic_runtime_refresh_token_00001';
const origin = 'https://localhost';
let permitted = true, exchanges = 0, requestBody;
let entered, release;
const exchangeEntered = new Promise(resolve => { entered = resolve; });
const exchangeRelease = new Promise(resolve => { release = resolve; });
const bindings=new Map();let bindingAllowed=true;
gateway.setHandler(async (req, res) => {
  if (req.url === '/v1/auth/me') return json(res, { authenticated: true, user: { user_id: 'actor', organization_id: org } });
  if (req.url === `/v1/organizations/${org}/members/me/permissions`) return json(res, { permissions: permitted ? ['integration-connector:edit'] : [] });
  if(req.method==='POST' && req.url.startsWith(`/v1/organizations/${org}/external-observation-bindings/`) && req.url.endsWith('/inspect')) {
    assert.equal(req.headers.origin,origin);assert.equal(req.headers.cookie,'session=abcdefghijklmnop');
    assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers['x-organization-id'],undefined);
    let body='';for await(const chunk of req) body+=chunk;assert.equal(body,'{}');
    if(!bindingAllowed) return json(res,{detail:'synthetic binding permission denied'},403);
    const binding=req.url.split('/').at(-2),record=bindings.get(binding)??null;
    return json(res,{found:record!==null,record,snapshot_at_ms:Date.now()},200,{'Cache-Control':'no-store'});
  }
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
async function cliRuntime() {
  const caPaths = {};
  for (const [name, value] of Object.entries({ database: f.ca, vault: f.baoCa, canvas: canvas.ca, gateway: gateway.ca })) {
    caPaths[name] = join(directory, `bootstrap-${name}-ca.pem`); await replacePrivate(caPaths[name], value);
  }
  const tlsKeyFile = join(directory, 'bootstrap-tls-key.pem'), tlsCertificateFile = join(directory, 'bootstrap-tls-cert.pem');
  await replacePrivate(tlsKeyFile, canvas.key); await replacePrivate(tlsCertificateFile, canvas.ca);
  const { ca: _databaseCa, credentialProvider: _passwordProvider, ...databaseOptions } = configuration.database;
  const { ca: _keyCa, tokenProvider: _tokenProvider, ...keyOptions } = configuration.keyCustody;
  const { ca: _canvasCa, ...canvasOptions } = configuration.canvas;
  const { ca: _gatewayCa, ...gatewayOptions } = configuration.gatewayAuthentication;
  const { tls: _tls, ...httpOptions } = configuration.http;
  const configFile = join(directory, 'bootstrap-service.json');
  const ltiCaFile=join(directory,'bootstrap-lti-ca.pem');
  if(configuration.lti) await replacePrivate(ltiCaFile,configuration.lti.ca);
  await replacePrivate(configFile, JSON.stringify({ schemaVersion: 1,
    database: { ...databaseOptions, passwordFile: httpPasswordFile, caFile: caPaths.database },
    keyCustody: { ...keyOptions, tokenFile, caFile: caPaths.vault },
    canvas: { ...canvasOptions, caFile: caPaths.canvas },
    ...(configuration.lti?{lti:{selfManagedOriginAllowlist:configuration.lti.selfManagedOriginAllowlist,
      allowedPrivateAddresses:configuration.lti.allowedPrivateAddresses,timeoutMs:configuration.lti.timeoutMs,caFile:ltiCaFile}}:{}),
    gatewayAuthentication: { ...gatewayOptions, caFile: caPaths.gateway },
    http: { ...httpOptions, tlsKeyFile, tlsCertificateFile },
  }));
  const environment = Object.fromEntries(Object.entries({ PATH: process.env.PATH, HOME: process.env.HOME,
    LANG: process.env.LANG, CANVAS_CONNECTOR_CONFIG_FILE: configFile }).filter(([, value]) => typeof value === 'string'));
  const child = spawn(process.execPath, [fileURLToPath(new URL('../bin/serve-oauth.mjs', import.meta.url))],
    { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', pending = '', started = false, stopped = false, port, accept, reject, closing;
  const listening = new Promise((resolve, fail) => { accept = resolve; reject = fail; });
  void listening.catch(() => {});
  const watchdog = setTimeout(() => { reject(Error('synthetic_cli_watchdog')); child.kill('SIGKILL'); }, 20000);
  child.on('error', () => reject(Error('synthetic_cli_start_failed')));
  child.stdout.on('data', chunk => {
    stdout += chunk; pending += chunk;
    if (Buffer.byteLength(stdout) > 4096) { reject(Error('synthetic_cli_output_bound')); child.kill('SIGKILL'); return; }
    while (pending.includes('\n')) {
      const index = pending.indexOf('\n'), line = pending.slice(0, index); pending = pending.slice(index + 1);
      try {
        const value = JSON.parse(line);
        if (value.state === 'listening' && Number.isInteger(value.port)) { started = true; port = value.port; accept({ port }); }
        else if (value.state === 'stopped') stopped = true;
        else throw Error();
      } catch { reject(Error('synthetic_cli_protocol_failed')); }
    }
  });
  child.stderr.on('data', chunk => { stderr += chunk; if (Buffer.byteLength(stderr) > 4096) child.kill('SIGKILL'); });
  const exited = new Promise(resolve => child.on('close', (code, signal) => {
    clearTimeout(watchdog); if (!started) reject(Error(`synthetic_cli_start_failed: ${stderr}`)); resolve({ code, signal });
  }));
  const server = { listen: () => listening, async waitUntilDraining() {
    const deadline = performance.now() + 3000;
    while (performance.now() < deadline) {
      assert.equal(child.exitCode, null); assert.equal(child.signalCode, null); assert.equal(stopped, false);
      const refused = await new Promise((resolve, fail) => {
        const socket = createConnection({ host: '127.0.0.1', port }); let finished = false;
        const finish = (error, value) => { if (finished) return; finished = true; socket.destroy(); error ? fail(error) : resolve(value); };
        socket.once('connect', () => finish(null, false));
        socket.once('error', error => {
          if (error.code === 'ECONNREFUSED') finish(null, true);
          // A connection can race listener closure. Reset is inconclusive:
          // retry within the deadline and still require actual refusal.
          else if (error.code === 'ECONNRESET') finish(null, false);
          else finish(Error(`synthetic_cli_probe_failed:${error.code}`));
        });
        socket.setTimeout(200, () => finish(Error('synthetic_cli_probe_timeout')));
      });
      if (refused) {
        assert.equal(child.exitCode, null); assert.equal(child.signalCode, null); assert.equal(stopped, false); return;
      }
      await pause(10);
    }
    throw Error('synthetic_cli_drain_not_observed');
  }, close() {
    if (closing) return closing;
    if (child.exitCode === null && !child.killed) child.kill('SIGTERM');
    closing = (async () => {
      const outcome = await exited;
      if (started) { assert.deepEqual(outcome, { code: 0, signal: null }); assert.equal(stopped, true); assert.equal(stderr, ''); }
      for (const secret of [CLIENT, ACCESS, REFRESH, f.baoToken, f.baoFileToken]) {
        if (secret) assert.equal(stdout.includes(secret) || stderr.includes(secret), false);
      }
    })();
    return closing;
  } };
  runtimes.push(server); return server;
}
async function runtime(overrides = {}) {
  const value = await createConnectorOAuthRuntime({ ...configuration, ...overrides }); runtimes.push(value); return value;
}
function send(address, { path = '/platforms/runtime-platform/oauth/start', method = 'POST', body, cookie = 'session=abcdefghijklmnop',requestOrigin=origin } = {}) {
  let req;
  const response = new Promise((resolve, reject) => {
    req = request({ hostname: 'localhost', servername: 'localhost', family: 4, port: address.port, ca: canvas.ca, agent: false,
      method, path, headers: { Host: 'localhost', Origin: requestOrigin, Cookie: cookie,
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
  // Keep cold connection acquisitions within the file provider's four-read bound.
  const admitted = [];
  for (let batch = 0; batch < 2; batch++) {
    admitted.push(...await Promise.all(Array.from({ length: 4 }, () => limiter.consume('ignored-client-address'))));
  }
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
  let reference;
  owner(`CREATE ROLE canvas_oauth_http LOGIN PASSWORD 'synthetic-oauth-http-password';
    GRANT CONNECT ON DATABASE canvas_driver_test TO canvas_oauth_http;
    GRANT USAGE ON SCHEMA canvas_connector TO canvas_oauth_http;
    GRANT SELECT ON canvas_connector.platforms,canvas_connector.oauth_http_limit TO canvas_oauth_http;
    GRANT INSERT ON canvas_connector.platforms TO canvas_oauth_http;
    GRANT SELECT ON canvas_connector.rest_capture_routes,canvas_connector.rest_route_operation_audit TO canvas_oauth_http;
    GRANT INSERT(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled) ON canvas_connector.rest_capture_routes TO canvas_oauth_http;
    GRANT UPDATE(binding_revision,requirement,claim_names,effective_time_policy,enabled) ON canvas_connector.rest_capture_routes TO canvas_oauth_http;
    GRANT INSERT(organization_id,operation_id,platform_id,route_id,actor_id,action,request,receipt) ON canvas_connector.rest_route_operation_audit TO canvas_oauth_http;
    GRANT INSERT(organization_id,capture_id,producer_ref,route_id,route_version,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy) ON canvas_connector.rest_capture_jobs TO canvas_oauth_http;
    GRANT SELECT(organization_id,capture_id,producer_ref,route_id,route_version,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,phase,attempts,available_at,lease_id,lease_expires_at,last_error) ON canvas_connector.rest_capture_jobs TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.valid_rest_route(jsonb,text[]),canvas_connector.administer_rest_route(text,text,text,uuid,text,text,bigint,bigint,jsonb) TO canvas_oauth_http;
    GRANT SELECT,INSERT ON canvas_connector.platform_operation_audit TO canvas_oauth_http;
    GRANT SELECT,INSERT ON canvas_connector.oauth_client_configurations,canvas_connector.oauth_client_provisioning_audit TO canvas_oauth_http;
    GRANT UPDATE(client_id,client_secret_ref,platform_config_version) ON canvas_connector.oauth_client_configurations TO canvas_oauth_http;
    GRANT SELECT,INSERT ON canvas_connector.secrets TO canvas_oauth_http;
    GRANT SELECT,INSERT,DELETE ON canvas_connector.authorizations TO canvas_oauth_http;
    GRANT SELECT,INSERT,UPDATE ON canvas_connector.authorization_attempts TO canvas_oauth_http;
    GRANT SELECT,INSERT ON canvas_connector.authorization_recovery_audit,canvas_connector.revocation_jobs TO canvas_oauth_http;
    GRANT SELECT,INSERT,UPDATE ON canvas_connector.oauth_status,canvas_connector.connections TO canvas_oauth_http;
    GRANT DELETE ON canvas_connector.connections TO canvas_oauth_http;
    GRANT SELECT(organization_id,platform_id,phase,lease_until) ON canvas_connector.refresh_attempts TO canvas_oauth_http;
    GRANT SELECT,INSERT ON canvas_connector.connection_operation_audit TO canvas_oauth_http;
    GRANT UPDATE(hits,window_started_at) ON canvas_connector.oauth_http_limit TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.consume_oauth_http_limit(),
      canvas_connector.consume_authorization_attempt(text,text),
      canvas_connector.begin_authorization_exchange(text,text,text),
      canvas_connector.require_authorization_reconciliation(text,text,text),
      canvas_connector.publish_authorization_connection(text,text,text),
      canvas_connector.recover_authorization_attempt(text,text,text,bigint,uuid,text,text) TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.disconnect_connection(text,text,uuid,bigint,uuid,text) TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.administer_platform(text,text,uuid,text,text,text,bigint,boolean,boolean) TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.provision_oauth_client(text,text,uuid,text,bigint,text,text,text,bytea,bytea,bytea,bytea) TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION
      canvas_connector.stage_authorization_result(text,text,text,text,text,bytea,bytea,bytea,text,text,bytea,bytea,bytea,timestamptz),
      canvas_connector.mark_authorization_pending(text,text,bigint,text),
      canvas_connector.check_connection_configuration() TO canvas_oauth_http;`);
  const httpDatabase = { ...database, user: 'canvas_oauth_http',
    credentialProvider: fileCustody ? createConnectorDatabasePasswordFile({ path: httpPasswordFile })
      : { getPassword: async () => 'synthetic-oauth-http-password' } };
  const missingLockPrivilege = await runtime({ database: httpDatabase });
  await assert.rejects(missingLockPrivilege.listen(), { message: 'connector_oauth_runtime_unavailable' });
  // Configuration administration updates only enabled/archive flags. These
  // rights also permit row locks; origin and stable platform ID remain denied.
  owner('GRANT UPDATE(enabled,archived) ON canvas_connector.platforms TO canvas_oauth_http;');
  const missingSecretLockPrivilege = await runtime({ database: httpDatabase });
  await assert.rejects(missingSecretLockPrivilege.listen(), { message: 'connector_oauth_runtime_unavailable' });
  owner('GRANT UPDATE(created_at) ON canvas_connector.secrets TO canvas_oauth_http;');
  owner('ALTER TABLE canvas_connector.secrets DISABLE TRIGGER secret_creation_time;');
  try {
    const missingGuard = await runtime({ database: httpDatabase });
    await assert.rejects(missingGuard.listen(), { message: 'connector_oauth_runtime_unavailable' });
  } finally { owner('ALTER TABLE canvas_connector.secrets ENABLE TRIGGER secret_creation_time;'); }
  for(const [table,trigger] of [['connections','connection_identity'],['authorization_attempts','authorization_cleanup'],
    ['connection_operation_audit','connection_operation_audit_immutable'],['platforms','platform_configuration_revision'],
    ['platform_operation_audit','platform_operation_audit_immutable'],['oauth_client_provisioning_audit','oauth_client_provisioning_audit_immutable'],
    ['rest_capture_routes','rest_route_revision'],['rest_capture_jobs','rest_capture_immutable'],['rest_route_operation_audit','rest_route_operation_audit_immutable']]) {
    owner(`ALTER TABLE canvas_connector.${table} DISABLE TRIGGER ${trigger};`);
    try {
      const missingGuard=await runtime({database:httpDatabase});
      await assert.rejects(missingGuard.listen(),{message:'connector_oauth_runtime_unavailable'});
    } finally {owner(`ALTER TABLE canvas_connector.${table} ENABLE TRIGGER ${trigger};`);}
  }
  configuration.database = httpDatabase;
  const lti={selfManagedOriginAllowlist:[ltiPeer.origin],allowedPrivateAddresses:['127.0.0.1','::1'],ca:ltiPeer.ca,timeoutMs:5000};
  const missingLti=await runtime({lti});
  await assert.rejects(missingLti.listen(),{message:'connector_oauth_runtime_unavailable'});
  owner(`GRANT SELECT ON canvas_connector.lti_registrations,canvas_connector.lti_launch_states,
    canvas_connector.lti_launch_receipts,canvas_connector.lti_registration_operation_audit TO canvas_oauth_http;
    GRANT INSERT(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
      ON canvas_connector.lti_registrations TO canvas_oauth_http;
    GRANT UPDATE(client_id,deployment_id,trust_profile,environment,target_link_uri,enabled,updated_at)
      ON canvas_connector.lti_registrations TO canvas_oauth_http;
    GRANT INSERT(state_hash,launch_id,browser_hash,organization_id,platform_id,registration_id,platform_version,registration_version,registration_snapshot,nonce)
      ON canvas_connector.lti_launch_states TO canvas_oauth_http;
    GRANT UPDATE(phase,token_hash,protocol_claims,accepted_at) ON canvas_connector.lti_launch_states TO canvas_oauth_http;
    GRANT INSERT(state_hash,launch_id,token_hash,receipt) ON canvas_connector.lti_launch_receipts TO canvas_oauth_http;
    GRANT INSERT(organization_id,operation_id,platform_id,registration_id,actor_id,action,request,receipt)
      ON canvas_connector.lti_registration_operation_audit TO canvas_oauth_http;
    GRANT SELECT ON canvas_connector.lti_provider_identities,canvas_connector.lti_provider_identity_claims,
      canvas_connector.lti_provider_identity_observations TO canvas_oauth_http;
    GRANT INSERT(id,organization_id,platform_id,issuer,client_id,deployment_id,subject) ON canvas_connector.lti_provider_identities TO canvas_oauth_http;
    GRANT UPDATE(canvas_user_id,status) ON canvas_connector.lti_provider_identities TO canvas_oauth_http;
    GRANT INSERT(identity_id,canvas_user_id) ON canvas_connector.lti_provider_identity_claims TO canvas_oauth_http;
    GRANT INSERT(state_hash,launch_id,identity_id,token_hash,canvas_user_id,receipt) ON canvas_connector.lti_provider_identity_observations TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.observe_lti_provider_identity(uuid,text,text,uuid) TO canvas_oauth_http;
    GRANT EXECUTE ON FUNCTION canvas_connector.lti_visible_identifier(text),canvas_connector.lti_numeric_date(jsonb),canvas_connector.lti_canvas_user_id(text),
      canvas_connector.lti_claims_match(jsonb,canvas_connector.lti_registrations,canvas_connector.platforms,text),
      canvas_connector.begin_lti_launch(uuid,bigint,bigint,text,text,text,uuid),canvas_connector.stage_lti_launch(text,text,jsonb),
      canvas_connector.confirm_lti_launch(text,text,text),canvas_connector.administer_lti_registration(text,text,text,uuid,uuid,text,bigint,bigint,jsonb)
      TO canvas_oauth_http;`);
  for(const [table,trigger] of [['lti_registrations','lti_registration_revision'],['lti_launch_states','lti_launch_state_transition'],
    ['lti_launch_receipts','lti_launch_receipt_immutable'],['lti_registration_operation_audit','lti_registration_audit_immutable'],
    ['lti_provider_identities','lti_provider_identity_revision'],['lti_provider_identity_claims','lti_provider_identity_claim_immutable'],
    ['lti_provider_identity_observations','lti_provider_identity_observation_immutable']]) {
    owner(`ALTER TABLE canvas_connector.${table} DISABLE TRIGGER ${trigger};`);
    try {const denied=await runtime({lti});await assert.rejects(denied.listen(),{message:'connector_oauth_runtime_unavailable'});}
    finally {owner(`ALTER TABLE canvas_connector.${table} ENABLE TRIGGER ${trigger};`);}
  }
  owner('GRANT UPDATE(receipt) ON canvas_connector.lti_launch_receipts TO canvas_oauth_http;');
  try {const denied=await runtime({lti});await assert.rejects(denied.listen(),{message:'connector_oauth_runtime_unavailable'});}
  finally {owner('REVOKE UPDATE(receipt) ON canvas_connector.lti_launch_receipts FROM canvas_oauth_http;');}
  for(const [change,restore] of [
    ['REVOKE EXECUTE ON FUNCTION canvas_connector.confirm_lti_launch(text,text,text) FROM canvas_oauth_http',
      'GRANT EXECUTE ON FUNCTION canvas_connector.confirm_lti_launch(text,text,text) TO canvas_oauth_http'],
    ['GRANT DELETE ON canvas_connector.lti_launch_states TO canvas_oauth_http','REVOKE DELETE ON canvas_connector.lti_launch_states FROM canvas_oauth_http'],
    ['GRANT UPDATE(id) ON canvas_connector.lti_registrations TO canvas_oauth_http','REVOKE UPDATE(id) ON canvas_connector.lti_registrations FROM canvas_oauth_http'],
    ['GRANT CREATE ON SCHEMA canvas_connector TO canvas_oauth_http','REVOKE CREATE ON SCHEMA canvas_connector FROM canvas_oauth_http'],
    ['ALTER ROLE canvas_oauth_http BYPASSRLS','ALTER ROLE canvas_oauth_http NOBYPASSRLS'],
    ['ALTER FUNCTION canvas_connector.guard_lti_launch_state() SECURITY DEFINER','ALTER FUNCTION canvas_connector.guard_lti_launch_state() SECURITY INVOKER'],
  ]) {
    owner(change);
    try {const denied=await runtime({lti});await assert.rejects(denied.listen(),{message:'connector_oauth_runtime_unavailable'});}
    finally {owner(restore);}
  }
  const optedOut=await runtime(),optedOutAddress=await optedOut.listen();
  owner(`CREATE ROLE lti_set_role_mutator;
    GRANT UPDATE(receipt) ON canvas_connector.lti_launch_receipts TO lti_set_role_mutator;
    GRANT lti_set_role_mutator TO canvas_oauth_http WITH INHERIT FALSE;`);
  try {const denied=await runtime({lti});await assert.rejects(denied.listen(),{message:'connector_oauth_runtime_unavailable'});}
  finally {owner('REVOKE lti_set_role_mutator FROM canvas_oauth_http; DROP OWNED BY lti_set_role_mutator; DROP ROLE lti_set_role_mutator;');}
  owner(`CREATE ROLE lti_set_role_owner;
    GRANT CREATE ON SCHEMA canvas_connector TO lti_set_role_owner;
    ALTER FUNCTION canvas_connector.confirm_lti_launch(text,text,text) OWNER TO lti_set_role_owner;
    REVOKE CREATE ON SCHEMA canvas_connector FROM lti_set_role_owner;
    GRANT lti_set_role_owner TO canvas_oauth_http WITH INHERIT FALSE;`);
  try {const denied=await runtime({lti});await assert.rejects(denied.listen(),{message:'connector_oauth_runtime_unavailable'});}
  finally {owner(`REVOKE lti_set_role_owner FROM canvas_oauth_http;
    ALTER FUNCTION canvas_connector.confirm_lti_launch(text,text,text) OWNER TO postgres;
    DROP OWNED BY lti_set_role_owner; DROP ROLE lti_set_role_owner;`);}
  assert.equal((await send(optedOutAddress,{path:'/lti/registrations/'+randomUUID()+'/login?iss=unused&login_hint=opaque',method:'GET'}).response).status,404);
  await optedOut.close();
  configuration.lti=lti;
  const ltiServer=fileCustody?await cliRuntime():await runtime(),ltiAddress=await ltiServer.listen();
  await ltiRuntimeHttpContract({owner,pool,send,server:ltiServer,address:ltiAddress,peer:ltiPeer,org,origin});
  const httpPool = createConnectorPostgresPool(httpDatabase);
  try {
    await assert.rejects(httpPool.query("UPDATE canvas_connector.platforms SET canvas_origin='https://evil.example.test'"));
    await assert.rejects(httpPool.query("UPDATE canvas_connector.platforms SET id='renamed-platform' WHERE id='runtime-platform'"));
    await assert.rejects(httpPool.query('DELETE FROM canvas_connector.platforms'));
    await assert.rejects(httpPool.query('SELECT * FROM canvas_connector.refresh_attempts'));
    await assert.rejects(httpPool.query('DELETE FROM canvas_connector.secrets'));
    await assert.rejects(httpPool.query("UPDATE canvas_connector.secrets SET created_at=clock_timestamp()-interval '1 day'"));
    await assert.rejects(httpPool.query('UPDATE canvas_connector.secrets SET enabled=true'));
    await assert.rejects(httpPool.query('UPDATE canvas_connector.revocation_jobs SET completed_at=clock_timestamp()'));
    await assert.rejects(httpPool.query("UPDATE canvas_connector.authorization_recovery_audit SET actor_id='forged'"));
    assert.equal((await httpPool.query("SELECT has_schema_privilege(current_user,'canvas_connector','CREATE') AS allowed")).rows[0].allowed, false);
  } finally { await httpPool.close(); }
  const server = fileCustody ? await cliRuntime() : await runtime(); const address = await server.listen();
  assert.equal((await send(address,{body:'capabilities=catalog'}).response).status,409);
  const clientPath='/platforms/runtime-platform/oauth/client/';
  const provisionBody=new URLSearchParams({operation_id:randomUUID(),expected_version:'1',client_id:'runtime-client',client_secret:CLIENT}).toString();
  permitted=false;
  assert.equal((await send(address,{path:clientPath+'provision',body:provisionBody}).response).status,403);
  permitted=true;
  const provisioned=await send(address,{path:clientPath+'provision',body:provisionBody}).response;
  assert.equal(provisioned.status,200);const clientReceipt=JSON.parse(provisioned.body).receipt;
  assert.equal(clientReceipt.configVersion,2);reference=clientReceipt.clientSecretRef;
  assert.equal(provisioned.body.includes(CLIENT),false);
  assert.deepEqual(JSON.parse((await send(address,{path:clientPath+'provision',body:provisionBody}).response).body).receipt,clientReceipt);
  const clientReceiptBody=new URLSearchParams({operation_id:clientReceipt.operationId}).toString();
  assert.deepEqual(JSON.parse((await send(address,{path:clientPath+'receipt',body:clientReceiptBody}).response).body).receipt,clientReceipt);
  const currentClient=JSON.parse((await send(address,{path:clientPath+'inspect',body:''}).response).body).client;
  assert.equal(currentClient.clientId,'runtime-client');assert.equal(currentClient.clientSecretRef,reference);
  assert.equal((await send(address,{body:new URLSearchParams({client_id:'substituted-client',client_secret_ref:reference,capabilities:'catalog'}).toString()}).response).status,409);
  console.log('Actual Gateway-authorized restricted-role HTTPS client provisioning/encrypted receipt replay/current configuration and caller substitution rejection passed');
  const recoveryRepository=createPostgresRepository(pool), recoveryHash='d'.repeat(64), recoveryNow=Date.now();
  await recoveryRepository.saveAuthorization({stateHash:recoveryHash,browserBindingHash:'c'.repeat(64),
    organizationId:org,platformId:'runtime-platform',platformConfigVersion:2,canvasOrigin:canvas.origin,
    clientId:'recovery-client',clientSecretRef:reference,capabilities:['catalog'],scopes:['read'],redirectUri:origin+'/oauth/callback',
    createdAt:recoveryNow,expiresAt:recoveryNow+600000});
  await recoveryRepository.markAuthorizationPending(org,'runtime-platform',2,recoveryHash);
  await recoveryRepository.consumeAuthorizationAttempt(recoveryHash,'c'.repeat(64));
  const recoveryPath='/platforms/runtime-platform/oauth/attempts/';
  const inspectionForm=new URLSearchParams({authorization_id:recoveryHash}).toString();
  permitted=false;
  assert.equal((await send(address,{path:recoveryPath+'inspect',body:inspectionForm}).response).status,403);
  permitted=true;
  const inspected=await send(address,{path:recoveryPath+'inspect',body:inspectionForm}).response;
  assert.equal(inspected.status,200);assert.equal(inspected.headers['cache-control'],'no-store');
  const recoverySnapshot=JSON.parse(inspected.body).attempt;assert.equal(recoverySnapshot.phase,'consumed');
  assert.equal(inspected.body.includes(reference),false);assert.equal(inspected.body.includes(CLIENT),false);
  const recoveryOperation='10000000-0000-4000-8000-000000000002';
  const recoveryForm=new URLSearchParams({authorization_id:recoveryHash,operation_id:recoveryOperation,
    expected_revision:String(recoverySnapshot.revision),action:'abandon_unstarted'}).toString();
  const recovered=await send(address,{path:recoveryPath+'recover',body:recoveryForm}).response;
  assert.equal(recovered.status,200);assert.equal(JSON.parse(recovered.body).receipt.actorId,'actor');
  assert.equal(JSON.parse(recovered.body).receipt.phase,'abandoned');
  const replayedRecovery=await send(address,{path:recoveryPath+'recover',body:recoveryForm}).response;
  assert.equal(replayedRecovery.status,200);assert.deepEqual(JSON.parse(replayedRecovery.body),JSON.parse(recovered.body));
  const readReceipt=await send(address,{path:recoveryPath+'receipt',body:new URLSearchParams({authorization_id:recoveryHash,operation_id:recoveryOperation}).toString()}).response;
  assert.equal(readReceipt.status,200);assert.deepEqual(JSON.parse(readReceipt.body),JSON.parse(recovered.body));
  assert.equal((await pool.query('SELECT actor_id FROM canvas_connector.authorization_recovery_audit WHERE organization_id=$1 AND operation_id=$2',[org,recoveryOperation])).rows[0].actor_id,'actor');
  console.log('Actual public Gateway session/permission to production HTTPS listener/limited HTTP role recovery, immutable actor audit and receipt replay contracts passed');
  const started = await send(address, { body:'capabilities=catalog' }).response;
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
  if (fileCustody) await server.waitUntilDraining();
  else await setImmediate();
  assert.equal(closed, false);
  release(); await stopping;
  if (fileCustody) console.log('Actual standalone CLI loaded private configuration and drained SIGTERM through disconnected-client OAuth publication');
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
  const connectionPath='/platforms/runtime-platform/connection/';
  const snapshot=JSON.parse((await send(secondAddress,{path:connectionPath+'inspect',body:''}).response).body);
  assert.equal(snapshot.connection.status,'connected');
  const disconnectBody=new URLSearchParams({connection_id:snapshot.connection.connectionId,
    expected_revision:String(snapshot.connection.revision),operation_id:randomUUID()}).toString();
  permitted=false;
  assert.equal((await send(secondAddress,{path:connectionPath+'disconnect',body:disconnectBody}).response).status,403);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM canvas_connector.connections WHERE organization_id=$1',[org])).rows[0].count,1);
  permitted=true;
  const disconnected=await send(secondAddress,{path:connectionPath+'disconnect',body:disconnectBody}).response;
  assert.equal(disconnected.status,200);
  const disconnectReceipt=JSON.parse(disconnected.body).receipt;
  assert.equal(disconnectReceipt.actorId,'actor');assert.equal(disconnectReceipt.status,'disconnected');
  assert.deepEqual(JSON.parse((await send(secondAddress,{path:connectionPath+'disconnect',body:disconnectBody}).response).body).receipt,disconnectReceipt);
  const receiptBody=new URLSearchParams({operation_id:disconnectReceipt.operationId}).toString();
  assert.deepEqual(JSON.parse((await send(secondAddress,{path:connectionPath+'receipt',body:receiptBody}).response).body).receipt,disconnectReceipt);
  const afterDisconnect=JSON.parse((await send(secondAddress,{path:connectionPath+'inspect',body:''}).response).body);
  assert.equal(afterDisconnect.connection,null);assert.equal(afterDisconnect.pendingRevocation,true);
  for(const secret of [CLIENT,ACCESS,REFRESH,reference,connection.access_token_ref,connection.refresh_token_ref])
    assert.equal(disconnected.body.includes(secret),false);
  assert.equal(await vault.get(org,connection.access_token_ref,{...scope,purpose:'oauth_access_token'}),ACCESS);
  console.log('Actual Gateway session/permission -> HTTPS restricted HTTP role connection inspect/disconnect/immutable receipt replay and deferred token cleanup passed');
  const platformPath='/platforms/managed-platform/configuration/';
  const createPlatformBody=new URLSearchParams({operation_id:randomUUID(),canvas_origin:canvas.origin}).toString();
  permitted=false;
  assert.equal((await send(secondAddress,{path:platformPath+'create',body:createPlatformBody}).response).status,403);
  permitted=true;
  const createdPlatform=await send(secondAddress,{path:platformPath+'create',body:createPlatformBody}).response;
  assert.equal(createdPlatform.status,200);const platformReceipt=JSON.parse(createdPlatform.body).receipt;
  assert.equal(platformReceipt.enabled,false);assert.equal(platformReceipt.configVersion,1);assert.equal(platformReceipt.actorId,'actor');
  assert.deepEqual(JSON.parse((await send(secondAddress,{path:platformPath+'create',body:createPlatformBody}).response).body).receipt,platformReceipt);
  const enableBody=new URLSearchParams({operation_id:randomUUID(),expected_version:'1',enabled:'true',archived:'false'}).toString();
  const enabledPlatform=await send(secondAddress,{path:platformPath+'change',body:enableBody}).response;
  assert.equal(enabledPlatform.status,200);assert.equal(JSON.parse(enabledPlatform.body).receipt.configVersion,2);
  const staleBody=new URLSearchParams({operation_id:randomUUID(),expected_version:'1',enabled:'false',archived:'false'}).toString();
  assert.equal((await send(secondAddress,{path:platformPath+'change',body:staleBody}).response).status,409);
  const managed=JSON.parse((await send(secondAddress,{path:platformPath+'inspect',body:''}).response).body).platform;
  assert.equal(managed.platformId,'managed-platform');assert.equal(managed.enabled,true);
  const catalog=JSON.parse((await send(secondAddress,{path:'/platforms/catalog',body:''}).response).body);
  assert.ok(catalog.platforms.some(row=>row.platformId==='managed-platform'));
  const platformReceiptBody=new URLSearchParams({operation_id:platformReceipt.operationId}).toString();
  assert.deepEqual(JSON.parse((await send(secondAddress,{path:platformPath+'receipt',body:platformReceiptBody}).response).body).receipt,platformReceipt);
  console.log('Actual Gateway-authorized restricted-role HTTPS platform create/enable/catalog/inspect/CAS/immutable receipt replay passed');
  const captureLimitedPool=createConnectorPostgresPool(httpDatabase);
  try { await captureRouteHttpContract({send,address:secondAddress,organizationId:org,canvasOrigin:canvas.origin,pool,
    limitedPool:captureLimitedPool,gateway,owner,bindings,setBindingAllowed:value=>{bindingAllowed=value;}}); }
  finally {await captureLimitedPool.close();}
  await ltiServiceHttpContract(configuration,{pool,owner});

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
  await pool.close(); await canvas.close(); await gateway.close(); await ltiPeer.close();
}
