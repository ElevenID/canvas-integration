// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
import { connect } from 'node:tls';
import { setImmediate } from 'node:timers/promises';
import { createConnectorHttpsService } from '../src/connector-https-service.mjs';
import { createGatewayAdminAuthenticator } from '../src/gateway-admin-auth.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const origin = 'https://localhost';
const state = Buffer.alloc(32, 8).toString('base64url');
const form = 'client_id=client&client_secret_ref=opaque-client-secret&capabilities=catalog';
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const ltiRegistration='10000000-0000-4000-8000-000000000002';
const ltiLogin=`/lti/registrations/${ltiRegistration}/login?iss=https%3A%2F%2Fcanvas.instructure.com&login_hint=opaque`;
const ltiPlan={registrationId:ltiRegistration,launchId:'synthetic-launch',state,browserProof:Buffer.alloc(32,9).toString('base64url'),
  canvasOrigin:'https://college.instructure.com',storageOrigin:'https://sso.canvaslms.com',
  authorizationUrl:'https://sso.canvaslms.com/api/lti/authorize_redirect'};
const ltiMethods=begin=>({begin,browserContext:async()=>({}),stage:async()=>({}),confirm:async()=>({}),active:async()=>({})});
async function fixture(t, overrides = {}) {
  const peer = await httpsFixture();
  const starts = [], callbacks = [];
  peer.setHandler((req, res) => {
    if (req.url === '/v1/auth/me') return json(res, { authenticated: true, user: {
      user_id: 'actor', organization_id: '750e8400-e29b-41d4-a716-446655440001' } });
    if (req.url.endsWith('/members/me/permissions')) return json(res, { permissions: ['integration-connector:edit'] });
    res.writeHead(404); res.end();
  });
  const configuration = {
    publicOrigin: origin, completionUrl: origin + '/complete', tls: { key: peer.key, cert: peer.ca }, port: 0,
    rateLimiter: { consume: async () => true },
    authenticateAndAuthorize: createGatewayAdminAuthenticator({ gatewayOrigin: peer.origin, adminOrigin: origin,
      sessionCookieName: 'session', ca: peer.ca }),
    lifecycle: {
      async start(input) {
        starts.push(input);
        return { authorizationUrl: `https://canvas.example.test/login/oauth2/auth?state=${state}&redirect_uri=${encodeURIComponent(origin + '/oauth/callback')}`,
          redirectUri: origin + '/oauth/callback' };
      },
      async callback(input) { callbacks.push(input); return { location: origin + '/complete?outcome=connected' }; },
    }, ...overrides,
  };
  const service = createConnectorHttpsService(configuration);
  const address = await service.listen();
  t.after(async () => { await service.close(); await peer.close(); });
  function begin({ path = '/platforms/platform/oauth/start', method = 'POST', body,
    headers = {}, ca = peer.ca } = {}) {
    let req;
    const response = new Promise((resolve, reject) => {
      req = request({ hostname: 'localhost', servername: 'localhost', family: 4, port: address.port, method, path, ca, agent: false,
        headers: { Host: 'localhost', Origin: origin, Cookie: 'session=abcdefghijklmnop',
          'Content-Type': 'application/x-www-form-urlencoded', ...headers } }, res => {
        let body = '';
        res.setEncoding('utf8'); res.on('data', chunk => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        res.on('error', reject);
      });
      req.on('error', reject); req.end(body ?? (method === 'POST' ? form : undefined));
    });
    return { request: req, response };
  }
  const send = async options => begin(options).response;
  return { service, send, begin, starts, callbacks, peer, address, configuration };
}

test('operator shell is static, same-origin and cannot disclose authenticated state or execute query input',async t=>{
  const f=await fixture(t);
  for(const [path,type] of [['/admin','text/html'],['/admin/app.js','text/javascript'],['/admin/styles.css','text/css'],['/complete','text/html']]) {
    const result=await f.send({path,method:'GET',headers:{Cookie:'',Origin:'https://other.example'}});
    assert.equal(result.status,200);assert.ok(result.headers['content-type'].startsWith(type));
    assert.equal(result.headers['cache-control'],'no-store');assert.equal(result.headers['x-frame-options'],'DENY');
    assert.equal(result.headers['cross-origin-resource-policy'],'same-origin');
    assert.match(result.headers['content-security-policy'],/connect-src 'self'/);
    assert.equal(result.headers['content-security-policy'].includes('unsafe-inline'),false);
    assert.equal(result.headers['set-cookie'],undefined);
    if(path==='/admin') {assert.match(result.body,/<fieldset id="workspace" disabled>/);assert.match(result.body,/method="post" action="\/admin"/);}
    assert.equal((await f.send({path,method:'POST'})).status,405);
  }
  for(const path of ['/admin?platform=other','/admin/app.js?x=1','/admin/../admin','/complete?token=private']) assert.equal((await f.send({path,method:'GET'})).status,404);
  for(const query of ['outcome=connected&platform_id=platform','outcome=error&error_code=oauth_denied']) {
    const complete=await f.send({path:'/complete?'+query,method:'GET'});assert.equal(complete.status,200);
    assert.equal(complete.body,(await f.send({path:'/complete',method:'GET'})).body);
  }
  for(const query of ['outcome=connected&outcome=error','outcome=other','outcome=connected&platform_id=%FF','outcome=connected&token=secret']) assert.equal((await f.send({path:'/complete?'+query,method:'GET'})).status,404);
  assert.equal(f.peer.seen.length,0);assert.equal(f.starts.length,0);assert.equal(f.callbacks.length,0);
});

test('LTI routes are opt-in and share the bounded HTTPS dispatcher without Gateway privilege impersonation',async t=>{
  const absent=await fixture(t);
  assert.equal((await absent.send({path:ltiLogin,method:'GET'})).status,404);
  let calls=0;const enabled=await fixture(t,{ltiLifecycle:ltiMethods(async()=>{calls++;return ltiPlan;})});
  const result=await enabled.send({path:ltiLogin,method:'GET'});
  assert.equal(result.status,200);assert.match(result.headers['set-cookie'][0],/^__Host-canvas_lti_/);
  assert.equal(calls,1);assert.equal(enabled.starts.length,0);assert.equal(enabled.peer.seen.length,0);
});

test('LTI work keeps its concurrency reservation and shutdown waits after peer disconnect',async t=>{
  const entered=deferred(),release=deferred();
  const f=await fixture(t,{maxConcurrentRequests:1,ltiLifecycle:ltiMethods(async()=>{entered.resolve();await release.promise;return ltiPlan;})});
  const pending=f.begin({path:ltiLogin,method:'GET'});void pending.response.catch(()=>{});
  await entered.promise;pending.request.destroy();
  assert.equal((await f.send({path:ltiLogin,method:'GET'})).status,503);
  let closed=false;const closing=f.service.close().then(()=>{closed=true;});
  await setImmediate();assert.equal(closed,false);
  release.resolve();await closing;assert.equal(closed,true);
});

test('real HTTPS service composes Gateway-only admin authentication and browser-bound callback', async t => {
  const f = await fixture(t);
  const start = await f.send({ headers: { 'X-Organization-ID': 'spoofed' } });
  assert.equal(start.status, 200);
  assert.equal(f.starts[0].organizationId, '750e8400-e29b-41d4-a716-446655440001');
  const cookie = start.headers['set-cookie'][0].split(';')[0];
  const callback = await f.send({ path: `/oauth/callback?state=${state}&code=synthetic-code`, method: 'GET',
    body: undefined, headers: { Cookie: cookie } });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.location, origin + '/complete?outcome=connected');
  assert.equal(f.callbacks[0].browserBinding, f.starts[0].browserBinding);
  assert.equal(callback.headers['cache-control'], 'no-store');
  assert.deepEqual(f.peer.seen.map(r => r.url), ['/v1/auth/me',
    '/v1/organizations/750e8400-e29b-41d4-a716-446655440001/members/me/permissions']);
  assert.ok(f.peer.seen.every(r => r.headers.cookie === 'session=abcdefghijklmnop'));
  assert.ok(f.peer.seen.every(r => !r.headers['x-api-key'] && !r.headers['x-organization-id']));
});

test('service denies alternate hosts, malformed routes, cross-origin start and missing callback proof', async t => {
  const f = await fixture(t);
  assert.equal((await f.send({ headers: { Host: 'evil.example.test' } })).status, 421);
  assert.equal((await f.send({ path: 'https://localhost/platforms/platform/oauth/start' })).status, 404);
  assert.equal((await f.send({ path: '/platforms/%70latform/oauth/start' })).status, 404);
  assert.equal((await f.send({ headers: { Origin: 'https://evil.example.test' } })).status, 403);
  assert.equal((await f.send({ path: `/oauth/callback?state=${state}&code=synthetic-code`, method: 'GET', body: undefined })).status, 400);
  assert.equal(f.starts.length + f.callbacks.length, 0);
});

test('TLS trust is mandatory and unauthenticated sessions never reach lifecycle', async t => {
  const f = await fixture(t);
  // Explicitly omit the synthetic CA from the client's trusted certificates.
  await assert.rejects(f.send({ ca: [] }));
  assert.equal((await f.send({ headers: { Cookie: '' } })).status, 401);
  assert.equal(f.starts.length, 0);
});

test('oversized and duplicate raw headers cannot hide security headers', async t => {
  const f = await fixture(t);
  const headers = Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['X-Filler-' + i, 'x']));
  assert.equal((await f.send({ headers })).status, 431);
  const response = await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: f.address.port, servername: 'localhost', ca: f.peer.ca }, () => {
      socket.write('POST /platforms/platform/oauth/start HTTP/1.1\r\nHost: localhost\r\nHost: evil.example.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    });
    let output = ''; socket.setEncoding('utf8'); socket.on('data', chunk => { output += chunk; });
    socket.on('end', () => resolve(output)); socket.on('error', reject);
  });
  assert.ok(response === '' || !/^HTTP\/1\.1 2/.test(response));
  assert.equal(f.starts.length, 0);
});

test('peer disconnect keeps its capacity reserved and shutdown waits for actual handler completion', async t => {
  const entered = deferred(), release = deferred();
  const f = await fixture(t, { maxConcurrentRequests: 1,
    rateLimiter: { async consume() { entered.resolve(); await release.promise; return false; } } });
  const first = f.begin();
  const aborted = assert.rejects(first.response);
  try {
    await entered.promise;
    first.request.destroy(); await aborted;
    assert.equal((await f.send()).status, 503);
    let stopped = false;
    const close = f.service.close().then(() => { stopped = true; });
    await setImmediate();
    assert.equal(stopped, false);
    release.resolve(); await close;
    await f.service.close();
    await assert.rejects(f.service.listen(), { message: 'connector_service_unavailable' });
    assert.equal(f.starts.length, 0);
  } finally { release.resolve(); }
});

test('configuration rejects plaintext, noncanonical origin and TLS overrides', async t => {
  const f = await fixture(t);
  for (const change of [{ publicOrigin: 'http://localhost' }, { publicOrigin: origin + '/' },
    { host: 'database.internal' }, { port: -1 }, { maxConcurrentRequests: 0 },
    { tls: { ...f.configuration.tls, rejectUnauthorized: false } }, { gatewayDatabaseUrl: 'forbidden' }]) {
    assert.throws(() => createConnectorHttpsService({ ...f.configuration, ...change }),
      { message: 'invalid_connector_service_configuration' });
  }
});
