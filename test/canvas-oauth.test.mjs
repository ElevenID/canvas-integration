// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createCanvasOAuthLifecycle } from '../src/canvas-oauth.mjs';
import { createServer, request } from 'node:http';
import { createOAuthCallbackHandler } from '../src/oauth-callback-http.mjs';
import { createOAuthAdminHandler } from '../src/oauth-admin-http.mjs';
import { oauthBrowserBindingCookieName } from '../src/oauth-browser-binding.mjs';
const BROWSER_BINDING=Buffer.alloc(32,9).toString('base64url');

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
  const attempts = new Map();
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
    async consumeAuthorizationAttempt(hash, browserBindingHash) {
      const value = authorizations.get(hash);
      if (!value || value.browserBindingHash!==browserBindingHash || value.expiresAt <= now) return null;
      authorizations.delete(hash);
      attempts.set(hash,{...value,phase:'consumed'});
      return value;
    },
    async beginAuthorizationExchange(hash,org,id) {
      calls.push(['begin',hash,org,id]);
      if(overrides.begin) return overrides.begin();
      const a=attempts.get(hash);
      if(!a || a.phase!=='consumed' || a.organizationId!==org || a.platformId!==id
          || a.platformConfigVersion!==platform.configVersion || !platform.enabled || platform.archived
          || a.expiresAt<=now || connections.size || [...attempts.values()].some(v=>['exchanging','staged','reconciliation_required'].includes(v.phase))) return false;
      a.phase='exchanging';return true;
    },
    async requireAuthorizationReconciliation(hash) {
      calls.push(['reconcile',hash]);const a=attempts.get(hash);
      if(a && ['exchanging','staged','reconciliation_required'].includes(a.phase)) a.phase='reconciliation_required';
    },
    async publishAuthorizationConnection(hash,org,id) {
      const a=attempts.get(hash);const value={...a,status:'connected'};
      calls.push(['publish',value,a?.platformConfigVersion]);
      if (overrides.publish) return overrides.publish(value,a?.platformConfigVersion);
      if (a?.phase!=='staged' || org!==ORG || id!==PLATFORM || a.platformConfigVersion!==platform.configVersion || connections.has(ORG + ':' + PLATFORM)) return false;
      connections.set(ORG + ':' + PLATFORM,value);a.phase='published';return true;
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
      return { organizationId: ORG, platformId: PLATFORM, enabled: true, provider: 'canvas', purpose: 'oauth_client_secret' };
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
    async stageAuthorizationResult(a,bundle,expiresAt) {
      if(overrides.stage) return overrides.stage(a,bundle,expiresAt);
      const accessTokenRef='secret-token-'+(++sequence);
      const refreshTokenRef=bundle.refreshToken?'secret-token-'+(++sequence):null;
      secrets.set(accessTokenRef,bundle.accessToken);
      saved.push({secretRef:accessTokenRef,purpose:'oauth_access_token',value:bundle.accessToken});
      if(refreshTokenRef) {secrets.set(refreshTokenRef,bundle.refreshToken);saved.push({secretRef:refreshTokenRef,purpose:'oauth_refresh_token',value:bundle.refreshToken});}
      Object.assign(attempts.get(a.authorizationId),{accessTokenRef,refreshTokenRef,tokenExpiresAt:expiresAt,phase:'staged'});
      return {accessTokenRef,refreshTokenRef};
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
    lifecycle, repository, vault, provider, authorizations, connections, attempts,
    saved, deleted, revoked, calls, platform, secrets,
    setNow(value) { now = value; },
  };
}
async function started(value, capabilities = ['catalog', 'native_activity_scores']) {
  const result = await value.lifecycle.start({
    browserBinding:BROWSER_BINDING, organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities,
  });
  const url = new URL(result.authorizationUrl);
  return { result, url, state: url.searchParams.get('state'), stored: [...value.authorizations.values()][0] };
}

async function callbackHttp(t, lifecycle) {
  const server = createServer(createOAuthCallbackHandler({ lifecycle,
    completionUrl: 'https://console.example.test/integrations/canvas',
    rateLimiter: { consume: async () => true },
  }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return (parameters,browserBinding=BROWSER_BINDING) => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.address().port,
      headers:browserBinding?{Cookie:`${oauthBrowserBindingCookieName(parameters.state)}=${browserBinding}`}:{ },
      path: '/oauth/callback?' + new URLSearchParams(parameters) }, res => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location ? new URL(res.headers.location) : undefined }));
    });
    req.on('error', reject); req.end();
  });
}

test('HTTP adapter composes with OAuth lifecycle and rejects state replay', async t => {
  const f = fixture();
  const authorization = await started(f);
  const send = await callbackHttp(t, f.lifecycle);
  const connected = await send({ state: authorization.state, code: 'synthetic-code' });
  assert.equal(connected.status, 303);
  assert.equal(connected.location.searchParams.get('outcome'), 'connected');
  assert.equal(f.connections.size, 1);
  const repeated = await send({ state: authorization.state, code: 'synthetic-code' });
  assert.equal(repeated.location.searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.filter(call => call[0] === 'exchange').length, 1);
  assert.equal(f.connections.size, 1);
});

test('HTTP provider denial consumes state without exchanging or reflecting provider error', async t => {
  const f = fixture();
  const authorization = await started(f);
  const send = await callbackHttp(t, f.lifecycle);
  const denied = await send({ state: authorization.state, error: 'sensitive-provider-text' });
  assert.equal(denied.status, 303);
  assert.equal(denied.location.searchParams.get('error_code'), 'oauth_authorization_denied');
  assert.doesNotMatch(denied.location.href, /sensitive-provider-text/);
  const replay = await send({ state: authorization.state, code: 'synthetic-code' });
  assert.equal(replay.location.searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.filter(call => call[0] === 'exchange').length, 0);
  assert.equal(f.connections.size, 0);
});

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
  const result = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, code: 'synthetic-auth-code' });
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
  const replay = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, code: 'synthetic-auth-code' });
  assert.equal(new URL(replay.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.filter(item => item[0] === 'exchange').length, 1);
});

test('state is bound to tenant, platform configuration and the fixed callback URI', async () => {
  const f = fixture();
  const { state } = await started(f);
  f.platform.configVersion += 1;
  const result = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_configuration_changed');
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('Canvas authorization denial consumes state and does not exchange a token', async () => {
  const f = fixture();
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, error: 'access_denied' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_authorization_denied');
  assert.equal(f.authorizations.size, 0);
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('expired, malformed and unknown states never reach the provider', async () => {
  const f = fixture();
  const { state, stored } = await started(f);
  f.setNow(stored.expiresAt);
  const expired = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, code: 'synthetic-code' });
  assert.equal(new URL(expired.location).searchParams.get('error_code'), 'oauth_state_invalid');
  const malformed = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state: 'not-a-state', code: 'synthetic-code' });
  assert.equal(new URL(malformed.location).searchParams.get('error_code'), 'oauth_state_invalid');
  assert.equal(f.calls.some(item => item[0] === 'exchange'), false);
});

test('unsupported capabilities, missing client secret and existing connection fail before state creation', async () => {
  const f = fixture();
  await assert.rejects(f.lifecycle.start({
    browserBinding:BROWSER_BINDING, organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities: ['admin:full'],
  }), { code: 'unsupported_capability' });
  await assert.rejects(f.lifecycle.start({
    browserBinding:BROWSER_BINDING, organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: 'wrong-secret', capabilities: ['catalog'],
  }), { code: 'client_secret_unavailable' });
  f.connections.set(ORG + ':' + PLATFORM, { status: 'connected' });
  await assert.rejects(f.lifecycle.start({
    browserBinding:BROWSER_BINDING, organizationId: ORG, platformId: PLATFORM, clientId: 'canvas-client',
    clientSecretRef: CLIENT_SECRET_REF, capabilities: ['catalog'],
  }), { code: 'connection_exists' });
  assert.equal(f.authorizations.size, 0);
});

test('configuration race cancels the pending state', async () => {
  const f = fixture({ markPending: () => false });
  await assert.rejects(started(f), { code: 'platform_configuration_changed' });
  assert.equal(f.authorizations.size, 0);
});

test('atomic token staging failure retains the attempt without inline deletion or revocation', async () => {
  const f = fixture({stage:async()=>{throw Error('synthetic unknown staging outcome');}});
  const {state}=await started(f);
  const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
  assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_connection_reconciliation_required');
  assert.deepEqual(f.deleted,[]);assert.deepEqual(f.revoked,[]);
  assert.equal([...f.attempts.values()][0].phase,'reconciliation_required');
  assert.equal(f.secrets.size,1);
});

test('rejected and uncertain publication retain staged tokens for explicit reconciliation', async () => {
  for(const publish of [async()=>false,async()=>{throw Error('synthetic lost reply');}]) {
    const f=fixture({publish});const {state}=await started(f);
    const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.match(new URL(result.location).searchParams.get('error_code'),/^oauth_(authorization_conflict|connection_reconciliation_required)$/);
    assert.deepEqual(f.deleted,[]);assert.deepEqual(f.revoked,[]);assert.equal(f.secrets.size,3);
    assert.equal([...f.attempts.values()][0].phase,'reconciliation_required');
  }
});

test('post-publication platform race preserves durable tokens and marks reauthorization', async () => {
  const f = fixture({ markConnected: () => false });
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING, state, code: 'synthetic-code' });
  assert.equal(new URL(result.location).searchParams.get('error_code'), 'oauth_configuration_changed');
  assert.equal(f.connections.size, 1);
  assert.deepEqual(f.deleted, []);
  assert.equal(f.calls.some(item => item[0] === 'reauthorization'), true);
});

test('lost consumption or begin reply never sends the authorization code to Canvas', async () => {
  for(const method of ['consumeAuthorizationAttempt','beginAuthorizationExchange']) {
    const f=fixture();const {state}=await started(f);
    const original=f.repository[method];
    f.repository[method]=async(...args)=>{await original(...args);throw Error('synthetic lost acknowledgment');};
    const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_connection_reconciliation_required');
    assert.equal(f.calls.some(v=>v[0]==='exchange'),false);
    assert.equal(f.connections.size,0);assert.equal(f.secrets.size,1);
    assert.equal([...f.attempts.values()][0].phase,method==='consumeAuthorizationAttempt'?'consumed':'reconciliation_required');
    f.repository[method]=original;
    const replay=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(replay.location).searchParams.get('error_code'),'oauth_state_invalid');
  }
});

test('lost staging or publication reply preserves committed refs and never repeats exchange', async () => {
  for(const method of ['stageAuthorizationResult','publishAuthorizationConnection']) {
    const f=fixture();const {state}=await started(f);
    const owner=method==='stageAuthorizationResult'?f.vault:f.repository;
    const original=owner[method];
    owner[method]=async(...args)=>{await original(...args);throw Error('synthetic lost acknowledgment');};
    const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_connection_reconciliation_required');
    const attempt=[...f.attempts.values()][0];
    assert.equal(attempt.phase,method==='stageAuthorizationResult'?'reconciliation_required':'published');
    assert.equal(f.secrets.get(attempt.accessTokenRef),ACCESS_TOKEN);
    assert.equal(f.secrets.get(attempt.refreshTokenRef),REFRESH_TOKEN);
    assert.deepEqual(f.deleted,[]);assert.deepEqual(f.revoked,[]);
    const replay=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(replay.location).searchParams.get('error_code'),'oauth_state_invalid');
    assert.equal(f.calls.filter(v=>v[0]==='exchange').length,1);
  }
});

test('exchange failure parks uncertainty without cleanup even when reconciliation is unavailable', async () => {
  for(const unavailable of [false,true]) {
    const f=fixture({exchange:async()=>{throw Error('sensitive provider body');}});
    if(unavailable) f.repository.requireAuthorizationReconciliation=async()=>{throw Error('sensitive database body');};
    const {state}=await started(f);
    const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_token_exchange_failed');
    assert.doesNotMatch(result.location,/sensitive/);
    assert.equal([...f.attempts.values()][0].phase,unavailable?'exchanging':'reconciliation_required');
    assert.deepEqual(f.deleted,[]);assert.deepEqual(f.revoked,[]);
    const replay=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(replay.location).searchParams.get('error_code'),'oauth_state_invalid');
    assert.equal(f.calls.filter(v=>v[0]==='exchange').length,1);
  }
});

test('false exchange admission and malformed staging refs never publish or clean custody', async () => {
  const denied=fixture({begin:async()=>false});const first=await started(denied);
  const response=await denied.lifecycle.callback({browserBinding:BROWSER_BINDING,state:first.state,code:'synthetic-code'});
  assert.equal(new URL(response.location).searchParams.get('error_code'),'oauth_authorization_conflict');
  assert.equal(denied.calls.some(v=>v[0]==='exchange'),false);
  for(const refs of [{accessTokenRef:CLIENT_SECRET_REF,refreshTokenRef:null},{accessTokenRef:'a',refreshTokenRef:'a'},{accessTokenRef:'a'}]) {
    const f=fixture({stage:async()=>refs});const {state}=await started(f);
    const result=await f.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
    assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_connection_reconciliation_required');
    assert.equal(f.calls.some(v=>v[0]==='publish'),false);assert.deepEqual(f.deleted,[]);assert.deepEqual(f.revoked,[]);
  }
});

test('callback response never reflects caller-controlled redirect or error text', async () => {
  const f = fixture();
  const { state } = await started(f);
  const result = await f.lifecycle.callback({ browserBinding:BROWSER_BINDING,
    state, code: '', error: 'https://attacker.example/?token=secret',
  });
  const location = new URL(result.location);
  assert.equal(location.origin, 'https://console.example.test');
  assert.equal(location.searchParams.get('error_code'), 'oauth_authorization_denied');
  assert.equal(location.searchParams.has('token'), false);
});

test('Canvas OAuth modules fail closed under browser export conditions', async () => {
  const run = promisify(execFile);
  for (const name of ['canvas-oauth', 'canvas-oauth-provider','oauth-browser-binding']) {
    await assert.rejects(run(process.execPath, [
      '--conditions=browser', '--input-type=module', '-e',
      `await import('@elevenid/canvas-integration/${name}')`,
    ]), error => {
      assert.match(error.stderr, /server-only/);
      return true;
    });
  }
});

test('different or missing initiating browser proof never consumes state or exchanges code', async t => {
  const f=fixture();const {state,stored}=await started(f);
  assert.equal(stored.browserBindingHash,createHash('sha256').update(BROWSER_BINDING).digest('hex'));
  assert.equal(JSON.stringify(stored).includes(BROWSER_BINDING),false);
  const send=await callbackHttp(t,f.lifecycle);
  const missing=await send({state,code:'synthetic-victim-code'},null);
  assert.equal(missing.status,400);
  const wrong=await send({state,code:'synthetic-victim-code'},Buffer.alloc(32,11).toString('base64url'));
  assert.equal(wrong.location.searchParams.get('error_code'),'oauth_state_invalid');
  assert.equal(f.authorizations.size,1);
  assert.equal(f.calls.filter(c=>c[0]==='exchange').length,0);
  assert.equal(f.connections.size,0);
  const legitimate=await send({state,code:'synthetic-legitimate-code'});
  assert.equal(legitimate.location.searchParams.get('outcome'),'connected');
  assert.equal(f.authorizations.size,0);
  assert.equal(f.calls.filter(c=>c[0]==='exchange').length,1);
});
test('service lifecycle denies missing browser binding before storing or consuming state',async()=>{
  const f=fixture();
  await assert.rejects(f.lifecycle.start({organizationId:ORG,platformId:PLATFORM,clientId:'canvas-client',clientSecretRef:CLIENT_SECRET_REF,capabilities:['catalog']}),/invalid_oauth_browser_binding/);
  const {state}=await started(f);
  const result=await f.lifecycle.callback({state,code:'synthetic-victim-code'});
  assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_state_invalid');
  assert.equal(f.authorizations.size,1);
  assert.equal(f.calls.filter(c=>c[0]==='exchange').length,0);
});
test('client secret platform metadata is enforced at start and callback',async()=>{
  const f=fixture();
  f.vault.metadata=async()=>({organizationId:ORG,platformId:'other-platform',enabled:true,provider:'canvas',purpose:'oauth_client_secret'});
  await assert.rejects(started(f),{code:'client_secret_unavailable'});
  assert.equal(f.authorizations.size,0);
  const other=fixture();const {state}=await started(other);
  other.vault.metadata=f.vault.metadata;
  const result=await other.lifecycle.callback({browserBinding:BROWSER_BINDING,state,code:'synthetic-code'});
  assert.equal(new URL(result.location).searchParams.get('error_code'),'oauth_configuration_changed');
  assert.equal(other.calls.filter(c=>c[0]==='exchange').length,0);
});

test('authenticated start HTTP sets browser proof that completes its callback',async t=>{
  const f=fixture();const server=createServer(createOAuthAdminHandler({
    lifecycle:f.lifecycle,adminOrigin:'https://connector.example.test',rateLimiter:{consume:async()=>true},
    authenticateAndAuthorize:async()=>({organizationId:ORG,authorized:true}),
  }));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const started=await new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,method:'POST',path:`/platforms/${PLATFORM}/oauth/start`,
      headers:{Origin:'https://connector.example.test','Content-Type':'application/x-www-form-urlencoded'}},res=>{
        let body='';res.on('data',chunk=>{body+=chunk;});res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));
      });
    req.on('error',reject);req.end(new URLSearchParams({client_id:'canvas-client',client_secret_ref:CLIENT_SECRET_REF,capabilities:'catalog'}).toString());
  });
  assert.equal(started.status,200);
  const state=new URL(JSON.parse(started.body).authorizationUrl).searchParams.get('state');
  const cookie=started.headers['set-cookie'][0].split(';')[0];
  assert.equal(cookie.split('=')[0],oauthBrowserBindingCookieName(state));
  const proof=cookie.split('=')[1];
  assert.equal([...f.authorizations.values()][0].browserBindingHash,createHash('sha256').update(proof).digest('hex'));
  assert.equal(started.body.includes(proof),false);
  const callback=await callbackHttp(t,f.lifecycle);
  assert.equal((await callback({state,code:'synthetic-victim-code'},null)).status,400);
  assert.equal(f.authorizations.size,1);
  const completed=await callback({state,code:'synthetic-real-code'},proof);
  assert.equal(completed.location.searchParams.get('outcome'),'connected');
  assert.equal(f.connections.size,1);
});
test('production configured-client mode requires current metadata and rejects caller substitution',async()=>{
  const f=fixture();let configured=true;
  f.repository.configuredClient=async(org,platform,version)=>{
    assert.equal(org,ORG);assert.equal(platform,PLATFORM);assert.equal(version,7);
    return configured?{clientId:'configured-client',clientSecretRef:CLIENT_SECRET_REF}:null;
  };
  const strict=createCanvasOAuthLifecycle({publicOrigin:'https://connector.example.test',completionUrl:'https://console.example.test/complete',
    repository:f.repository,secretVault:f.vault,provider:f.provider,requireConfiguredClient:true});
  const input={organizationId:ORG,platformId:PLATFORM,browserBinding:BROWSER_BINDING,capabilities:['catalog']};
  await strict.start(input);
  const saved=[...f.authorizations.values()][0];assert.equal(saved.clientId,'configured-client');assert.equal(saved.clientSecretRef,CLIENT_SECRET_REF);
  await assert.rejects(strict.start({...input,clientId:'substituted',clientSecretRef:CLIENT_SECRET_REF}),error=>error.code==='client_configuration_changed');
  configured=false;
  await assert.rejects(strict.start(input),error=>error.code==='client_configuration_required');
  assert.equal(f.authorizations.size,1);assert.equal(f.calls.some(call=>call[0]==='exchange'),false);
});
