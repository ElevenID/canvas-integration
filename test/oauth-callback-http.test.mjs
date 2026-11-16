// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createOAuthCallbackHandler } from '../src/oauth-callback-http.mjs';
import { oauthBrowserBindingCookieName } from '../src/oauth-browser-binding.mjs';
const browserBinding=Buffer.alloc(32,9).toString('base64url');

const state = 'a'.repeat(43);
async function fixture(t, options = {}) {
  const inputs = [];
  const handler = createOAuthCallbackHandler({
    completionUrl: 'https://connector.example/complete',
    rateLimiter: { consume: async () => true },
    lifecycle: { callback: async input => {
      inputs.push(input);
      return { location: 'https://connector.example/complete?outcome=connected&platform_id=platform-one' };
    } }, ...options,
  });
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const send = (path, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.address().port, path, method, headers: {Cookie:`${oauthBrowserBindingCookieName(state)}=${browserBinding}`,...headers} }, res => {
      let body = ''; res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject); req.end();
  });
  return { inputs, send };
}
test('real HTTP callback forwards only validated parameters and redirects without secrets', async t => {
  const f = await fixture(t);
  const result = await f.send(`/oauth/callback?state=${state}&code=secret-code`);
  assert.equal(result.status, 303);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.headers['referrer-policy'], 'no-referrer');
  assert.match(result.headers['set-cookie'][0],/; Secure; HttpOnly; SameSite=Lax; Max-Age=0$/);
  assert.equal(result.body, '');
  assert.doesNotMatch(result.headers.location, /secret-code|aaaaa/);
  assert.deepEqual({ ...f.inputs[0] }, { state, code: 'secret-code',browserBinding });
});
for (const query of [
  `state=${state}&state=${state}&code=x`, `state=${state}&%63ode=x&code=y`,
  `state=${state}&code=x&error=denied`, `state=${state}`, `state=${state}&code=`,
  `state=${state}&code=x&organization_id=other`, `state=${state}&code=%FF`,
  `state=${state}&code=%ZZ`, `state=${state}&code=%00`, `state=${state}&code=x#fragment`,
]) test(`reject malformed callback before lifecycle: ${query.slice(-45)}`, async t => {
  const f = await fixture(t);
  assert.equal((await f.send(`/oauth/callback?${query}`)).status, 400);
  assert.equal(f.inputs.length, 0);
});
test('bounds input, denies request bodies and methods', async t => {
  const f = await fixture(t);
  assert.equal((await f.send('/oauth/callback?' + 'x'.repeat(8192))).status, 414);
  assert.equal((await f.send(`/oauth/callback?state=${state}&code=x`, 'POST')).status, 405);
  assert.equal((await f.send(`/oauth/callback?state=${state}&code=x`, 'GET', { 'Content-Length': '1' })).status, 400);
  assert.equal((await f.send('/other')).status, 404);
  assert.equal(f.inputs.length, 0);
});
test('rate limiter denies and fails closed without trusting forwarded IP', async t => {
  let address;
  const f = await fixture(t, { rateLimiter: { consume: async value => { address = value; return false; } } });
  assert.equal((await f.send(`/oauth/callback?state=${state}&code=x`, 'GET', { 'X-Forwarded-For': 'spoof' })).status, 429);
  assert.equal(address, '127.0.0.1');
  assert.equal(f.inputs.length, 0);
  const failing = await fixture(t, { rateLimiter: { consume: async () => { throw Error('private'); } } });
  assert.equal((await failing.send(`/oauth/callback?state=${state}&code=x`)).status, 503);
});
for (const location of ['https://evil.example/complete?outcome=connected',
  'https://connector.example/other?outcome=connected',
  'https://connector.example/complete?outcome=connected&code=secret',
  'https://connector.example/complete?outcome=connected&outcome=error']) {
  test('rejects unsafe completion redirect', async t => {
    const f = await fixture(t, { lifecycle: { callback: async () => ({ location }) } });
    const result = await f.send(`/oauth/callback?state=${state}&code=x`);
    assert.equal(result.status, 503); assert.equal(result.headers.location, undefined);
  });
}
test('requires explicit lifecycle, limiter and fixed HTTPS completion', () => {
  assert.throws(() => createOAuthCallbackHandler());
  assert.throws(() => createOAuthCallbackHandler({ lifecycle: { callback() {} }, completionUrl: 'https://connector.example' }));
});

test('missing, duplicate or malformed browser proof cookies never reach lifecycle',async t=>{
  const f=await fixture(t);const name=oauthBrowserBindingCookieName(state);
  for (const cookie of ['',`${name}=short`,`${name}=${browserBinding}; ${name}=${browserBinding}`,`other=${browserBinding}`]) {
    assert.equal((await f.send(`/oauth/callback?state=${state}&code=synthetic-code`,'GET',{Cookie:cookie})).status,400);
  }
  assert.equal(f.inputs.length,0);
});
