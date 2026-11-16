// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
import { createLtiLaunchHandler } from '../src/lti-launch-http.mjs';
import { ltiBrowserCookieName, ltiBrowserCookie } from '../src/lti-browser-binding.mjs';
import { httpsFixture } from './support/canvas-https-fixture.mjs';

const id = '10000000-0000-4000-8000-000000000002', base = `/lti/registrations/${id}`;
const state = Buffer.alloc(32, 1).toString('base64url'), proof = Buffer.alloc(32, 2).toString('base64url');
const tokenHash = 'a'.repeat(64), token = 'synthetic.private.token';
const cookie = `${ltiBrowserCookieName(state)}=${proof}`;
async function fixture(options = {}) {
  const tls = await httpsFixture(), calls = [], context = { registrationId: id, launchId: 'launch-one',
    canvasOrigin: 'https://canvas.example', storageOrigin: 'https://sso.canvaslms.com', current: true, phase: 'accepted' };
  const lifecycle = {
    async begin(input) { calls.push(['begin',input]);return { ...context, state, browserProof: proof,
      authorizationUrl: `https://sso.canvaslms.com/api/lti/authorize_redirect?state=${state}` }; },
    async browserContext(input) { calls.push(['context',input]);return { ...context }; },
    async stage(input) { calls.push(['stage',input]);return { ...context, state, tokenHash }; },
    async confirm(input) { calls.push(['confirm',input]);if (input.browserProof !== proof) throw Error('invalid_lti_browser_proof');return { launchId: 'launch-one' }; },
    async active(input) { calls.push(['active',input]);if (input.browserProof !== proof || !context.current || context.phase !== 'accepted') throw Error('lti_launch_unavailable');return { protocolClaims: { subject: 'never-render-private-subject' } }; },
  };
  const handler = createLtiLaunchHandler({ publicOrigin: tls.origin, lifecycle, rateLimiter: options.rateLimiter ?? { consume: async () => true } });
  tls.setHandler((req,res) => { void handler(req,res).catch(() => res.destroy()); });
  async function send(path, method = 'GET', fields, headers = []) {
    const body = fields === undefined ? undefined : Buffer.isBuffer(fields) ? fields : Buffer.from(typeof fields === 'string' ? fields : new URLSearchParams(fields).toString());
    return new Promise((resolve,reject) => {
      let settled = false;
      const done = (error,value) => { if (settled) return;settled = true;error ? reject(error) : resolve(value); };
      const req = request(new URL(path,tls.origin), { method, ca: tls.ca, agent: false,
        headers: ['Host',new URL(tls.origin).host, ...(body === undefined ? [] : ['Content-Type','application/x-www-form-urlencoded','Content-Length',String(body.length)]), ...headers] }, res => {
        const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>done(null,{ status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error',error=>done(error));req.end(body);
    });
  }
  return { ...tls, calls, context, send };
}
test('login renders a nonce-CSP page and secure cross-site partitioned proof cookie',async()=>{
  const f=await fixture();try {
    const response=await f.send(base+'/login?'+new URLSearchParams({iss:'https://canvas.instructure.com',login_hint:'opaque',target_link_uri:f.origin+base+'/resource',client_id:'client-two',deployment_id:'deployment-two',lti_storage_target:'post_message_forwarding'}));
    assert.equal(response.status,200);assert.equal(response.headers['cache-control'],'no-store');
    assert.equal(response.headers['referrer-policy'],'origin');
    assert.match(response.headers['set-cookie'][0],/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=300$/);
    assert.ok(!response.headers['set-cookie'][0].includes('Domain='));
    const nonce=/script-src 'nonce-([^']+)'/.exec(response.headers['content-security-policy'])[1];
    assert.ok(response.body.includes(`nonce="${nonce}"`));
    assert.equal(f.calls[0][0],'begin');assert.equal(f.calls[0][1].clientId,'client-two');
    assert.equal(f.calls[0][1].deploymentId,'deployment-two');assert.equal(f.calls[0][1].storageTarget,'post_message_forwarding');
    assert.ok(response.body.includes('event.origin !== plan.storageOrigin'));assert.ok(response.body.includes('event.source !== target'));
    assert.ok(!response.body.includes("postMessage('*'"));
  }finally{await f.close();}
});
test('malformed, duplicate, authority-bearing and unsupported login inputs cause no initiation',async()=>{
  const f=await fixture();try {
    for(const query of ['iss=a&iss=b&login_hint=x','iss=%E0%A4%A&login_hint=x','iss=x&login_hint=x&organization_id=forged',
      'iss=x&login_hint=x&deployment_id=one&lti_deployment_id=two','iss=x&login_hint=x&lti_storage_target=attacker',
      'iss=x&login_hint=x&canvas_environment='+ 'a'.repeat(65)]) assert.equal((await f.send(base+'/login?'+query)).status,400);
    assert.equal(f.calls.length,0);
    const accepted=await f.send(base+'/login','POST',{iss:'https://canvas.instructure.com',login_hint:'opaque',lti_storage_target:'_parent'});
    assert.equal(accepted.status,200);assert.equal(f.calls[0][1].storageTarget,'_parent');
  }finally{await f.close();}
});
test('signed callback with original proof cookie confirms and redirects only to fixed resource',async()=>{
  const f=await fixture();try {
    const response=await f.send(base+'/launch','POST',{state,id_token:token},['Origin',f.context.storageOrigin,'Cookie',cookie]);
    assert.equal(response.status,303);assert.equal(response.headers.location,base+'/resource?state='+state);
    assert.deepEqual(f.calls.map(value=>value[0]),['context','stage','confirm']);assert.equal(f.calls.at(-1)[1].browserProof,proof);
    assert.equal(response.body,'');assert.ok(!JSON.stringify(response.headers).includes(token));
  }finally{await f.close();}
});
test('callback rejects missing/duplicate/foreign Origin, absent proof transport and ambiguous cookie',async()=>{
  const f=await fixture();try {
    for(const headers of [[],['Origin','https://attacker.invalid'],['Origin',f.context.storageOrigin,'Origin',f.context.storageOrigin]]) {
      assert.equal((await f.send(base+'/launch','POST',{state,id_token:token},headers)).status,403);
    }
    assert.equal((await f.send(base+'/launch','POST',{state,id_token:token},['Origin',f.context.storageOrigin])).status,403);
    assert.equal((await f.send(base+'/launch','POST',{state,id_token:token},['Origin',f.context.storageOrigin,'Cookie',cookie+'; '+cookie])).status,400);
    assert.equal(f.calls.filter(value=>value[0]==='stage').length,0);
  }finally{await f.close();}
});
test('cookie-free callback renders proof retrieval only; no raw JWT or premature confirmation',async()=>{
  const f=await fixture();try {
    const response=await f.send(base+'/launch','POST',{state,id_token:token,lti_storage_target:'post_message_forwarding'},['Origin',f.context.storageOrigin]);
    assert.equal(response.status,200);assert.ok(response.body.includes('lti.get_data'));
    assert.ok(!response.body.includes(token));assert.ok(!response.body.includes(proof));
    assert.deepEqual(f.calls.map(value=>value[0]),['context','stage']);
  }finally{await f.close();}
});
test('confirmation requires exact connector Origin and proof, rejecting client success flags',async()=>{
  const f=await fixture();try {
    const fields={state,browser_proof:proof,token_hash:tokenHash,storage_target:'post_message_forwarding'};
    assert.equal((await f.send(base+'/confirm','POST',fields,['Origin','https://attacker.invalid'])).status,403);
    assert.equal((await f.send(base+'/confirm','POST',{...fields,verified:'true'},['Origin',f.origin])).status,400);
    assert.equal((await f.send(base+'/confirm','POST',{...fields,browser_proof:Buffer.alloc(32,3).toString('base64url')},['Origin',f.origin])).status,400);
    const response=await f.send(base+'/confirm','POST',fields,['Origin',f.origin]);assert.equal(response.status,303);
    assert.ok(response.headers.location.startsWith(base+'/resource?'));assert.equal(response.body,'');
  }finally{await f.close();}
});
test('resource content requires current active proof; cookie-free reload retrieves proof first',async()=>{
  const f=await fixture();try {
    let response=await f.send(base+'/resource?state='+state,'GET',undefined,['Cookie',cookie]);
    assert.equal(response.status,200);assert.ok(response.body.includes('<h1>Canvas connected</h1>'));
    assert.equal(response.headers['referrer-policy'],'no-referrer');
    assert.ok(!response.body.includes('never-render-private-subject'));
    response=await f.send(base+'/resource?state='+state+'&storage_target=post_message_forwarding');
    assert.equal(response.status,200);assert.ok(response.body.includes('lti.get_data'));assert.ok(!response.body.includes('<h1>Canvas connected</h1>'));
    response=await f.send(base+'/resource','POST',{state,browser_proof:proof},['Origin',f.origin]);assert.equal(response.status,200);
    f.context.current=false;
    assert.equal((await f.send(base+'/resource?state='+state,'GET',undefined,['Cookie',cookie])).status,403);
    assert.equal((await f.send(base+'/resource?state='+state+'&storage_target=post_message_forwarding')).status,403);
  }finally{await f.close();}
});
test('request framing/encoding/header ambiguity and unsupported methods fail before lifecycle',async()=>{
  const f=await fixture();try {
    for(const headers of [['Content-Type','application/json'],['Content-Encoding','gzip']]) {
      assert.equal((await f.send(base+'/launch','POST',{state,id_token:token},headers)).status,400);
    }
    assert.equal((await f.send(base+'/launch','POST',Buffer.from([0xff]))).status,400);
    assert.equal((await f.send(base+'/launch','POST','x'.repeat(98305))).status,400);
    assert.equal((await f.send(base+'/launch')).status,405);
    assert.equal((await f.send(base+'/resource','POST',{state,browser_proof:proof},['Origin',f.origin,'Origin',f.origin])).status,403);
    assert.equal((await f.send(base+'/login?'+ 'x'.repeat(8200))).status,414);
    assert.equal(f.calls.length,0);
  }finally{await f.close();}
});
test('shared rate budget fails closed and does not initiate or authenticate work',async()=>{
  for(const consume of [async()=>false,async()=>{throw Error('private-material');}]) {
    const f=await fixture({rateLimiter:{consume}});try {
      const response=await f.send(base+'/login?iss=x&login_hint=y');assert.ok([429,503].includes(response.status));
      assert.equal(f.calls.length,0);assert.ok(!response.body.includes('private-material'));
    }finally{await f.close();}
  }
});
test('cookie helper uses canonical independent proof values and rejects ambiguous fields',()=>{
  assert.match(ltiBrowserCookie(state,proof),/^__Host-canvas_lti_[a-f0-9]{64}=/);
  assert.throws(()=>ltiBrowserCookie('bad',proof));assert.throws(()=>ltiBrowserCookie(state,'bad'));
});
