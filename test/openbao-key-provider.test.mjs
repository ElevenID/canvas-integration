// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { httpsFixture,json } from './support/canvas-https-fixture.mjs';
const TOKEN='synthetic-connector-bao-token';
const ID='canvas-key-one';const KEY=Buffer.alloc(32,27);
const envelope=(data,version=1)=>({data:{data,metadata:{version,destroyed:false,deletion_time:''}}});
async function fixture(t,options={}) {
  const https=await httpsFixture();t.after(()=>https.close());
  const config={openbaoOrigin:https.origin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',
    tokenProvider:{getToken:async()=>TOKEN},ca:https.ca,...options};
  https.setHandler((req,res)=>json(res,req.url.endsWith('/current')?envelope({id:ID}):envelope({key_base64:KEY.toString('base64')})));
  return {https,config,provider:createOpenBaoKeyProvider(config)};
}
test('read-only key paths retain old keys across current-pointer rotation and use fresh authority',async t=>{
  let tokenCalls=0;const f=await fixture(t,{tokenProvider:{getToken:async()=>{tokenCalls++;return TOKEN;}}});
  let current=ID;const keys=new Map([[ID,KEY],['canvas-key-two',Buffer.alloc(32,31)]]);
  f.https.setHandler((req,res)=>{
    assert.equal(req.method,'GET');assert.equal(req.headers['x-vault-token'],TOKEN);
    assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.authorization,undefined);
    if(req.url==='/v1/connector-kv/data/canvas-envelope/current') return json(res,envelope({id:current},37));
    const match=/^\/v1\/connector-kv\/data\/canvas-envelope\/keys\/(canvas-key-(?:one|two))\?version=1$/.exec(req.url);
    assert.ok(match);json(res,envelope({key_base64:keys.get(match[1]).toString('base64')}));
  });
  const first=await f.provider.current();assert.equal(first.id,ID);assert.deepEqual(first.key,KEY);first.key.fill(0);
  current='canvas-key-two';const next=await f.provider.current();assert.deepEqual(next.key,keys.get(current));
  assert.deepEqual(await f.provider.byId(ID),KEY);assert.equal(tokenCalls,3);
  assert.equal(f.https.seen.length,5);
  f.https.setHandler((_req,res)=>json(res,{errors:['private-token-detail']},403));
  await assert.rejects(f.provider.byId(ID),/^Error: connector_key_provider_unavailable$/);
});
test('invalid IDs and traversal are rejected without credential lookup or network',async t=>{
  let calls=0;const f=await fixture(t,{tokenProvider:{getToken:async()=>{calls++;return TOKEN;}}});
  for(const id of ['other-key','canvas-','canvas-../key','canvas-key?version=2','canvas-key/other',null])
    await assert.rejects(f.provider.byId(id),/^Error: connector_key_provider_unavailable$/);
  assert.equal(calls,0);assert.equal(f.https.seen.length,0);
});
for(const status of [301,302,307,401,403,404,500]) test(`status ${status} fails closed without redirect or retry`,async t=>{
  const f=await fixture(t);f.https.setHandler((_req,res)=>json(res,{private:TOKEN},status,{Location:f.https.origin+'/steal'}));
  await assert.rejects(f.provider.byId(ID),/^Error: connector_key_provider_unavailable$/);
  assert.equal(f.https.seen.length,1);
});
for(const body of [
  envelope({key_base64:KEY.toString('base64')},2),
  {data:{data:{key_base64:KEY.toString('base64')},metadata:{version:1,destroyed:true,deletion_time:''}}},
  {data:{data:{key_base64:KEY.toString('base64')},metadata:{version:1,destroyed:false,deletion_time:'2026-11-15'}}},
  envelope({key_base64:'invalid'}),envelope({key_base64:Buffer.alloc(31).toString('base64')}),
  envelope({key_base64:'1'.repeat(43)+'='}),envelope({key_base64:KEY.toString('base64'),other:'mixed-secret'}),
  {data:{data:{key_base64:KEY.toString('base64')}}},null,
]) test('malformed, deleted, destroyed or substituted key response is never accepted',async t=>{
  const f=await fixture(t);f.https.setHandler((_req,res)=>json(res,body));
  await assert.rejects(f.provider.byId(ID),/^Error: connector_key_provider_unavailable$/);
});
for(const pointer of [{id:'other-key'},{id:ID,other:'secret'},null]) test('current pointer cannot select outside configured key namespace',async t=>{
  const f=await fixture(t);f.https.setHandler((_req,res)=>json(res,envelope(pointer)));
  await assert.rejects(f.provider.current(),/^Error: connector_key_provider_unavailable$/);assert.equal(f.https.seen.length,1);
});
test('TLS validation and body/encoding/UTF8 bounds cannot be bypassed',async t=>{
  const f=await fixture(t);const untrusted=createOpenBaoKeyProvider({...f.config,ca:undefined});
  await assert.rejects(untrusted.byId(ID),/^Error: connector_key_provider_unavailable$/);assert.equal(f.https.seen.length,0);
  for(const [body,headers] of [[Buffer.alloc(8193,32),{}],[Buffer.from([255]),{}],[Buffer.from('{}'),{'Content-Encoding':'gzip'}],[Buffer.from('{}'),{'Content-Type':'text/plain'}]]) {
    f.https.setHandler((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json',...headers});res.end(body);});
    await assert.rejects(f.provider.byId(ID),/^Error: connector_key_provider_unavailable$/);
  }
});
test('one deadline covers credential lookup and late lookup cannot send a request',async t=>{
  let resolveToken;let signal;
  const f=await fixture(t,{timeoutMs:50,tokenProvider:{getToken:input=>{signal=input.signal;return new Promise(resolve=>{resolveToken=resolve;});}}});
  await assert.rejects(f.provider.current(),/^Error: connector_key_provider_unavailable$/);
  assert.equal(signal.aborted,true);resolveToken(TOKEN);
  await new Promise(resolve=>setTimeout(resolve,20));assert.equal(f.https.seen.length,0);
});
test('header/body stalls use the same absolute deadline',async t=>{
  const f=await fixture(t,{timeoutMs:50});
  for(const partial of [false,true]) {
    f.https.setHandler((_req,res)=>{if(partial){res.writeHead(200,{'Content-Type':'application/json'});res.write('{');}});
    const start=Date.now();await assert.rejects(f.provider.byId(ID),/^Error: connector_key_provider_unavailable$/);
    assert.ok(Date.now()-start<2000);
  }
});
test('configuration has no insecure origin, traversal, missing authority or default-key fallback',()=>{
  const valid={openbaoOrigin:'https://bao.example',mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',tokenProvider:{getToken:async()=>TOKEN}};
  for(const patch of [{openbaoOrigin:'http://bao.example'},{openbaoOrigin:'https://user:pass@bao.example'},
    {openbaoOrigin:'https://bao.example/path'},{mount:'secret/other'},{keyPath:'../keys'},{keyPath:'keys/%2fescape'},
    {keyNamespace:''},{tokenProvider:null},{timeoutMs:0},{ca:'PRIVATE KEY'}]) assert.throws(()=>createOpenBaoKeyProvider({...valid,...patch}),/^Error: connector_key_provider_unavailable$/);
});
test('package denies browser conditions',async()=>{
  await assert.rejects(promisify(execFile)(process.execPath,['--conditions=browser','--input-type=module','-e',
    "await import('@elevenid/canvas-integration/openbao-key-provider')"]),error=>{assert.match(error.stderr,/server-only/);return true;});
});

test('deadline spans both current-pointer and key requests without resetting',async t=>{
  const f=await fixture(t,{timeoutMs:600});
  f.https.setHandler((req,res)=>setTimeout(()=>{if(!res.destroyed)json(res,req.url.endsWith('/current')?envelope({id:ID}):envelope({key_base64:KEY.toString('base64')}));},req.url.endsWith('/current')?250:450));
  await assert.rejects(f.provider.current(),/^Error: connector_key_provider_unavailable$/);
  assert.equal(f.https.seen.length,2);
});
test('invalid or failing token provider never sends credentials or leaks details',async t=>{
  const f=await fixture(t);
  for(const getToken of [async()=>null,async()=>'',async()=>TOKEN+'\r\nInjected:yes',async()=>{throw Error('private-key-value');}]) {
    const provider=createOpenBaoKeyProvider({...f.config,tokenProvider:{getToken}});
    await assert.rejects(provider.current(),/^Error: connector_key_provider_unavailable$/);
  }
  assert.equal(f.https.seen.length,0);
});
