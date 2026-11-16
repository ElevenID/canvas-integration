// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic real OpenBao contract. The fixture contains an ephemeral read-only
// test token and CA; it is neither a runtime credential source nor a fallback.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
const fixture=JSON.parse(await readFile(process.argv[2],'utf8'));
const stage=process.argv[3];
assert.ok(['initial','rotated','destroyed','revoked'].includes(stage));
const provider=createOpenBaoKeyProvider({openbaoOrigin:fixture.origin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',
  ca:fixture.ca,tokenProvider:{getToken:async()=>fixture.token}});
if(stage==='revoked') {
  await assert.rejects(provider.current(),/^Error: connector_key_provider_unavailable$/);
  await assert.rejects(provider.byId('canvas-key-two'),/^Error: connector_key_provider_unavailable$/);
} else {
  const current=await provider.current();assert.equal(current.id,stage==='initial'?'canvas-key-one':'canvas-key-two');
  assert.deepEqual(current.key,Buffer.alloc(32,stage==='initial'?37:41));current.key.fill(0);
  assert.deepEqual(await provider.byId('canvas-key-two'),Buffer.alloc(32,41));
  if(stage==='destroyed') await assert.rejects(provider.byId('canvas-key-one'),/^Error: connector_key_provider_unavailable$/);
  else assert.deepEqual(await provider.byId('canvas-key-one'),Buffer.alloc(32,37));
}
if(stage==='initial') {
  const probe=(path,method,body)=>new Promise((resolve,reject)=>{
    const req=request(new URL(path,fixture.origin),{method,ca:fixture.ca,agent:false,rejectUnauthorized:true,
      headers:{'X-Vault-Token':fixture.token,'Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
    req.on('error',reject);req.end(body?JSON.stringify(body):undefined);
  });
  assert.equal(await probe('/v1/connector-kv/data/canvas-envelope/current','POST',{options:{cas:1},data:{id:'canvas-key-two'}}),403);
  assert.equal(await probe('/v1/connector-kv/data/outside-connector-path','GET'),403);
  assert.equal(await probe('/v1/sys/mounts','GET'),403);
}
console.log('Real OpenBao connector key contract passed: '+stage);
