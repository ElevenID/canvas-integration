// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createOAuthClientHandler,createOAuthClientStore} from '../src/oauth-client-admin.mjs';
import {clientId,clientSecret} from '../src/oauth-client-contract.mjs';
import {createEncryptedVault} from '../src/encrypted-vault.mjs';
const origin='https://connector.example.test',operationId='10000000-0000-4000-8000-000000000001';
const secret='synthetic_provisioned_client_secret_0001';
const identity={organizationId:'org',actorId:'operator',authorized:true};
const form={operation_id:operationId,expected_version:'1',client_id:'client',client_secret:secret};
const receipt={platformId:'platform',operationId,actorId:'operator',clientId:'client',clientSecretRef:'20000000-0000-4000-8000-000000000001',configVersion:2};
async function fixture(t,{authenticate=async()=>identity,limit=async()=>true,store:overrides={}}={}) {
  const calls=[];
  const store=Object.fromEntries(['inspect','receipt','provision'].map(method=>[method,async(value,plain)=>{
    calls.push({method,value,plain});return overrides[method]?overrides[method](value,plain):receipt;
  }]));
  const server=createServer(createOAuthClientHandler({store,authenticateAndAuthorize:authenticate,rateLimiter:{consume:limit},adminOrigin:origin}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const send=(action,fields={},options={})=>new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,path:`/platforms/platform/oauth/client/${action}`,
      method:options.method??'POST',headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...options.headers}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));
    });req.on('error',reject);req.end(options.raw??new URLSearchParams(fields).toString());
  });return {send,calls};
}
test('client provisioning derives authority from Gateway and separates plaintext from receipt metadata',async t=>{
  const f=await fixture(t),result=await f.send('provision',form);assert.equal(result.status,200);
  assert.deepEqual(f.calls[0],{method:'provision',value:{organizationId:'org',platformId:'platform',operationId,
    actorId:'operator',expectedVersion:1,clientId:'client'},plain:secret});
  assert.equal(result.body.includes(secret),false);assert.equal(result.headers['cache-control'],'no-store');
  assert.equal(result.headers['access-control-allow-origin'],undefined);
  assert.equal((await f.send('inspect')).status,200);assert.equal((await f.send('receipt',{operation_id:operationId})).status,200);
});
test('client provisioning rejects authority, references, ambiguous and invalid input before custody',async t=>{
  const f=await fixture(t);
  for(const fields of [{...form,organization_id:'foreign'},{...form,actor_id:'forged'},{...form,client_secret_ref:receipt.clientSecretRef},
    ...['0','01','-1','9007199254740992',' 1'].map(expected_version=>({...form,expected_version})),
    {...form,client_id:' client'},{...form,client_secret:'x\nsecret'},{...form,client_secret:'x'.repeat(4097)}])
    assert.equal((await f.send('provision',fields)).status,400);
  for(const raw of [new URLSearchParams(form)+'&client_secret=other','client_secret=%FF','client_secret=%QQ',Buffer.from([0xff])])
    assert.equal((await f.send('provision',{}, {raw})).status,400);
  assert.equal((await f.send('provision',{}, {raw:'x'.repeat(65537)})).status,413);
  assert.equal((await f.send('inspect',{client_secret:secret})).status,400);assert.equal(f.calls.length,0);
});
test('client provisioning rechecks canonical actor, tenant and permission before encrypting',async t=>{
  for(const next of [null,{...identity,authorized:false},{...identity,actorId:'other'},{...identity,organizationId:'foreign'}]) {
    let n=0;const f=await fixture(t,{authenticate:async()=>++n===1?identity:next});
    assert.equal((await f.send('provision',form)).status,403);assert.equal(f.calls.length,0);
  }
});
test('client routes require session, Origin, method, media type and distributed budget',async t=>{
  const f=await fixture(t);
  assert.equal((await f.send('provision',form,{method:'GET'})).status,405);
  assert.equal((await f.send('provision',form,{headers:{Origin:'https://foreign.example'}})).status,403);
  assert.equal((await f.send('provision',form,{headers:{'Content-Type':'application/json'}})).status,415);
  for(const c of [{authenticate:async()=>null,status:401},{authenticate:async()=>({...identity,authorized:false}),status:403},
    {limit:async()=>false,status:429},{authenticate:async()=>{throw Error(secret);},status:503}]) {
    const denied=await fixture(t,c);assert.equal((await denied.send('provision',form)).status,c.status);assert.equal(denied.calls.length,0);
  }assert.equal(f.calls.length,0);
});
test('unknown provisioning replies never auto-retry or reveal plaintext failures',async t=>{
  const f=await fixture(t,{store:{provision:async()=>{throw Error(secret);}}});
  const result=await f.send('provision',form);assert.equal(result.status,503);assert.equal(result.body,'');assert.equal(f.calls.length,1);
  const conflict=await fixture(t,{store:{provision:async()=>null}});assert.equal((await conflict.send('provision',form)).status,409);
});
test('client store rejects corrupted, secret-bearing or mismatched receipt data',async()=>{
  const value={organizationId:'org',platformId:'platform',operationId,actorId:'operator',clientId:'client',expectedVersion:1};
  for(const result of [{...receipt,secret},{...receipt,inputDigest:'hidden'},{...receipt,clientId:'other'},
    {...receipt,configVersion:3},{...receipt,actorId:'other'}]) {
    const store=createOAuthClientStore({query:async()=>({rows:[{result}]})},{stageClientConfiguration:async()=>result});
    await assert.rejects(store.provision(value,secret),{message:'connector_oauth_client_unavailable'});
  }
});
test('malformed JS Unicode never aliases a different secret in keyed operation proof',async()=>{
  let calls=0;
  const vault=createEncryptedVault({pool:{query:async()=>{calls++;throw Error('unexpected SQL');}},
    keyProvider:{current:async()=>{calls++;},byId:async()=>{calls++;}}});
  const input={organizationId:'org',platformId:'platform',operationId,actorId:'operator',clientId:'client',expectedVersion:1};
  for(const value of ['\uD800','\uD801','\uDC00']) {
    assert.equal(clientId(value),false);assert.equal(clientSecret(value),false);
    await assert.rejects(vault.stageClientConfiguration(input,value),{message:'connector_vault_unavailable'});
  }
  assert.equal(calls,0);assert.equal(clientSecret('synthetic_雪_secret'),true);
});
