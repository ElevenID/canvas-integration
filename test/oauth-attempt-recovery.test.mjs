// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createOAuthAttemptRecoveryHandler,createOAuthAttemptRecoveryStore} from '../src/oauth-attempt-recovery.mjs';
const origin='https://connector.example.test', authorizationId='a'.repeat(64);
const operationId='10000000-0000-4000-8000-000000000001';
const identity={organizationId:'org',actorId:'operator',authorized:true};
const mutation={authorization_id:authorizationId,operation_id:operationId,expected_revision:'2',action:'queue_staged_revocation'};
async function fixture(t,{authenticate=async()=>identity,limit=async()=>true,store:overrides={}}={}) {
  const calls=[];
  const store=Object.fromEntries(['inspect','receipt','recover'].map(method=>[method,async value=>{
    calls.push({method,value});return overrides[method]?overrides[method](value):{phase:'staged',revision:2};
  }]));
  const server=createServer(createOAuthAttemptRecoveryHandler({store,authenticateAndAuthorize:authenticate,
    rateLimiter:{consume:limit},adminOrigin:origin}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const send=(operation,fields,{headers={},method='POST',raw}={})=>new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,path:'/platforms/platform/oauth/attempts/'+operation,method,
      headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...headers}},res=>{
      const chunks=[];res.on('data',v=>chunks.push(v));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString()}));
    });req.on('error',reject);req.end(raw??new URLSearchParams(fields).toString());
  });
  return {send,calls};
}
test('recovery scopes inspection, receipt and mutation to the fresh Gateway identity',async t=>{
  const f=await fixture(t);
  assert.equal((await f.send('inspect',{authorization_id:authorizationId})).status,200);
  assert.equal((await f.send('receipt',{authorization_id:authorizationId,operation_id:operationId})).status,200);
  const response=await f.send('recover',mutation);assert.equal(response.status,200);
  assert.equal(response.headers['cache-control'],'no-store');assert.equal(response.headers['access-control-allow-origin'],undefined);
  assert.deepEqual(f.calls[2],{method:'recover',value:{organizationId:'org',platformId:'platform',authorizationId,
    operationId,actorId:'operator',expectedRevision:2,action:'queue_staged_revocation'}});
});
test('recovery rejects request-supplied authority and ambiguous or unbounded forms',async t=>{
  const f=await fixture(t);
  for(const fields of [{...mutation,organization_id:'foreign'},{...mutation,actor_id:'forged'},
    ...['0','01','-1','NaN','9007199254740992',' 2'].map(expected_revision=>({...mutation,expected_revision})),
    {...mutation,action:'publish'},{...mutation,authorization_id:'A'.repeat(64)}]) {
    assert.equal((await f.send('recover',fields)).status,400);
  }
  for(const raw of [new URLSearchParams(mutation)+'&action=abandon_unstarted','authorization_id=%QQ',Buffer.from([0xff])])
    assert.equal((await f.send('recover',{}, {raw})).status,400);
  assert.equal((await f.send('recover',{}, {raw:'a'.repeat(2049)})).status,413);
  assert.equal(f.calls.length,0);
});
test('recovery rechecks permission, actor and organization after reading mutation input',async t=>{
  for(const changed of [null,{...identity,authorized:false},{...identity,actorId:'other'},{...identity,organizationId:'other'}]) {
    let n=0;const f=await fixture(t,{authenticate:async()=>++n===1?identity:changed});
    assert.equal((await f.send('recover',mutation)).status,403);assert.equal(f.calls.length,0);
  }
});
test('recovery is session authorized, same-origin, POST-only and rate bounded',async t=>{
  const cases=[{authenticate:async()=>null,status:401},{authenticate:async()=>({...identity,authorized:false}),status:403},
    {authenticate:async()=>({...identity,actorId:undefined}),status:403},{limit:async()=>false,status:429},
    {authenticate:async()=>{throw Error('sensitive');},status:503}];
  for(const c of cases) {const f=await fixture(t,c);assert.equal((await f.send('recover',mutation)).status,c.status);assert.equal(f.calls.length,0);}
  const f=await fixture(t);
  assert.equal((await f.send('recover',mutation,{method:'GET'})).status,405);
  assert.equal((await f.send('recover',mutation,{headers:{Origin:'https://foreign.example'}})).status,403);
  assert.equal((await f.send('recover',mutation,{headers:{'Content-Type':'application/json'}})).status,415);
  assert.equal(f.calls.length,0);
});
test('recovery reports conflicts and unknown acknowledgments without retry or error disclosure',async t=>{
  const conflict=await fixture(t,{store:{recover:async()=>null}});
  assert.equal((await conflict.send('recover',mutation)).status,409);assert.equal(conflict.calls.length,1);
  const unknown=await fixture(t,{store:{recover:async()=>{throw Error('secret token from database');}}});
  const response=await unknown.send('recover',mutation);assert.equal(response.status,503);assert.equal(response.body,'');
  assert.equal(unknown.calls.length,1);assert.equal(unknown.calls[0].value.operationId,operationId);
});
test('store refuses malformed scope, actor, revision and oversized results',async()=>{
  let queries=0;const store=createOAuthAttemptRecoveryStore({query:async()=>{queries++;return {rows:[{result:{value:'x'.repeat(16385)}}]};}});
  const value={organizationId:'org',platformId:'platform',authorizationId,operationId,actorId:'operator',expectedRevision:1,action:'abandon_unstarted'};
  for(const altered of [{...value,organizationId:'bad/id'},{...value,actorId:'unbounded '.repeat(30)},
    {...value,expectedRevision:1.5},{...value,operationId:'not-id'},{...value,action:'publish'}])
    await assert.rejects(store.recover(altered),/connector_recovery_unavailable/);
  assert.equal(queries,0);await assert.rejects(store.inspect(value),/connector_recovery_unavailable/);assert.equal(queries,1);
});
test('store fails closed on unexpected audit payloads instead of exporting them',async()=>{
  const value={organizationId:'org',platformId:'platform',authorizationId,operationId,actorId:'operator',expectedRevision:1,action:'abandon_unstarted'};
  const valid={operationId,authorizationId,actorId:'operator',action:'abandon_unstarted',phase:'abandoned',revision:2,revocationJobId:null};
  for(const result of [{...valid,secret:'must never export'},{...valid,authorizationId:'b'.repeat(64)},
    {...valid,actorId:'unbounded actor'},{...valid,revision:9007199254740992}]) {
    const store=createOAuthAttemptRecoveryStore({query:async()=>({rows:[{result}]})});
    await assert.rejects(store.receipt(value),/connector_recovery_unavailable/);
    await assert.rejects(store.recover(value),/connector_recovery_unavailable/);
  }
});
