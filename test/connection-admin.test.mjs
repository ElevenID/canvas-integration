// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createConnectionAdminHandler,createConnectionAdminStore} from '../src/connection-admin.mjs';
const origin='https://connector.example.test',connectionId='10000000-0000-4000-8000-000000000001';
const operationId='20000000-0000-4000-8000-000000000001',jobId='30000000-0000-4000-8000-000000000001';
const identity={organizationId:'org',actorId:'operator',authorized:true};
const mutation={connection_id:connectionId,operation_id:operationId,expected_revision:'2'};
const receipt={connectionId,operationId,actorId:'operator',expectedRevision:2,status:'disconnected',revocationJobId:jobId};
async function fixture(t,{authenticate=async()=>identity,limit=async()=>true,store:overrides={}}={}) {
  const calls=[];
  const store=Object.fromEntries(['inspect','receipt','disconnect'].map(method=>[method,async value=>{
    calls.push({method,value});return overrides[method]?overrides[method](value):receipt;
  }]));
  const server=createServer(createConnectionAdminHandler({store,authenticateAndAuthorize:authenticate,
    rateLimiter:{consume:limit},adminOrigin:origin}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const send=(action,fields={},options={})=>new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,path:`/platforms/platform/connection/${action}`,
      method:options.method??'POST',headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...options.headers}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));
    });req.on('error',reject);req.end(options.raw??new URLSearchParams(fields).toString());
  });
  return {send,calls};
}
test('connection routes derive authority from Gateway and preserve exact operation identity',async t=>{
  const f=await fixture(t);
  assert.equal((await f.send('inspect')).status,200);
  assert.equal((await f.send('receipt',{operation_id:operationId})).status,200);
  const response=await f.send('disconnect',mutation);assert.equal(response.status,200);
  assert.equal(response.headers['cache-control'],'no-store');assert.equal(response.headers['access-control-allow-origin'],undefined);
  assert.deepEqual(f.calls[2],{method:'disconnect',value:{organizationId:'org',platformId:'platform',operationId,
    connectionId,expectedRevision:2,actorId:'operator'}});
});
test('connection mutation rejects caller authority, duplicate fields and invalid revisions',async t=>{
  const f=await fixture(t);
  for(const fields of [{...mutation,organization_id:'foreign'},{...mutation,actor_id:'forged'},
    ...['0','01','-1','NaN','9007199254740992',' 2'].map(expected_revision=>({...mutation,expected_revision})),
    {...mutation,connection_id:'not-a-uuid'}]) assert.equal((await f.send('disconnect',fields)).status,400);
  for(const raw of [new URLSearchParams(mutation)+'&expected_revision=2','operation_id=%QQ',Buffer.from([0xff])])
    assert.equal((await f.send('disconnect',{}, {raw})).status,400);
  assert.equal((await f.send('disconnect',{}, {raw:'a'.repeat(2049)})).status,413);
  assert.equal((await f.send('inspect',{connection_id:connectionId})).status,400);
  assert.equal(f.calls.length,0);
});
test('connection disconnect rechecks canonical permission and actor after reading body',async t=>{
  for(const changed of [null,{...identity,authorized:false},{...identity,actorId:'other'},{...identity,organizationId:'other'}]) {
    let n=0;const f=await fixture(t,{authenticate:async()=>++n===1?identity:changed});
    assert.equal((await f.send('disconnect',mutation)).status,403);assert.equal(f.calls.length,0);
  }
});
test('connection routes fail closed on missing session, Origin, permission and rate budget',async t=>{
  for(const c of [{authenticate:async()=>null,status:401},{authenticate:async()=>({...identity,authorized:false}),status:403},
    {authenticate:async()=>({...identity,actorId:undefined}),status:403},{limit:async()=>false,status:429},
    {authenticate:async()=>{throw Error('synthetic-sensitive');},status:503}]) {
    const f=await fixture(t,c);assert.equal((await f.send('disconnect',mutation)).status,c.status);assert.equal(f.calls.length,0);
  }
  const f=await fixture(t);
  assert.equal((await f.send('disconnect',mutation,{method:'GET'})).status,405);
  assert.equal((await f.send('disconnect',mutation,{headers:{Origin:'https://foreign.example'}})).status,403);
  assert.equal((await f.send('disconnect',mutation,{headers:{'Content-Type':'application/json'}})).status,415);
  assert.equal(f.calls.length,0);
});
test('connection route never retries an uncertain database mutation or reveals errors',async t=>{
  const f=await fixture(t,{store:{disconnect:async()=>{throw Error('synthetic-raw-secret');}}});
  const result=await f.send('disconnect',mutation);assert.equal(result.status,503);assert.equal(result.body,'');
  assert.equal(f.calls.length,1);
  const conflict=await fixture(t,{store:{disconnect:async()=>null}});
  assert.equal((await conflict.send('disconnect',mutation)).status,409);
});
test('connection store rejects unexpected storage fields instead of leaking them',async()=>{
  const value={organizationId:'org',platformId:'platform',operationId,connectionId,actorId:'operator',expectedRevision:2};
  for(const result of [{...receipt,accessToken:'synthetic-secret'},{...receipt,actorId:'different'},
    {...receipt,connectionId:operationId},{...receipt,expectedRevision:3}]) {
    const store=createConnectionAdminStore({query:async()=>({rows:[{result}]})});
    await assert.rejects(store.disconnect(value),{message:'connector_connection_admin_unavailable'});
  }
  const store=createConnectionAdminStore({query:async()=>({rows:[{result:{connection:null,pendingRefresh:false,pendingRevocation:true,extra:'secret'}}]})});
  await assert.rejects(store.inspect(value),{message:'connector_connection_admin_unavailable'});
});
