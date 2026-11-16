// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createPlatformAdminHandler,createPlatformAdminStore} from '../src/platform-admin.mjs';
const origin='https://connector.example.test',canvas='https://canvas.example.test';
const operationId='10000000-0000-4000-8000-000000000001';
const identity={organizationId:'org',actorId:'operator',authorized:true};
const create={operation_id:operationId,canvas_origin:canvas};
const change={operation_id:operationId,expected_version:'2',enabled:'false',archived:'true'};
const platform={platformId:'platform',canvasOrigin:canvas,configVersion:2,enabled:true,archived:false};
const receipt={...platform,operationId,actorId:'operator',action:'create'};
async function fixture(t,{authenticate=async()=>identity,limit=async()=>true,store:overrides={}}={}) {
  const calls=[];
  const store=Object.fromEntries(['catalog','inspect','receipt','apply'].map(method=>[method,async value=>{
    calls.push({method,value});return overrides[method]?overrides[method](value):method==='catalog'?{platforms:[platform],nextCursor:null}:receipt;
  }]));
  const server=createServer(createPlatformAdminHandler({store,authenticateAndAuthorize:authenticate,
    rateLimiter:{consume:limit},adminOrigin:origin}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const send=(action,fields={},options={})=>new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,path:options.path??(action==='catalog'?'/platforms/catalog':`/platforms/platform/configuration/${action}`),
      method:options.method??'POST',headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...options.headers}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));
    });req.on('error',reject);req.end(options.raw??new URLSearchParams(fields).toString());
  });return {send,calls};
}
test('platform routes bind create/change and bounded catalog to the canonical session',async t=>{
  const f=await fixture(t);
  assert.equal((await f.send('catalog',{after_id:'last-platform'})).status,200);
  assert.deepEqual(f.calls[0],{method:'catalog',value:{organizationId:'org',afterId:'last-platform'}});
  const response=await f.send('create',create);assert.equal(response.status,200);
  assert.deepEqual(f.calls[1],{method:'apply',value:{organizationId:'org',platformId:'platform',operationId,
    canvasOrigin:canvas,actorId:'operator',action:'create'}});
  assert.equal((await f.send('change',change)).status,200);
  assert.deepEqual(f.calls[2],{method:'apply',value:{organizationId:'org',platformId:'platform',operationId,
    expectedVersion:2,enabled:false,archived:true,actorId:'operator',action:'change'}});
  assert.equal(response.headers['cache-control'],'no-store');assert.equal(response.headers['access-control-allow-origin'],undefined);
});
test('platform configuration rejects ambiguous authority and an origin change',async t=>{
  const f=await fixture(t);
  for(const fields of [{...create,organization_id:'foreign'},{...create,actor_id:'forged'},{...create,enabled:'true'},
    {...create,canvas_origin:'http://canvas.example.test'},{...create,canvas_origin:canvas+'/'},
    {...create,canvas_origin:'https://issuance.internal'},{...create,canvas_origin:'https://user:secret@canvas.example.test'}])
    assert.equal((await f.send('create',fields)).status,400);
  for(const fields of [{...change,canvas_origin:canvas},{...change,enabled:'true'},
    ...['0','01','-1','9007199254740992',' 2'].map(expected_version=>({...change,expected_version})),
    {...change,enabled:'TRUE'}]) assert.equal((await f.send('change',fields)).status,400);
  for(const raw of [new URLSearchParams(create)+'&operation_id='+operationId,'operation_id=%QQ',Buffer.from([0xff])])
    assert.equal((await f.send('create',{}, {raw})).status,400);
  assert.equal((await f.send('create',{}, {raw:'x'.repeat(4097)})).status,413);
  assert.equal((await f.send('catalog',{after_id:'../other'})).status,400);assert.equal(f.calls.length,0);
});
test('platform mutation rechecks permission, actor and tenant before any write',async t=>{
  for(const next of [null,{...identity,authorized:false},{...identity,actorId:'other'},{...identity,organizationId:'foreign'}]) {
    let n=0;const f=await fixture(t,{authenticate:async()=>++n===1?identity:next});
    assert.equal((await f.send('create',create)).status,403);assert.equal(f.calls.length,0);
  }
});
test('platform routes enforce same Origin, exact method/content type, session and budget',async t=>{
  const f=await fixture(t);
  assert.equal((await f.send('create',create,{method:'GET'})).status,405);
  assert.equal((await f.send('create',create,{headers:{Origin:'https://foreign.example'}})).status,403);
  assert.equal((await f.send('create',create,{headers:{'Content-Type':'application/json'}})).status,415);
  assert.equal((await f.send('create',create,{path:'/platforms/platform/configuration/create?x=1'})).status,404);
  for(const c of [{authenticate:async()=>null,status:401},{authenticate:async()=>({...identity,authorized:false}),status:403},
    {limit:async()=>false,status:429},{authenticate:async()=>{throw Error('sensitive');},status:503}]) {
    const denied=await fixture(t,c);assert.equal((await denied.send('create',create)).status,c.status);assert.equal(denied.calls.length,0);
  }assert.equal(f.calls.length,0);
});
test('platform failed acknowledgments are redacted and never automatically retried',async t=>{
  const f=await fixture(t,{store:{apply:async()=>{throw Error('sensitive');}}});
  const result=await f.send('create',create);assert.equal(result.status,503);assert.equal(result.body,'');assert.equal(f.calls.length,1);
  const conflict=await fixture(t,{store:{apply:async()=>null}});assert.equal((await conflict.send('change',change)).status,409);
});
test('platform store rejects corruption, extra fields and unbounded catalog rows',async()=>{
  const value={organizationId:'org',platformId:'platform',operationId,actorId:'operator',action:'create',canvasOrigin:canvas};
  for(const result of [{...receipt,secretRef:'synthetic-secret'},{...receipt,actorId:'foreign'},
    {...receipt,platformId:'other'},{...receipt,canvasOrigin:'http://canvas.example.test'},
    {...receipt,enabled:true},{...receipt,configVersion:7}]) {
    const store=createPlatformAdminStore({query:async()=>({rows:[{result}]})});
    await assert.rejects(store.apply(value),{message:'connector_platform_admin_unavailable'});
  }
  for(const result of [Array(22).fill(platform),[{...platform,secret:'hidden'}]]) {
    const store=createPlatformAdminStore({query:async()=>({rows:[{result}]})});
    await assert.rejects(store.catalog(value),{message:'connector_platform_admin_unavailable'});
  }
});
