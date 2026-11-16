// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {createCaptureRouteAdminHandler} from '../src/capture-route-admin-http.mjs';
const origin='https://connector.example.test',canvas='https://canvas.example.test',operationId='10000000-0000-4000-8000-000000000001';
const identity={organizationId:'org',actorId:'operator',authorized:true};
const definition={producerRef:'source-one',platformId:'platform',bindingId:'binding-one',bindingRevision:3,
  requirement:{factType:'canvas.assignment_score',courseId:'11',userId:'22',activityId:'33'},claimNames:['completed'],effectiveTimePolicy:'require_provider_time'};
const create={operation_id:operationId,expected_platform_version:'2',producer_ref:'source-one',binding_id:'binding-one',binding_revision:'3',
  requirement:JSON.stringify(definition.requirement),claim_names:'["completed"]',effective_time_policy:'require_provider_time'};
const current={operation_id:operationId,expected_platform_version:'2',expected_route_version:'5'};
const snapshot=()=>({found:true,snapshot_at_ms:Date.now(),record:{id:'binding-one',revision:3,active:true,source_id:'source-one',provider:'canvas',
  fact_type:'canvas.assignment_score',resource_scope:{canvas_origin:canvas,course_id:'11',user_id:'22',activity_id:'33'},application_status:'pending',
  application_revision:1794844800000000,application_expires_at_ms:Date.now()+60000,claim_rules:{completed:{kind:'boolean',required:true,nullable:false},
    effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}}}});
const receipt=value=>({operationId:value.operationId,actorId:'operator',action:value.action,routeId:'route',platformId:'platform',
  version:value.action==='create'?1:5+(value.action==='schedule'?0:1),enabled:['activate','schedule'].includes(value.action),captureId:value.action==='schedule'?value.operationId:null});
async function fixture(t,{authenticate=async()=>identity,read,limit=async()=>true,store:overrides={}}={}) {
  const calls=[];
  const defaults={platform:()=>({platformId:'platform',canvasOrigin:canvas,configVersion:2,enabled:true,archived:false}),
    catalog:()=>({routes:[],nextCursor:null}),inspect:()=>({routeId:'route',version:5,enabled:false,definition}),receipt:()=>null,replay:()=>null,apply:receipt,capture:()=>null};
  const store=Object.fromEntries(Object.entries(defaults).map(([method,fn])=>[method,async value=>{calls.push({method,value});return (overrides[method]??fn)(value);} ]));
  const server=createServer(createCaptureRouteAdminHandler({store,authenticateAndAuthorize:authenticate,rateLimiter:{consume:limit},adminOrigin:origin,
    readBinding:async(req,value)=>{calls.push({method:'readBinding',value});return read?read(req,value):{...identity,snapshot:snapshot()};}}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const send=(action,fields={},options={})=>new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:server.address().port,path:options.path??`/platforms/platform/capture-routes/${action==='catalog'?'catalog':'route/'+action}`,
      method:options.method??'POST',headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...options.headers}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));});
    req.on('error',reject);req.end(options.raw??new URLSearchParams(fields).toString());
  });return {send,calls};
}
test('create and schedule use derived tenant/actor, own platform and fresh canonical binding only',async t=>{
  const f=await fixture(t);const response=await f.send('create',create);assert.equal(response.status,200);
  assert.deepEqual(f.calls.map(c=>c.method),['replay','platform','readBinding','apply']);
  assert.deepEqual(f.calls[2].value,{platformId:'platform',bindingId:'binding-one'});
  assert.deepEqual(f.calls[3].value,{organizationId:'org',platformId:'platform',routeId:'route',operationId,actorId:'operator',action:'create',expectedPlatformVersion:2,definition});
  assert.equal(response.headers['cache-control'],'no-store');assert.equal(response.headers['access-control-allow-origin'],undefined);
  const scheduled=await f.send('schedule',current);assert.equal(scheduled.status,200);assert.equal(JSON.parse(scheduled.body).receipt.captureId,operationId);
  assert.ok(f.calls.some(c=>c.method==='inspect'));
});
test('operator auth, Origin, format, rate and HTTP method deny before storage',async t=>{
  for(const [options,status] of [[{authenticate:async()=>null},401],[{authenticate:async()=>({...identity,authorized:false})},403],[{limit:async()=>false},429]]) {
    const f=await fixture(t,options);assert.equal((await f.send('create',create)).status,status);assert.equal(f.calls.length,0);
  }
  const f=await fixture(t);for(const [options,status] of [[{headers:{Origin:'https://evil.test'}},403],[{headers:{'Content-Type':'application/json'}},415],[{method:'GET'},405]]) {
    assert.equal((await f.send('create',create,options)).status,status);assert.equal(f.calls.length,0);
  }
});
test('caller authority, unknown/duplicate fields, ambiguous JSON, unsafe revisions and oversized bodies fail before storage',async t=>{
  const f=await fixture(t);
  for(const fields of [{...create,organization_id:'forged'},{...create,actor_id:'forged'},{...create,snapshot:'forged'},
    {...create,expected_platform_version:'9007199254740992'},{...create,binding_revision:'01'},
    {...create,requirement:'{"factType":"canvas.assignment_score","courseId":"11","userId":"22","userId":"99","activityId":"33"}'},
    {...create,claim_names:'["verified"]'}]) assert.equal((await f.send('create',fields)).status,400);
  for(const raw of [new URLSearchParams(create)+'&operation_id='+operationId,'operation_id=%QQ',Buffer.from([0xff])]) assert.equal((await f.send('create',{}, {raw})).status,400);
  assert.equal((await f.send('create',{}, {raw:'x'.repeat(8193)})).status,413);assert.equal(f.calls.length,0);
});
test('permission, actor or tenant changes after the lookup deny every write',async t=>{
  for(const currentIdentity of [null,{...identity,authorized:false},{...identity,actorId:'different'},{...identity,organizationId:'different'}]) {
    let calls=0;const f=await fixture(t,{authenticate:async()=>++calls===1?identity:currentIdentity});
    assert.equal((await f.send('create',create)).status,403);assert.equal(f.calls.filter(c=>c.method==='apply').length,0);
  }
});
test('freshness is checked after final reauthorization, and wrong resource/origin/revision never persists',async t=>{
  for(const mutate of [s=>s.snapshot_at_ms=Date.now()-30001,s=>s.record.active=false,s=>s.record.revision=4,
    s=>s.record.resource_scope.canvas_origin='https://other-canvas.example.test',s=>s.record.resource_scope.user_id='99']) {
    const s=snapshot();let authCalls=0;const f=await fixture(t,{read:async()=>({...identity,snapshot:s}),
      authenticate:async()=>{if(++authCalls===2) mutate(s);return identity;}});
    assert.equal((await f.send('create',create)).status,409);assert.equal(f.calls.filter(c=>c.method==='apply').length,0);
  }
});
test('original intent replay survives closed binding state and does not write or consult new authority snapshots',async t=>{
  const old=receipt({action:'create',operationId});const f=await fixture(t,{read:async()=>{throw Error('must not read');},store:{replay:()=>({conflict:false,receipt:old})}});
  const response=await f.send('create',create);assert.equal(response.status,200);assert.deepEqual(JSON.parse(response.body),{receipt:old});
  assert.deepEqual(f.calls.map(c=>c.method),['replay']);
  const conflict=await fixture(t,{store:{replay:()=>({conflict:true})}});assert.equal((await conflict.send('create',create)).status,409);assert.deepEqual(conflict.calls.map(c=>c.method),['replay']);
});
test('deactivate remains available without binding lookup while still requiring current permission and revision',async t=>{
  const f=await fixture(t,{read:async()=>{throw Error('must not read');},store:{platform:()=>{throw Error('must not read');}}});
  assert.equal((await f.send('deactivate',{operation_id:operationId,expected_route_version:'5'})).status,200);
  assert.deepEqual(f.calls.map(c=>c.method),['replay','apply']);assert.equal(f.calls[1].value.definition,undefined);
});
test('uncertain write reply reports unavailable without retries; receipt inspection reconciles the same ID',async t=>{
  const old=receipt({action:'create',operationId}),f=await fixture(t,{store:{apply:()=>{throw Error('synthetic token must not leak');},receipt:()=>old}});
  const response=await f.send('create',create);assert.equal(response.status,503);assert.equal(response.body,'');assert.equal(f.calls.filter(c=>c.method==='apply').length,1);
  assert.equal((await f.send('receipt',{operation_id:operationId})).status,200);assert.equal(f.calls.filter(c=>c.method==='apply').length,1);
});
test('historical read paths are scoped and neither schedule nor interpret completion as issuance',async t=>{
  const f=await fixture(t);for(const [action,fields] of [['catalog',{after_id:'route'}],['inspect',{}],['receipt',{operation_id:operationId}],['capture',{capture_id:operationId}]]) assert.equal((await f.send(action,fields)).status,200);
  assert.deepEqual(f.calls.map(c=>c.method),['catalog','inspect','receipt','capture']);
  assert.equal((await f.send('schedule',{...current,requirement:'forged'})).status,400);
});
