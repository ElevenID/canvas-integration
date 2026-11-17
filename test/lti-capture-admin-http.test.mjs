// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request} from 'node:http';
import {randomUUID} from 'node:crypto';
import {createLtiCaptureAdminHandler} from '../src/lti-capture-admin-http.mjs';
const origin='https://connector.example.test',canvas='https://canvas.example.test',registration=randomUUID(),operation=randomUUID(),service=randomUUID();
const identity={organizationId:'org',actorId:'actor',authorized:true};
const definition={producerRef:'producer',platformId:'platform',registrationId:registration,bindingId:'binding',bindingRevision:1,
 requirement:{factType:'canvas.ags_result',courseId:'11',userId:'opaque:user',lineItemId:'33',resourceLinkId:'link-one'},claimNames:['score'],effectiveTimePolicy:'as_of_read'};
const create={operation_id:operation,expected_platform_version:'1',expected_registration_version:'2',expected_key_version:'3',service_operation_id:service,
 producer_ref:'producer',binding_id:'binding',binding_revision:'1',requirement:JSON.stringify(definition.requirement),claim_names:'["score"]',effective_time_policy:'as_of_read'};
const current={operation_id:operation,expected_platform_version:'1',expected_registration_version:'2',expected_key_version:'3',expected_route_version:'4',service_operation_id:service};
const receipt=command=>({operationId:command.operationId,actorId:'actor',action:command.action,platformId:'platform',registrationId:registration,routeId:'route',
 version:command.action==='create'?1:4+(command.action==='schedule'?0:1),enabled:['activate','schedule'].includes(command.action),serviceOperationId:service,captureId:command.action==='schedule'?command.operationId:null});
function snapshot(){return {found:true,snapshot_at_ms:Date.now(),record:{id:'binding',revision:1,active:true,source_id:'producer',provider:'canvas',fact_type:'canvas.ags_result',
 application_status:'pending',application_revision:1,application_expires_at_ms:Date.now()+60000,
 resource_scope:{canvas_origin:canvas,registration_id:registration,course_id:'11',user_id:'opaque:user',line_item_id:'33',resource_link_id:'link-one'},
 claim_rules:{score:{kind:'number',required:true,nullable:true,minimum:-100,maximum:100},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:64}}}};}
async function fixture(t,{authenticate=async()=>identity,readBinding,overrides={}}={}) {
 const calls={writes:[],reads:0,deadlines:[]};
 const store={platform:async()=>({canvasOrigin:canvas,configVersion:1,enabled:true,archived:false}),
  inspect:async()=>({routeId:'route',version:4,enabled:true,serviceOperationId:service,definition}),catalog:async()=>({routes:[],nextCursor:null}),
  receipt:async()=>null,replay:async()=>null,capture:async()=>null,
  async apply(command,beforeCommit,deadline){calls.deadlines.push(deadline);if(await beforeCommit()!==true)return null;calls.writes.push(command);return receipt(command);},...overrides};
 const server=createServer(createLtiCaptureAdminHandler({store,readBinding:async(...args)=>{calls.reads++;return readBinding?readBinding(...args):{...identity,snapshot:snapshot()};},
  authenticateAndAuthorize:authenticate,rateLimiter:{consume:async()=>true},publicOrigin:origin}));
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 async function call(action,body={},headers={},path){return new Promise((resolve,reject)=>{
  const text=typeof body==='string'?body:new URLSearchParams(body).toString();
  const req=request({host:'127.0.0.1',port:server.address().port,path:path??`/platforms/platform/lti/registrations/${registration}/capture-routes/route/${action}`,method:'POST',
   headers:{Host:new URL(origin).host,Origin:origin,'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(text),...headers}},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));
   });req.on('error',reject);req.end(text);
 });}
 return {call,calls,store};
}
test('LTI capture administration derives tenant/actor and exact resource intent from canonical Gateway inputs',async t=>{
 const f=await fixture(t),r=await f.call('create',create);assert.equal(r.status,200);assert.equal(f.calls.writes.length,1);
 assert.equal(f.calls.writes[0].organizationId,'org');assert.equal(f.calls.writes[0].actorId,'actor');assert.deepEqual(f.calls.writes[0].definition,definition);
 assert.ok(f.calls.deadlines[0]<=Date.now()+30000);assert.equal(f.calls.reads,1);
 for(const key of ['organization_id','actor_id','application_id','subject_id','approved'])assert.equal((await f.call('create',{...create,[key]:'foreign'})).status,400);
});
test('Canonical resource or application mismatch denies new local configuration',async t=>{
 for(const mutate of [s=>s.record.resource_scope.registration_id=randomUUID(),s=>s.record.resource_scope.user_id='other',
  s=>s.record.resource_scope.resource_link_id='other',s=>s.record.application_status='approved',s=>s.record.application_expires_at_ms=1]) {
  const f=await fixture(t,{readBinding:async()=>{const s=snapshot();mutate(s);return {...identity,snapshot:s};}});
  assert.equal((await f.call('create',create)).status,409);assert.equal(f.calls.writes.length,0);
 }
});
test('Original replay survives changed binding/configuration without a new write or binding read',async t=>{
 const original=receipt({operationId:operation,action:'schedule'}),f=await fixture(t,{overrides:{replay:async()=>({conflict:false,receipt:original})},readBinding:async()=>{assert.fail('history does not refresh binding');}});
 const r=await f.call('schedule',current);assert.equal(r.status,200);assert.deepEqual(JSON.parse(r.body).receipt,original);assert.equal(f.calls.writes.length,0);assert.equal(f.calls.reads,0);
});
test('Concurrent original commit during route/platform precheck reconciles without a write retry',async t=>{
 for(const conflict of [false,true]) {
  let reads=0;const original=receipt({operationId:operation,action:'activate'});
  const f=await fixture(t,{overrides:{replay:async()=>++reads===1?null:conflict?{conflict:true}:{conflict:false,receipt:original},platform:async()=>({canvasOrigin:canvas,configVersion:2})}});
  const r=await f.call('activate',current);assert.equal(r.status,conflict?409:200);assert.equal(reads,2);assert.equal(f.calls.writes.length,0);
 }
});
test('Last asynchronous authorization cannot extend binding/application snapshot lifetime',async t=>{
 const realNow=Date.now;let now=realNow(),auths=0;
 const f=await fixture(t,{authenticate:async()=>{if(++auths===3)now+=31000;return identity;}});
 Date.now=()=>now;
 try{assert.equal((await f.call('create',create)).status,409);assert.equal(f.calls.writes.length,0);}
 finally{Date.now=realNow;}
});
test('Postcommit permission loss hides receipt while preserving original committed operation',async t=>{
 let allowed=true;
 const f=await fixture(t,{authenticate:async()=>({...identity,authorized:allowed}),overrides:{apply:async command=>{allowed=false;return receipt(command);}}});
 const r=await f.call('create',create);assert.equal(r.status,403);assert.equal(r.body,'');
});
test('Read responses are reauthorized before disclosure and registration/catalog/capture scopes are fixed',async t=>{
 let auths=0;const f=await fixture(t,{authenticate:async()=>++auths===1?identity:{...identity,organizationId:'foreign'},overrides:{inspect:async()=>({private:'must hide'})}});
 const r=await f.call('inspect');assert.equal(r.status,403);assert.equal(r.body,'');
 const g=await fixture(t,{overrides:{catalog:async v=>{assert.equal(v.registrationId,registration);return {routes:[],nextCursor:null};}}});
 assert.equal((await g.call('catalog',{}, {},`/platforms/platform/lti/registrations/${registration}/capture-routes/catalog`)).status,200);
 assert.equal((await g.call('capture',{capture_id:'not-uuid'})).status,400);
});
test('Original-byte forms reject duplicate/unknown fields and duplicate nested JSON',async t=>{
 const f=await fixture(t);
 for(const body of [new URLSearchParams(create).toString()+'&operation_id='+operation,new URLSearchParams({...create,requirement:'{"factType":"canvas.ags_result","factType":"canvas.nrps_membership"}'}).toString(),
  new URLSearchParams(create).toString()+'&unknown=value',new URLSearchParams(create).toString()+'&%ff=x'])assert.equal((await f.call('create',body)).status,400);
 assert.equal((await f.call('create',create,{Origin:'https://other.example'})).status,403);assert.equal(f.calls.writes.length,0);
});
test('A failing reconciliation read returns only redacted503 without another mutation',async t=>{
 let reads=0;
 const f=await fixture(t,{overrides:{replay:async()=>{if(++reads===1)return null;throw Error('PRIVATE_HISTORY');},platform:async()=>null}});
 const r=await f.call('activate',current);assert.equal(r.status,503);assert.equal(r.body,'');assert.equal(reads,2);assert.equal(f.calls.writes.length,0);
});
