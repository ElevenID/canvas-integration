// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {prepareLtiCaptureRequirement,prepareLtiCaptureRouteIntent,prepareLtiCaptureRoute,projectLtiCapture} from '../src/lti-capture-contract.mjs';
import {createLtiCaptureWorker} from '../src/lti-capture-worker.mjs';
import {createCanvasLtiServiceReader,ltiReadScopes} from '../src/canvas-lti-service-client.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const registrationId=randomUUID(),origin='https://canvas.example';
const route=(members=false)=>({producerRef:'producer',platformId:'platform',registrationId,bindingId:'binding',bindingRevision:1,
 requirement:members?{factType:'canvas.nrps_membership',courseId:'11',userId:'opaque:user',contextId:'opaque:context',resourceLinkId:'link-one'}:
 {factType:'canvas.ags_result',courseId:'11',userId:'opaque:user',lineItemId:'33',resourceLinkId:'link-one'},
 claimNames:members?['provider_state']:['score','score_maximum','score_percent'],effectiveTimePolicy:'as_of_read'});
const numeric={kind:'number',required:true,nullable:true,minimum:-10000,maximum:10000};
const text={kind:'text',required:true,nullable:false,max_bytes:64};
function snapshot(r=route(),now=Date.now()) {
 const plan=prepareLtiCaptureRequirement(r.requirement);
 return {found:true,snapshot_at_ms:now,record:{id:r.bindingId,revision:r.bindingRevision,active:true,source_id:r.producerRef,
  provider:'canvas',fact_type:plan.factType,application_status:'pending',application_revision:1,application_expires_at_ms:now+60000,
  resource_scope:{canvas_origin:origin,registration_id:registrationId,...plan.scope},
  claim_rules:{...Object.fromEntries(r.claimNames.map(n=>[n,n==='provider_state'?{...text}:{...numeric}])),effective_time_source:{...text}}}};
}
const observation=()=>({userId:'opaque:user',resultScore:8,resultMaximum:10,lineItemUrl:origin+'/api/lti/courses/11/line_items/33'});
test('LTI routes bind exact public Gateway registration/resource data and preserve opaque user IDs',()=>{
 for(const members of [false,true]) {
  const r=route(members),s=snapshot(r);assert.deepEqual(prepareLtiCaptureRoute(r,s,{platformOrigin:origin}),prepareLtiCaptureRouteIntent(r));
  assert.equal(prepareLtiCaptureRequirement(r.requirement).scope.user_id,'opaque:user');
  const mutations=[s=>s.found=false,s=>s.record.active=false,s=>s.record.provider='other',s=>s.record.source_id='foreign',
   s=>s.record.revision++,s=>s.record.application_status='approved',s=>s.record.application_expires_at_ms=1,s=>s.snapshot_at_ms-=31000,
   s=>s.record.resource_scope.canvas_origin='https://other.example',s=>s.record.resource_scope.registration_id=randomUUID(),
   s=>s.record.resource_scope.resource_link_id='another',s=>s.record.resource_scope.user_id='numeric-other',
   s=>s.record.claim_rules.approved={kind:'boolean',required:true,nullable:false},s=>s.record.claim_rules.effective_time_source.nullable=true];
  for(const change of mutations){const changed=structuredClone(s);change(changed);assert.throws(()=>prepareLtiCaptureRoute(r,changed,{platformOrigin:origin}),/lti_capture_unavailable/);}
 }
});
test('LTI route intent rejects authority, aliases, coerced IDs, unsupported claims and fake provider event time',()=>{
 const r=route();
 for(const changed of [{...r,approved:true},{...r,effectiveTimePolicy:'require_provider_time'},{...r,claimNames:['completed']},
  {...r,claimNames:['score','score']},{...r,requirement:{...r.requirement,courseId:11}},
  {...r,requirement:{...r.requirement,subjectId:'marty-user'}},{...r,registrationId:'not-uuid'},
  {...r,requirement:{...r.requirement,userId:'bad\nuser'}}])assert.throws(()=>prepareLtiCaptureRouteIntent(changed),/lti_capture_unavailable/);
});
test('AGS projects selected bounded numeric facts at read time without inferring completion',()=>{
 const options={platformOrigin:origin,observedAtMs:Date.now()},value=projectLtiCapture(route(),observation(),options);
 assert.deepEqual(value.claims,{score:8,score_maximum:10,score_percent:80,effective_time_source:'observation_read'});
 assert.equal(value.observedAtMs,value.effectiveAtMs);assert.equal(Object.hasOwn(value.claims,'completed'),false);
 assert.equal(projectLtiCapture(route(),{...observation(),resultScore:null},options).claims.score_percent,null);
 assert.equal(projectLtiCapture(route(),{...observation(),resultMaximum:0},options).claims.score_percent,null);
 for(const changed of [null,{...observation(),userId:'foreign'},{...observation(),lineItemUrl:'https://other.example/api/lti/courses/11/line_items/33'},
  {...observation(),resultScore:Infinity},{...observation(),resultMaximum:-1},{...observation(),resultScore:Number.MAX_SAFE_INTEGER},
  {...observation(),resultScore:1e-100,resultMaximum:1e-320},{...observation(),completed:true}])
  assert.throws(()=>projectLtiCapture(route(),changed,options),/lti_capture_unavailable/);
});
test('NRPS status is provider data; roles, absence and PII cannot become canonical identity or authority',()=>{
 const r=route(true),options={platformOrigin:origin,observedAtMs:Date.now()},o={userId:'opaque:user',contextId:'opaque:context',status:'Inactive',roles:['https://example.test/Administrator']};
 assert.deepEqual(projectLtiCapture(r,o,options).claims,{provider_state:'Inactive',effective_time_source:'observation_read'});
 for(const changed of [null,{...o,email:'private@example.test'},{...o,contextId:'other'},{...o,status:'unknown'}])
  assert.throws(()=>projectLtiCapture(r,changed,options),/lti_capture_unavailable/);
});
async function fixture(t,{members=false,jobChange={},attemptChange={},permit=async()=>true,tokenPermit=async()=>true,complete=async()=>true,mode='valid'}={}) {
 const peer=await httpsFixture();t.after(()=>peer.close());const definition=route(members),operationId=randomUUID(),tokenReference=randomUUID(),kid=randomUUID();
 const now=Math.floor(Date.now()/1000),token={accessToken:'synthetic_lti_read_bearer_000001',scopes:Object.values(ltiReadScopes),expiresAtMs:(now+60)*1000};
 const job={organizationId:'org',producerRef:'producer',captureId:randomUUID(),leaseId:randomUUID(),attempts:1,definition,
  canvasOrigin:peer.origin,platformVersion:1,registrationVersion:2,keyVersion:3,serviceOperationId:operationId,tokenReference,...jobChange};
 const attempt={organizationId:'org',operationId,platformId:'platform',registrationId,actorId:'actor',platformVersion:1,registrationVersion:2,keyVersion:3,kid,
  clientId:'client',canvasOrigin:peer.origin,toolOrigin:'https://tool.example',scopes:[...token.scopes].sort(),phase:'published',dispatchId:randomUUID(),issuedAt:now,expiresAt:now+120,tokenReference,
  receipt:{operationId,actorId:'actor',platformId:'platform',registrationId,kid,keyVersion:3,tokenReference,scopes:[...token.scopes].sort(),expiresAtMs:token.expiresAtMs},...attemptChange};
 const calls={token:0,inspect:0,permit:0,tokenPermit:0,completed:[],deferred:[]};
 const repository={claim:async()=>job,permit:async(...args)=>{calls.permit++;return permit(...args);},
  complete:async(...args)=>{calls.completed.push(args);return complete(...args);},defer:async(...args)=>{calls.deferred.push(args);return true;}};
 const tokenStore={inspect:async()=>{calls.inspect++;return attempt;},currentToken:async()=>{calls.token++;return token;},
  permitRead:async(...args)=>{calls.tokenPermit++;return tokenPermit(...args);}};
 const worker=createLtiCaptureWorker({repository,tokenStore,organizationId:'org',producerRef:'producer',ca:peer.ca,allowedPrivateAddresses:['127.0.0.1','::1']});
 peer.setHandler((req,res)=>{
  assert.equal(req.method,'GET');assert.equal(req.headers.authorization,'Bearer '+token.accessToken);assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
  const url=new URL(req.url,peer.origin);
  if(mode==='outage')return json(res,{private:'do not project'},503);
  if(mode==='lost-response')return res.destroy();
  if(url.pathname.endsWith('/names_and_roles'))return json(res,{id:url.href,context:{id:'opaque:context'},members:mode==='missing'?[]:[
   {user_id:'opaque:user',status:'Active',roles:['https://example.test/Administrator'],email:'private@example.test'}]});
  if(url.pathname.endsWith('/results'))return json(res,mode==='missing'?[]:[{id:peer.origin+'/api/lti/courses/11/line_items/33/results/44',
   userId:'opaque:user',scoreOf:peer.origin+'/api/lti/courses/11/line_items/33',resultScore:8,resultMaximum:10,comment:'private'}]);
  return json(res,{id:peer.origin+'/api/lti/courses/11/line_items/33',scoreMaximum:10,resourceLinkId:mode==='wrong-link'?'other':mode==='no-link'?undefined:'link-one'});
 });
 return {worker,job,attempt,token,peer,calls};
}
test('Keyless capture reads actual Canvas TLS and hands only projection to repository',async t=>{
 for(const members of [false,true]) {
  const f=await fixture(t,{members});assert.equal((await f.worker.runOnce()).state,'captured');
  assert.equal(f.calls.completed.length,1);assert.equal(f.calls.deferred.length,0);assert.equal(f.calls.token,1);
  assert.equal(f.peer.seen.length,members?1:2);assert.equal(f.calls.permit,f.peer.seen.length);assert.equal(f.calls.tokenPermit,f.peer.seen.length);
  const claims=f.calls.completed[0][4].claims;
  assert.deepEqual(claims,members?{provider_state:'Active',effective_time_source:'observation_read'}:{score:8,score_maximum:10,score_percent:80,effective_time_source:'observation_read'});
  assert.equal(/private|Administrator|accessToken|completed/.test(JSON.stringify(claims)),false);
 }
});
test('AGS wrong or missing resource-link match parks before learner result read',async t=>{
 for(const mode of ['wrong-link','no-link']) {
  const f=await fixture(t,{mode});assert.equal((await f.worker.runOnce()).state,'parked');
  assert.equal(f.peer.seen.length,1);assert.equal(f.calls.completed.length,0);assert.equal(f.calls.deferred[0][4],'configuration_changed');
 }
});
test('No observation and transport failures never enqueue negative facts or reacquire credentials',async t=>{
 for(const mode of ['missing','outage','lost-response']) {
  const f=await fixture(t,{mode,members:true});assert.equal((await f.worker.runOnce()).state,'retry_scheduled');
  assert.equal(f.calls.completed.length,0);assert.equal(f.calls.token,1);assert.equal(f.peer.seen.length,1);
  assert.equal(f.calls.deferred[0][4],mode==='missing'?'observation_missing':'provider_unavailable');
 }
});
test('Wrong tenant, registration, versions or token reference cannot release bearer',async t=>{
 for(const options of [{jobChange:{organizationId:'foreign'}},{jobChange:{producerRef:'foreign'}},{attemptChange:{registrationId:randomUUID()}},
  {attemptChange:{keyVersion:4}},{attemptChange:{canvasOrigin:'https://foreign.example'}},{attemptChange:{tokenReference:randomUUID()}}]) {
  const f=await fixture(t,options);assert.ok(['parked','retry_scheduled','reconciliation_required'].includes((await f.worker.runOnce()).state));
  assert.equal(f.calls.token,0);assert.equal(f.peer.seen.length,0);assert.equal(f.calls.completed.length,0);
 }
});
test('Every verified-TLS GET must pass current lease and token permits',async t=>{
 for(const options of [{permit:async()=>false},{tokenPermit:async()=>false}]) {
  const f=await fixture(t,options);assert.equal((await f.worker.runOnce()).state,'parked');assert.equal(f.peer.seen.length,0);assert.equal(f.calls.completed.length,0);
 }
 const f=await fixture(t,{permit:async()=>++permits===1});let permits=0;
 assert.equal((await f.worker.runOnce()).state,'parked');assert.equal(f.peer.seen.length,1);assert.equal(f.calls.completed.length,0);
});
test('Lost or rejected complete acknowledgement requires original-capture reconciliation, never retry inside worker',async t=>{
 for(const complete of [async()=>false,async()=>{throw Error('lost committed response');}]) {
  const f=await fixture(t,{complete});assert.equal((await f.worker.runOnce()).state,'reconciliation_required');
  assert.equal(f.calls.completed.length,1);assert.equal(f.calls.completed[0][2],f.job.captureId);assert.equal(f.calls.deferred.length,0);
 }
});
test('Read-only transport has no signer/exchange API and rechecks permit on every page',async t=>{
 const peer=await httpsFixture();t.after(()=>peer.close());let permits=0;
 const config={canvasOrigin:peer.origin,ca:peer.ca,allowedPrivateAddresses:['127.0.0.1','::1'],beforeRead:async()=>++permits===1};
 const reader=createCanvasLtiServiceReader(config);assert.deepEqual(Object.keys(reader).sort(),['readLineItem','readMembership','readResults']);
 assert.throws(()=>createCanvasLtiServiceReader({...config,toolKey:{}}),/invalid_configuration/);
 assert.throws(()=>createCanvasLtiServiceReader({...config,beforeRead:undefined}),/invalid_configuration/);
 peer.setHandler((req,res)=>{const url=new URL(req.url,peer.origin),next=new URL(url);next.searchParams.set('page','2');json(res,[],200,{Link:`<${next.href}>; rel="next"`});});
 await assert.rejects(reader.readResults({token:{accessToken:'synthetic_bearer_00000001',scopes:[ltiReadScopes.results],expiresAtMs:Date.now()+60000},courseId:'11',lineItemId:'33',userId:'opaque:user'}),/dispatch_denied/);
 assert.equal(permits,2);assert.equal(peer.seen.length,1);
});
test('Capture freezes original query and receipt identity before asynchronous token lookup',async t=>{
 const f=await fixture(t),originalId=f.job.captureId,originalLease=f.job.leaseId;
 // Mutate the repository's caller-owned object during a later async permit.
 // The worker must continue using the original capture and provider resource.
 let once=false;
 const worker=createLtiCaptureWorker({organizationId:'org',producerRef:'producer',ca:f.peer.ca,allowedPrivateAddresses:['127.0.0.1','::1'],
  repository:{claim:async()=>f.job,permit:async(...args)=>{
   assert.equal(args[2],originalId);assert.equal(args[3],originalLease);
   if(!once){once=true;f.job.captureId=randomUUID();f.job.leaseId=randomUUID();f.job.definition.requirement.userId='foreign';}
   return true;
  },complete:async(...args)=>{assert.equal(args[2],originalId);assert.equal(args[3],originalLease);return true;},defer:async()=>{assert.fail('must complete original');}},
  tokenStore:{inspect:async()=>f.attempt,currentToken:async()=>f.token,permitRead:async()=>true}});
 assert.deepEqual(await worker.runOnce(),{state:'captured',captureId:originalId});
 assert.equal(new URL(f.peer.seen.at(-1).url,f.peer.origin).searchParams.get('user_id'),'opaque:user');
});
test('Attempt budget parks without releasing a bearer or making a provider call',async t=>{
 const f=await fixture(t,{jobChange:{attempts:9}});assert.equal((await f.worker.runOnce()).state,'parked');
 assert.equal(f.calls.inspect,0);assert.equal(f.calls.token,0);assert.equal(f.peer.seen.length,0);assert.equal(f.calls.deferred[0][4],'attempt_limit');
});
