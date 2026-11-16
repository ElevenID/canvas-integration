// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCaptureRoute} from '../src/capture-route-contract.mjs';
const now=1794844800000,origin='https://canvas.example.test';
const input={producerRef:'source-one',platformId:'platform-one',bindingId:'binding-one',bindingRevision:3,
  requirement:{factType:'canvas.assignment_score',courseId:'11',userId:'22',activityId:'33'},
  claimNames:['score','completed'],effectiveTimePolicy:'require_provider_time'};
const snapshot={found:true,snapshot_at_ms:now,record:{id:'binding-one',revision:3,active:true,source_id:'source-one',provider:'canvas',
  fact_type:'canvas.assignment_score',resource_scope:{canvas_origin:origin,course_id:'11',user_id:'22',activity_id:'33'},
  application_status:'pending',application_revision:1794844800000000,application_expires_at_ms:now+60000,
  application_id:'private-application',subject_id:'private-subject',claim_rules:{
    completed:{kind:'boolean',required:true,nullable:false},score:{kind:'number',required:false,nullable:true,minimum:0,maximum:100},
    effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}}}};
const clone=value=>structuredClone(value);
const prepare=(value=input,record=snapshot)=>prepareCaptureRoute(value,record,{platformOrigin:origin,nowMs:now});
const denied=fn=>assert.throws(fn,{message:'connector_capture_route_unavailable'});
test('capture configuration uses exact Core origin/resources and discards identity and authority metadata',()=>{
  const result=prepare();assert.deepEqual(result,{...input,claimNames:['completed','score']});
  assert.ok(Object.isFrozen(result));assert.ok(Object.isFrozen(result.requirement));assert.ok(Object.isFrozen(result.claimNames));
  assert.ok(!JSON.stringify(result).includes('private-'));assert.ok(!Object.hasOwn(result,'application_revision'));
  const source=clone(input),record=clone(snapshot),result2=prepare(source,record);
  source.requirement.userId='999';record.record.subject_id='other';assert.equal(result2.requirement.userId,'22');
});
test('canonical uint64 Canvas IDs remain strings for every supported fact type',()=>{
  for(const factType of ['canvas.assignment_score','canvas.quiz_score','canvas.module_completion','canvas.course_completion']) {
    const value=clone(input),record=clone(snapshot);value.requirement={factType,courseId:'18446744073709551615',userId:'22'};
    record.record.fact_type=factType;record.record.resource_scope={canvas_origin:origin,course_id:'18446744073709551615',user_id:'22'};
    if(factType.includes('_score')) {value.requirement.activityId='33';record.record.resource_scope.activity_id='33';}
    if(factType==='canvas.module_completion') {value.requirement.moduleId='44';record.record.resource_scope.module_id='44';}
    assert.equal(prepare(value,record).requirement.courseId,'18446744073709551615');
  }
});
test('foreign origin, source, learner, resource, stale revision and closed or expired application deny configuration',()=>{
  for(const mutate of [r=>r.id='other',r=>r.revision=4,r=>r.active=false,r=>r.source_id='other',r=>r.provider='other',
    r=>r.fact_type='canvas.quiz_score',r=>r.resource_scope.canvas_origin='https://other-canvas.example.test',
    r=>delete r.resource_scope.canvas_origin,r=>r.resource_scope.user_id='different-learner',r=>r.resource_scope.course_id='12',
    r=>r.resource_scope.extra='unapproved',r=>r.application_status='approved',r=>r.application_expires_at_ms=now,
    r=>r.application_revision=0]) {
    const record=clone(snapshot);mutate(record.record);denied(()=>prepare(input,record));
  }
  for(const value of [{...snapshot,found:false},{...snapshot,snapshot_at_ms:now-30001},
    {...snapshot,snapshot_at_ms:now+30001},{...snapshot,organization_id:'forged'}, {...snapshot,record:null}]) denied(()=>prepare(input,value));
});
test('mapping rejects unsafe IDs, authority input, duplicate/unknown assertions and unsupported query options',()=>{
  for(const mutate of [v=>v.organizationId='forged',v=>v.subjectId='forged',v=>v.verification={status:'VERIFIED'},
    v=>v.bindingRevision=9007199254740992,v=>v.requirement.userId=22,v=>v.requirement.courseId='01',
    v=>v.requirement.url='https://other.test',v=>v.requirement.courseId='18446744073709551616',
    v=>v.claimNames=['score','score'],v=>v.claimNames=['verified'],v=>v.claimNames=[],
    v=>v.effectiveTimePolicy='use_now',v=>v.producerRef='../source']) {
    const value=clone(input);mutate(value);denied(()=>prepare(value));
  }
  const getter={...input};Object.defineProperty(getter,'requirement',{get(){throw new Error('must not execute');}});denied(()=>prepare(getter));
});
test('every selected claim must be approved with its real nullable/type contract and mandatory time provenance',()=>{
  for(const mutate of [r=>delete r.score,r=>r.score.kind='text',r=>r.score.nullable=false,r=>r.score.minimum=Infinity,
    r=>r.score.maximum=-1,r=>r.score.extra=true,r=>r.extra={kind:'boolean',required:true,nullable:false},
    r=>delete r.effective_time_source,r=>r.effective_time_source.required=false,r=>r.effective_time_source.nullable=true,
    r=>r.effective_time_source.max_bytes=15,r=>r.effective_time_source.kind='boolean']) {
    const record=clone(snapshot);mutate(record.record.claim_rules);denied(()=>prepare(input,record));
  }
  const record=clone(snapshot);record.record.claim_rules.unused={kind:'boolean',required:false,nullable:false};assert.ok(prepare(input,record));
});
test('browser execution and noncanonical platform origins are denied without authority fallback',()=>{
  globalThis.window={};try{denied(()=>prepare());}finally{delete globalThis.window;}
  for(const platformOrigin of ['http://canvas.example.test',origin+'/',origin+'/path','https://user:secret@canvas.example.test'])
    denied(()=>prepareCaptureRoute(input,snapshot,{platformOrigin,nowMs:now}));
});
test('a slow connector clock cannot make an application already expired at the Gateway snapshot eligible',()=>{
  const record=clone(snapshot);record.snapshot_at_ms=now+30000;record.record.application_expires_at_ms=now+29999;
  denied(()=>prepare(input,record));record.record.application_expires_at_ms=now+30001;assert.ok(prepare(input,record));
});
