// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createLtiCaptureScheduler,ltiScheduledCaptureId} from '../src/lti-capture-scheduler.mjs';
const schedule=()=>({organizationId:'org',producerRef:'producer',routeId:'route',configurationId:randomUUID(),expectedRevision:0,routeVersion:1,intervalMs:60000,enabled:true});
const result=s=>({configuration:{configurationId:s.configurationId,producerRef:s.producerRef,routeId:s.routeId,revision:1,routeVersion:1,intervalMs:60000,enabled:true,configuredAtMs:Date.now()},current:true,
 capture:{captureId:ltiScheduledCaptureId(s,1),configurationId:s.configurationId,routeId:s.routeId,routeVersion:1,revision:1,ordinal:1,enqueuedAtMs:Date.now()},enqueued:true,reason:null});
test('LTI scheduled capture UUID binds original scope/configuration/cursor without random replacement',()=>{
 const s=schedule(),id=ltiScheduledCaptureId(s,1);assert.match(id,/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
 assert.equal(ltiScheduledCaptureId({...s},1),id);
 for(const change of [{organizationId:'foreign'},{producerRef:'foreign'},{routeId:'other'},{configurationId:randomUUID()}])assert.notEqual(ltiScheduledCaptureId({...s,...change},1),id);
 assert.notEqual(ltiScheduledCaptureId(s,2),id);for(const ordinal of [0,-1,1.5,Number.MAX_SAFE_INTEGER])assert.throws(()=>ltiScheduledCaptureId(s,ordinal));
});
test('One scheduler call preserves original configuration and validates returned deterministic receipt',async()=>{
 const s=schedule(),response=result(s);let calls=0;
 const worker=createLtiCaptureScheduler({schedule:s,pool:{async query(sql,args){calls++;assert.match(sql,/tick_lti_capture_schedule/);assert.equal(args[3],s.configurationId);return {rows:[{result:response}]};}}});
 assert.deepEqual(await worker.runOnce(),response);assert.equal(calls,1);
});
test('Conflicting cursor/authority-like extra fields or impossible outcome fail closed',async()=>{
 const s=schedule();
 for(const mutate of [r=>r.capture.captureId=randomUUID(),r=>r.capture.ordinal=2,r=>r.configuration.revision=2,r=>r.approved=true,
  r=>r.reason='disabled',r=>r.current=false,r=>r.capture.verified=true]) {
  const r=result(s);mutate(r);const worker=createLtiCaptureScheduler({schedule:s,pool:{query:async()=>({rows:[{result:r}]})}});
  await assert.rejects(worker.runOnce(),/lti_capture_scheduler_unavailable/);
 }
});
test('Unknown SQL acknowledgement is not retried or replaced inside the scheduler',async()=>{
 let calls=0;const s=schedule(),worker=createLtiCaptureScheduler({schedule:s,pool:{async query(){calls++;throw Error('private unknown outcome');}}});
 await assert.rejects(worker.runOnce(),{message:'lti_capture_scheduler_unavailable'});assert.equal(calls,1);
});
