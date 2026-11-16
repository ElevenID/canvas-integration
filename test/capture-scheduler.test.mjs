// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {prepareCaptureSchedule,createCaptureScheduler,preflightCaptureScheduler} from '../src/capture-scheduler.mjs';
const schedule={organizationId:'org',producerRef:'producer',routeId:'route',configurationId:'10000000-0000-4000-8000-000000000001',expectedRevision:0,routeVersion:2,intervalMs:60000,enabled:true};
const configuration={configurationId:schedule.configurationId,routeId:'route',producerRef:'producer',revision:1,routeVersion:2,intervalMs:60000,enabled:true,configuredAtMs:1794860000000};
const captureId='schedule_'+createHash('sha256').update(['canvas-rest-capture-v1','org','producer','route',schedule.configurationId,'1'].join('\n')).digest('hex');
const capture={captureId,configurationId:schedule.configurationId,routeId:'route',routeVersion:2,revision:1,ordinal:1,enqueuedAtMs:1794860000001};
const result={configuration,current:true,capture,enqueued:true,reason:null};
const denied={message:'connector_capture_scheduler_unavailable'};
test('private schedule intent is bounded, immutable and contains no Core authority or credentials',()=>{
 assert.deepEqual(prepareCaptureSchedule(schedule),schedule);assert.ok(Object.isFrozen(prepareCaptureSchedule(schedule)));
 for(const change of [v=>v.organizationId='../other',v=>v.intervalMs=999,v=>v.intervalMs=86400001,v=>v.expectedRevision=-1,
  v=>v.expectedRevision=Number.MAX_SAFE_INTEGER,v=>v.routeVersion=0,v=>v.enabled='true',v=>v.configurationId='invalid',
  v=>v.apiKey='secret',v=>v.applicationId='forbidden',v=>v.authority={verified:true}]) {
  const value=structuredClone(schedule);change(value);assert.throws(()=>prepareCaptureSchedule(value),denied);
 }
});
test('one tick uses bound server configuration and validates its deterministic original capture receipt',async()=>{
 const calls=[],mutable=structuredClone(schedule);
 const scheduler=createCaptureScheduler({pool:{query:async(sql,values)=>{calls.push({sql,values});return{rows:[{result}]};}},schedule:mutable});
 mutable.routeId='mutated';const value=await scheduler.runOnce();assert.deepEqual(value,result);assert.ok(Object.isFrozen(value.capture));
 assert.equal(calls.length,1);assert.deepEqual(calls[0].values,['org','producer','route',schedule.configurationId,0,2,60000,true]);
 assert.ok(!calls[0].sql.includes(schedule.configurationId));
});
test('corrupted scope, identity, cursor or authority fields fail closed',async()=>{
 let response=result;
 const scheduler=createCaptureScheduler({pool:{query:async()=>({rows:[{result:response}]})},schedule});
 for(const change of [v=>v.configuration.routeId='other',v=>v.configuration.revision=2,v=>v.capture.captureId='schedule_'+'0'.repeat(64),
  v=>v.capture.ordinal=Number.MAX_SAFE_INTEGER,v=>v.capture.applicationId='forbidden',v=>v.configuration.apiKey='forbidden',
  v=>v.current=false,v=>v.enqueued=false,v=>v.reason='verified']) {
  response=structuredClone(result);change(response);await assert.rejects(scheduler.runOnce(),denied);
 }
});
test('superseded configuration remains history and performs no new write retry',async()=>{
 let response={configuration,current:false,capture:null,enqueued:false,reason:'superseded'},calls=0;
 const scheduler=createCaptureScheduler({pool:{query:async()=>{calls++;return{rows:[{result:response}]};}},schedule});
 assert.equal((await scheduler.runOnce()).current,false);assert.equal(calls,1);
 response=null;assert.equal(await scheduler.runOnce(),null);assert.equal(calls,2);
});
test('unknown commits are redacted and no replacement adapter or implicit retry is introduced',async()=>{
 let calls=0;const pool={query:async()=>{calls++;throw Error('private database detail');}};
 await assert.rejects(createCaptureScheduler({pool,schedule}).runOnce(),denied);assert.equal(calls,1);
 assert.throws(()=>createCaptureScheduler({pool,schedule,transport:()=>{}}));
 await assert.rejects(preflightCaptureScheduler(pool),denied);
});
