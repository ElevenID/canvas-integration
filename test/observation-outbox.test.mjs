// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createObservationOutbox,createObservationDeliveryWorker} from '../src/observation-outbox.mjs';
import {encodeExternalObservation,ObservationSubmissionError} from '../src/observation-submit.mjs';
const base={binding_id:'binding-one',binding_revision:1,observation_id:'observation-one',sequence:1,
 observed_at_ms:1794804000000,effective_at_ms:1794803999000,claims:{completed:false}};
const job=()=>({...base,organizationId:'org-one',producerRef:'producer-one',body:encodeExternalObservation(base),
 phase:'leased',attempts:1,lease_id:'10000000-0000-4000-8000-000000000001'});
function fixture({item=job(),submit=async()=>({receipt_id:'receipt-one',replayed:false}),ack=async()=>true}={}) {
 const calls={submit:[],ack:[],defer:[]};
 const repository={prepareNext:async()=>false,claim:async()=>item,
  acknowledge:async(...args)=>{calls.ack.push(args);return ack(...args);},
  defer:async(...args)=>{calls.defer.push(args);return true;}};
 const worker=createObservationDeliveryWorker({organizationId:'org-one',producerRef:'producer-one',repository,
  submitter:{submit:async body=>{calls.submit.push(body);return submit(body);}}});return {calls,repository,worker};
}
test('Malformed or authority-bearing receipt never acknowledges durable delivery',async()=>{
 for(const receipt of [null,{}, {receipt_id:'one',replayed:false,verified:true},{receipt_id:'one',replayed:'false'}]) {
  const f=fixture({submit:async()=>receipt});assert.equal((await f.worker.runOnce()).state,'retry_scheduled');
  assert.equal(f.calls.ack.length,0);assert.equal(f.calls.defer[0][4],'submission_outcome_unknown');
 }
});
test('Wrong organization, key slot or unclaimed row never reaches submission',async()=>{
 for(const change of [{organizationId:'foreign'},{producerRef:'foreign'},{phase:'pending'},{lease_id:'invalid'}]) {
  const f=fixture({item:{...job(),...change}});assert.equal((await f.worker.runOnce()).state,'reconciliation_required');assert.equal(f.calls.submit.length,0);
 }
});
test('Noncanonical persisted body is parked without changing it or opening network',async()=>{
 const f=fixture({item:{...job(),body:encodeExternalObservation(base)+' '}});
 assert.equal((await f.worker.runOnce()).state,'parked');assert.equal(f.calls.submit.length,0);
 assert.equal(f.calls.defer[0][4],'invalid_stored_observation');
});
test('Rate limiting retains delivery for backoff; denied authority parks it',async()=>{
 for(const [status,state] of [[429,'retry_scheduled'],[403,'parked'],[409,'parked']]) {
  const f=fixture({submit:async()=>{throw new ObservationSubmissionError('submission_rejected',status);}});
  assert.equal((await f.worker.runOnce()).state,state);assert.equal(f.calls.ack.length,0);
  assert.equal(f.calls.defer[0][5],status);assert.equal(f.calls.submit.length,1);
 }
});
test('Unknown local receipt commit does not schedule another send',async()=>{
 const f=fixture({ack:async()=>{throw Error('sensitive synthetic database failure');}});
 assert.equal((await f.worker.runOnce()).state,'reconciliation_required');assert.equal(f.calls.submit.length,1);assert.equal(f.calls.defer.length,0);
});
test('Lost lease cannot report acknowledged delivery',async()=>{
 const f=fixture({ack:async()=>false});assert.equal((await f.worker.runOnce()).state,'reconciliation_required');assert.equal(f.calls.defer.length,0);
});
test('Invalid capture is rejected before database allocation',async()=>{
 let calls=0;const repo=createObservationOutbox({query:async()=>{calls++;throw Error('unreachable');}});
 const {sequence,...capture}=base;
 for(const input of [{...capture,sequence:5},{...capture,claims:{verified:true}},{...capture,effective_at_ms:0}])
  await assert.rejects(()=>repo.enqueue('org-one','producer-one',input),/connector_outbox_unavailable/);
 assert.equal(calls,0);
});
test('Database failure before claim opens no transport',async()=>{
 const f=fixture();f.repository.prepareNext=async()=>{throw Error('sensitive');};
 assert.deepEqual(await f.worker.runOnce(),{state:'storage_unavailable'});assert.equal(f.calls.submit.length,0);
});
test('Outbox export is denied under browser condition',async()=>{
 await assert.rejects(promisify(execFile)(process.execPath,['--conditions=browser','--input-type=module','-e',
  "await import('@elevenid/canvas-integration/observation-outbox')"]),e=>{assert.match(e.stderr,/server-only/);return true;});
});
