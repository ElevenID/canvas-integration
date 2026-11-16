// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {projectCanvasRestCapture,createCanvasRestCaptureWorker} from '../src/rest-capture.mjs';
const job=()=>({organizationId:'org-one',producerRef:'producer-one',capture_id:'capture-one',platform_id:'platform-one',
 binding_id:'binding-one',binding_revision:3,canvas_origin:'https://canvas.example',
 requirement:{factType:'canvas.course_completion',courseId:'17',userId:'29'},claim_names:['completed','requirement_count'],effective_time_policy:'require_provider_time',
 phase:'leased',lease_id:'10000000-0000-4000-8000-000000000001',attempts:1,capabilities:['course_completion'],
 scopes:['url:GET|/api/v1/courses/:course_id/users/:user_id/progress'],access_token_ref:'opaque-ref'});
const observation=()=>({schema:'elevenid.canvas-rest-observation/v1',source:'canvas_rest',fact_type:'canvas.course_completion',canvas_origin:'https://canvas.example',
 scope:{course_id:'17',user_id:'29'},assertion:{completed:false,score:null,score_maximum:null,score_percent:null,provider_state:null,requirement_count:3,requirement_completed_count:0},
 source_payload:{submission_body:'must-not-forward'},verification_method:'CANVAS_OAUTH_API_READ',observed_at:'2026-11-15T00:00:01.000Z',effective_at:null});
test('Unknown provider time fails closed without explicit policy opt-in',()=>{
 assert.throws(()=>projectCanvasRestCapture(job(),observation()),/connector_capture_unavailable/);
 const result=projectCanvasRestCapture({...job(),effective_time_policy:'as_of_read'},observation());
 assert.equal(result.observedAtMs,result.effectiveAtMs);assert.deepEqual(result.claims,{completed:false,requirement_count:3,effective_time_source:'observation_read'});
 assert.equal(JSON.stringify(result).includes('submission_body'),false);
});
test('Provider time keeps original provenance and never grants verified status',()=>{
 const result=projectCanvasRestCapture(job(),{...observation(),effective_at:'2026-11-14T00:00:00.000Z'});
 assert.equal(result.effectiveAtMs,Date.parse('2026-11-14T00:00:00.000Z'));assert.equal(result.claims.effective_time_source,'provider_event');
 assert.equal(Object.hasOwn(result.claims,'verified'),false);
});
for(const [name,change] of [['scope',x=>({...x,scope:{course_id:'17',user_id:'30'}})],['origin',x=>({...x,canvas_origin:'https://other.example'})],
 ['fact',x=>({...x,fact_type:'canvas.module_completion'})],['authority',x=>({...x,verified:true})],
 ['future-time',x=>({...x,effective_at:'2026-11-16T00:00:00.000Z'})],['coerced-completion',x=>({...x,assertion:{...x.assertion,completed:'false'}})],
 ['extra-claim',x=>({...x,assertion:{...x.assertion,approved:true}})]])test('Projection rejects '+name,()=>{
 assert.throws(()=>projectCanvasRestCapture({...job(),effective_time_policy:'as_of_read'},change(observation())),/connector_capture_unavailable/);
});
test('Selected claim list cannot introduce authority or duplicate provenance',()=>{
 for(const names of [['verified'],['effective_time_source'],['completed','completed']])
  assert.throws(()=>projectCanvasRestCapture({...job(),claim_names:names,effective_time_policy:'as_of_read'},observation()),/connector_capture_unavailable/);
});
test('Wrong tenant/slot or missing capability is rejected before vault access',async()=>{
 let vaultReads=0;
 for(const changed of [{organizationId:'foreign'},{producerRef:'foreign'},{capabilities:[]},{scopes:[]}]) {
  const repository={claim:async()=>({...job(),...changed}),complete:async()=>{throw Error('must not complete');},defer:async()=>true};
  const worker=createCanvasRestCaptureWorker({repository,secretVault:{get:async()=>{vaultReads++;throw Error('must not read');}},organizationId:'org-one',producerRef:'producer-one'});
  await worker.runOnce();
 }assert.equal(vaultReads,0);
});
test('Unknown storage claim opens no provider work',async()=>{
 let reads=0;const worker=createCanvasRestCaptureWorker({repository:{claim:async()=>{throw Error('sensitive');},complete:async()=>true,defer:async()=>true},
 secretVault:{get:async()=>{reads++;}},organizationId:'org-one',producerRef:'producer-one'});
 assert.deepEqual(await worker.runOnce(),{state:'storage_unavailable'});assert.equal(reads,0);
});
test('Browser condition denies capture module',async()=>{
 await assert.rejects(promisify(execFile)(process.execPath,['--conditions=browser','--input-type=module','-e',"await import('@elevenid/canvas-integration/rest-capture')"]),e=>{assert.match(e.stderr,/server-only/);return true;});
});
