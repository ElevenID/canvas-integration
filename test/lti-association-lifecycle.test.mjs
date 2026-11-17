// SPDX-License-Identifier: AGPL-3.0-only
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createLtiAssociationLifecycle} from '../src/lti-association-lifecycle.mjs';
const proof={stateHash:'a'.repeat(64),browserHash:'b'.repeat(64)};
function fixture(ttl=120000) {
 const a=Object.freeze({challengeId:'10000000-0000-4000-8000-000000000001',bindingId:'binding-one',code:'synthetic-code',
  body:Object.freeze({operation_id:'20000000-0000-4000-8000-000000000002',code_hash:'c'.repeat(64),expires_at_ms:Date.now()+ttl})});
 const result={operation_id:a.body.operation_id,challenge_id:a.challengeId,action:'create',revision:1,phase:'pending'},calls=[];
 let dispatched=false,current=a,record={challenge_id:a.challengeId,binding_id:a.bindingId,expires_at_ms:a.body.expires_at_ms,
  current:true,expired:false,revision:1,phase:'pending'},write=async()=>result;
 const store={claimDispatch:async p=>{assert.deepEqual(p,proof);const first=!dispatched;dispatched=true;return {attempt:a,dispatchGranted:first};},
  current:async p=>{assert.deepEqual(p,proof);return current;}};
 const gateway={execute:async value=>{calls.push(value);if(value.action==='create')return write();
  if(value.action==='receipt')return {kind:'receipt',receipt:result};return {kind:'current',record};}};
 return {lifecycle:createLtiAssociationLifecycle({store,gateway}),calls,a,
  setCurrent:value=>{current=value;},setRecord:value=>{record={...record,...value};},setWrite:value=>{write=value;}};
}
test('one committed dispatch claim writes once; subsequent starts and recovery read original receipt then current',async()=>{
 const f=fixture(),first=await f.lifecycle.start(proof);
 assert.equal(first.code,f.a.code);assert.deepEqual(f.calls.map(c=>c.action),['create','inspect']);
 assert.deepEqual(await f.lifecycle.start(proof),first);assert.deepEqual(await f.lifecycle.recover(proof),first);
 assert.deepEqual(f.calls.map(c=>c.action),['create','inspect','receipt','inspect','receipt','inspect']);
 assert.deepEqual(f.calls[2].expectedReceipt,{action:'create',revision:1});
});
test('lost write reply never returns code or retries the mutation; recovery looks up original ID',async()=>{
 const f=fixture();f.setWrite(async()=>{throw Error('synthetic lost reply');});
 await assert.rejects(f.lifecycle.start(proof),{message:'lti_association_unavailable'});
 assert.equal(f.calls.length,1);assert.equal((await f.lifecycle.start(proof)).phase,'pending');
 assert.deepEqual(f.calls.map(c=>c.action),['create','receipt','inspect']);
 assert.equal(f.calls[1].body.operation_id,f.a.body.operation_id);
});
test('history cannot substitute for expired, revoked, mismatched or changed current state',async()=>{
 for(const change of [{current:false},{expired:true},{expires_at_ms:1},{binding_id:'other'},{challenge_id:'other'},{revision:2}]) {
  const f=fixture();f.setRecord(change);await assert.rejects(f.lifecycle.start(proof),{message:'lti_association_unavailable'});
 }
 const f=fixture();f.setWrite(async()=>{f.setCurrent(null);return {operation_id:f.a.body.operation_id,
  challenge_id:f.a.challengeId,action:'create',revision:1,phase:'pending'};});
 await assert.rejects(f.lifecycle.start(proof),{message:'lti_association_unavailable'});
});
test('confirmed or terminal states never return raw consent code',async()=>{
 for(const phase of ['confirmed','denied','abandoned','expired']) {
  const f=fixture();f.setRecord({phase,revision:2,current:phase==='confirmed',expired:true});
  assert.deepEqual(await f.lifecycle.start(proof),{challengeId:f.a.challengeId,phase});
 }
});
test('a delayed response crossing expiry cannot return the pending consent code',async()=>{
 const f=fixture(50);f.setWrite(async()=>{
  await new Promise(resolve=>setTimeout(resolve,100));
  return {operation_id:f.a.body.operation_id,challenge_id:f.a.challengeId,action:'create',revision:1,phase:'pending'};
 });
 await assert.rejects(f.lifecycle.start(proof),{message:'lti_association_unavailable'});
 assert.deepEqual(f.calls.map(c=>c.action),['create','inspect']);
});
test('proof snapshots reject authority fields and getters before persistence or network access',async()=>{
 const f=fixture();let getterCalls=0;
 for(const invalid of [{...proof,organizationId:'other'},{get stateHash(){getterCalls++;return proof.stateHash;},browserHash:proof.browserHash},
  {...proof,browserHash:'wrong'}])await assert.rejects(f.lifecycle.start(invalid));
 assert.equal(getterCalls,0);assert.equal(f.calls.length,0);
});
