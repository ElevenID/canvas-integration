// SPDX-License-Identifier: AGPL-3.0-only
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import pg from 'pg';
import {createLtiAssociationStore} from '../src/lti-association-store.mjs';
const port=Number(process.env.CANVAS_ASSOCIATION_TEST_PORT);
if(!Number.isInteger(port)||port<1)throw Error('use test_lti_association_store.py');
const admin=new pg.Pool({host:'127.0.0.1',port,user:'postgres',password:'synthetic-association-only',database:'postgres'});
const runtime=new pg.Pool({host:'127.0.0.1',port,user:'association_runtime',password:'synthetic-runtime-only',database:'postgres',max:8});
after(async()=>{await runtime.end();await admin.end();});
const configuration={registrationId:'10000000-0000-4000-8000-000000000001',sourceId:'source-one',
 sourceGrantId:'20000000-0000-4000-8000-000000000002',bindingId:'binding-one',sourceRevision:1,bindingRevision:1};
const wrappingKey=randomBytes(32),keyProvider={current:async()=>({id:'synthetic-key-one',key:wrappingKey}),byId:async id=>{
 assert.equal(id,'synthetic-key-one');return wrappingKey;
}};
const store=overrides=>createLtiAssociationStore({pool:runtime,keyProvider,configuration,...overrides});
async function fixture(expiresIn=120) {
 const proof={stateHash:randomBytes(32).toString('hex'),browserHash:randomBytes(32).toString('hex')},nonce=randomBytes(32).toString('base64url');
 const launchId=randomUUID(),token=randomBytes(32).toString('hex'),identityId=randomUUID();
 const versions=(await admin.query(`SELECT p.config_version::float8 AS p,r.version::float8 AS r FROM canvas_connector.platforms p
  JOIN canvas_connector.lti_registrations r ON r.platform_id=p.id AND r.organization_id=p.organization_id WHERE r.id=$1`,[configuration.registrationId])).rows[0];
 await admin.query('SELECT canvas_connector.begin_lti_launch($1,$2,$3,$4,$5,$6,$7)',
  [configuration.registrationId,versions.p,versions.r,proof.stateHash,proof.browserHash,nonce,launchId]);
 const now=Math.floor(Date.now()/1000),claims={issuer:'https://canvas.example',clientId:'client-one',deploymentId:'deployment-one',
  subject:'subject-'+identityId,nonce,issuedAt:now-1,expiresAt:now+expiresIn,notBefore:null,
  targetLinkUri:'https://connector.example/lti/resource',resourceLinkId:'resource-one',contextId:null,
  messageType:'LtiResourceLinkRequest',version:'1.3.0'};
 await admin.query('SELECT canvas_connector.stage_lti_launch($1,$2,$3::jsonb)',[proof.stateHash,token,JSON.stringify(claims)]);
 await admin.query('SELECT canvas_connector.confirm_lti_launch($1,$2,$3)',[proof.stateHash,proof.browserHash,token]);
 const observed=await admin.query('SELECT canvas_connector.observe_lti_provider_identity($1,$2,$3,$4) AS receipt',
  [configuration.registrationId,proof.stateHash,proof.browserHash,identityId]);
 assert.ok(observed.rows[0].receipt);return {proof,launchId,identityId};
}
const unavailable={message:'lti_association_store_unavailable'};
test('concurrent prepares and process restart retain one encrypted immutable intent',async()=>{
 const {proof,launchId}=await fixture(),attempts=await Promise.all(Array.from({length:8},()=>store().prepare(proof)));
 for(const attempt of attempts)assert.deepEqual(attempt,attempts[0]);
 assert.deepEqual(await store().current(proof),attempts[0]);
 const saved=(await admin.query('SELECT * FROM canvas_connector.lti_association_attempts WHERE launch_id=$1',[launchId])).rows;
 assert.equal(saved.length,1);const row=saved[0],code=Buffer.from(attempts[0].code,'base64url');
 assert.equal(code.length,32);assert.equal(row.code_hash,createHash('sha256').update(code).digest('hex'));
 assert.notDeepEqual(row.ciphertext,code);assert.equal(row.ciphertext.length,32);
 for(const key of ['user_id','application_id','subject_id','organization_id'])assert.equal(Object.hasOwn(row,key),false);
});
test('lookup does not mint an attempt, and browser proof cannot be substituted',async()=>{
 const {proof}=await fixture();assert.equal(await store().current(proof),null);
 await assert.rejects(store().prepare({...proof,browserHash:'0'.repeat(64)}),unavailable);
 await store().prepare(proof);await assert.rejects(store().current({...proof,stateHash:'0'.repeat(64)}),unavailable);
});
test('durable dispatch claim is granted once across concurrency and restart',async()=>{
 const {proof}=await fixture(),results=await Promise.all(Array.from({length:8},()=>store().claimDispatch(proof)));
 assert.equal(results.filter(r=>r.dispatchGranted).length,1);
 for(const r of results)assert.deepEqual(r.attempt,results[0].attempt);
 const restarted=await store().claimDispatch(proof);assert.equal(restarted.dispatchGranted,false);
 assert.deepEqual(restarted.attempt,results[0].attempt);
 await assert.rejects(admin.query('DELETE FROM canvas_connector.lti_association_dispatches WHERE challenge_id=$1',
  [restarted.attempt.challengeId]),/immutable/);
});
test('source grant and binding revisions cannot mutate original persisted intent',async()=>{
 const {proof}=await fixture();const original=await store().prepare(proof);
 for(const change of [{sourceRevision:2},{bindingRevision:2},{sourceGrantId:randomUUID()}])
  await assert.rejects(store({configuration:{...configuration,...change}}).prepare(proof),unavailable);
 assert.deepEqual(await store().current(proof),original);
});
test('database rejects edits and deletes even by owner; runtime cannot truncate',async()=>{
 const {proof}=await fixture(),a=await store().prepare(proof);
 await assert.rejects(admin.query('UPDATE canvas_connector.lti_association_attempts SET operation_id=$1 WHERE challenge_id=$2',[randomUUID(),a.challengeId]),/immutable/);
 await assert.rejects(admin.query('DELETE FROM canvas_connector.lti_association_attempts WHERE challenge_id=$1',[a.challengeId]),/immutable/);
 await assert.rejects(runtime.query('TRUNCATE canvas_connector.lti_association_attempts'),/permission denied/);
});
test('quarantined provider invalidates retained code and cannot mint another attempt',async()=>{
 const {proof,identityId}=await fixture();await store().prepare(proof);
 await admin.query("UPDATE canvas_connector.lti_provider_identities SET status='quarantined' WHERE id=$1",[identityId]);
 await assert.rejects(store().current(proof),unavailable);await assert.rejects(store().prepare(proof),unavailable);
});
test('wrong encryption key fails closed without replacing original attempt',async()=>{
 const {proof}=await fixture(),original=await store().prepare(proof);
 await assert.rejects(store({keyProvider:{...keyProvider,byId:async()=>Buffer.alloc(32)}}).current(proof),unavailable);
 assert.deepEqual(await store().current(proof),original);assert.notDeepEqual(wrappingKey,Buffer.alloc(32));
});
test('expiry during real database COMMIT preserves dispatch claim but never returns plaintext code',async()=>{
 const {proof,launchId}=await fixture(2);
 const delayed={connect:async()=>{
  const client=await runtime.connect();return {release:()=>client.release(),query:async(...args)=>{
   if(args[0]==='COMMIT')await new Promise(resolve=>setTimeout(resolve,2200));
   return client.query(...args);
  }};
 }};
 await assert.rejects(store({pool:delayed}).claimDispatch(proof),unavailable);
 const retained=(await admin.query(`SELECT a.challenge_id,d.challenge_id AS dispatched FROM canvas_connector.lti_association_attempts a
  JOIN canvas_connector.lti_association_dispatches d USING(challenge_id) WHERE a.launch_id=$1`,[launchId])).rows;
 assert.equal(retained.length,1);assert.equal(retained[0].challenge_id,retained[0].dispatched);
 await assert.rejects(store().claimDispatch(proof),unavailable);
});
test('registration change invalidates accepted launch and retained attempt',async()=>{
 const {proof}=await fixture();await store().prepare(proof);
 await admin.query('UPDATE canvas_connector.lti_registrations SET enabled=false WHERE id=$1',[configuration.registrationId]);
 try {await assert.rejects(store().current(proof),unavailable);await assert.rejects(store().prepare(proof),unavailable);}
 finally {await admin.query('UPDATE canvas_connector.lti_registrations SET enabled=true WHERE id=$1',[configuration.registrationId]);}
});
