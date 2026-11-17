// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createLtiToolKeyStore } from '../src/lti-tool-key-store.mjs';
import { createLtiServiceStore } from '../src/lti-service-store.mjs';
import { ltiServiceReadScopes as scopes } from '../src/lti-service-contract.mjs';

export async function ltiServiceStoreContract(pool,{keyProvider,ownerQuery}) {
 const organizationId='lti-service-org',platformId='lti-service-platform',registrationId=randomUUID();
 await ownerQuery(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
  VALUES('${organizationId}','${platformId}','https://canvas.example.test',true);
  INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
  VALUES('${registrationId}','${organizationId}','${platformId}','service-client','deployment','hosted_global','production',
   'https://tool.example.test/lti/registrations/${registrationId}/resource',true);`);
 const keys=createLtiToolKeyStore({pool,keyProvider}),store=createLtiServiceStore({pool,keyProvider});
 await keys.administer({organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',action:'provision',
  expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null});
 const command=()=>({organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',
  expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1,scopes:[scopes.results,scopes.lineitems]});
 const handle=a=>({organizationId,operationId:a.operationId}),dispatch=a=>({...handle(a),dispatchId:a.dispatchId});
 const fresh=command(),attempts=await Promise.all(Array.from({length:4},()=>store.prepare(fresh)));
 for(const a of attempts)assert.deepEqual(a,attempts[0]);const prepared=attempts[0];assert.equal(prepared.phase,'prepared');
 assert.equal(await store.prepare({...fresh,actorId:'other'}),null);assert.equal(await store.prepare(command()),null,'unresolved attempt blocks replacement');
 assert.equal(await store.inspect({...handle(prepared),organizationId:'foreign'}),null);
 const begins=await Promise.all(Array.from({length:4},()=>store.begin({...handle(prepared),dispatchId:randomUUID()})));
 assert.equal(begins.filter(Boolean).length,1);const a=begins.find(Boolean);
 assert.equal(a.phase,'exchanging');assert.equal(a.expiresAt,a.issuedAt+120);assert.equal(a.operationId,prepared.operationId);
 assert.equal(await store.begin(dispatch(a)),null,'readback never becomes a second dispatch permission');
 assert.equal(await store.permitDispatch(dispatch(a)),true);
 assert.equal(await store.permitDispatch({...dispatch(a),dispatchId:randomUUID()}),false);
 const bundle={accessToken:'synthetic_lti_service_token_original_00001',scopes:[scopes.results]},expiry=(a.issuedAt+3600)*1000;
 await assert.rejects(store.stage(a,{...bundle,scopes:[scopes.memberships]},expiry),/lti_service_store_unavailable/);
 await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_service_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN NEW.wrapping_key_id:='rewritten';RETURN NEW;END;$$;
  CREATE TRIGGER synthetic_service_rewrite BEFORE INSERT ON canvas_connector.lti_service_tokens
   FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_service_rewrite();`);
 try {
  await assert.rejects(store.stage(a,bundle,expiry),/lti_service_store_unavailable/);
  assert.equal((await store.inspect(handle(a))).phase,'exchanging');
  assert.equal((await pool.query('SELECT count(*)::float8 AS count FROM canvas_connector.lti_service_tokens WHERE organization_id=$1',[organizationId])).rows[0].count,0);
 } finally {await ownerQuery('DROP TRIGGER synthetic_service_rewrite ON canvas_connector.lti_service_tokens;DROP FUNCTION canvas_connector.synthetic_service_rewrite();');}
 const changing={...bundle};let mutated=false;
 const snapshotStore=createLtiServiceStore({keyProvider,pool:{async query(sql,values){
  const result=await pool.query(sql,values);
  if(!mutated&&sql.includes('SELECT (SELECT canvas_connector.lti_service_attempt_view')){mutated=true;changing.accessToken='invalid\nchanged';}
  return result;
 }}});
 const staged=await Promise.all([snapshotStore.stage(a,changing,expiry),...Array.from({length:3},()=>store.stage(a,bundle,expiry))]);
 assert.equal(mutated,true,'caller mutation happened while the original durable lookup was pending');
 for(const item of staged)assert.deepEqual(item,staged[0]);assert.equal(staged[0].phase,'staged');
 const readHandle={...handle(a),tokenReference:staged[0].tokenReference};
 assert.equal(await store.permitRead(readHandle),false,'staged token is not read permission');
 assert.equal(await store.permitDispatch(dispatch(a)),false);
 assert.equal(await store.stage(a,{...bundle,accessToken:'synthetic_changed_lti_token_00002'},expiry),null,'changed plaintext is not an original-input replay');
 const receipt=await store.publish(dispatch(a));assert.equal(receipt.tokenReference,staged[0].tokenReference);assert.equal(Object.hasOwn(receipt,'accessToken'),false);
 assert.deepEqual(await store.publish(dispatch(a)),receipt);assert.deepEqual(await store.currentToken(handle(a)),{...bundle,expiresAtMs:expiry});
 assert.equal(await store.permitRead(readHandle),true);
 assert.equal(await store.permitRead({...readHandle,organizationId:'foreign'}),false);
 assert.equal(await store.permitRead({...readHandle,operationId:randomUUID()}),false);
 assert.equal(await store.permitRead({...readHandle,tokenReference:randomUUID()}),false);
 const storage=(await pool.query('SELECT ciphertext FROM canvas_connector.lti_service_tokens WHERE organization_id=$1',[organizationId])).rows;
 assert.equal(storage.length,1);assert.equal(storage[0].ciphertext.includes(Buffer.from(bundle.accessToken)),false);
 const tampered=createLtiServiceStore({keyProvider,pool:{async query(sql,values){
  const result=await pool.query(sql,values);
  if(sql.includes('SELECT (SELECT canvas_connector.lti_service_attempt_view'))return{rows:result.rows.map(row=>({result:{...row.result,canvasOrigin:'https://foreign.example.test'}}))};
  return result;
 }}});
 await assert.rejects(tampered.currentToken(handle(a)),/lti_service_store_unavailable/);
 const realNow=Date.now;let clock=realNow(),currentReads=0;
 const lateExpiry=createLtiServiceStore({keyProvider,pool:{async query(sql,values){
  const result=await pool.query(sql,values);
  if(sql.includes("a.phase='published'")&&++currentReads===2)clock=expiry+1;
  return result;
 }}});
 Date.now=()=>clock;
 try {assert.equal(await lateExpiry.currentToken(handle(a)),null,'expiry during final durable recheck never releases an expired credential');}
 finally {Date.now=realNow;}
 await assert.rejects(pool.query('UPDATE canvas_connector.lti_service_tokens SET ciphertext=$1 WHERE organization_id=$2',[Buffer.alloc(32),organizationId]));
 await assert.rejects(pool.query('DELETE FROM canvas_connector.lti_service_attempts WHERE organization_id=$1',[organizationId]));
 const lost=(sqlFragment)=>createLtiServiceStore({keyProvider,pool:{async query(sql,values){
  const result=await pool.query(sql,values);if(sql.includes(sqlFragment))throw Error('synthetic lost committed reply');return result;
 }}});
 const second=await store.prepare(command()),lostBegin=lost('SELECT canvas_connector.begin_lti_service_exchange');
 const secondHandle={...handle(second),dispatchId:randomUUID()};
 await assert.rejects(lostBegin.begin(secondHandle),/lti_service_store_unavailable/);
 assert.equal(await store.begin(secondHandle),null);assert.equal(await store.uncertain(secondHandle),true);
 assert.equal((await store.prepare({...fresh,operationId:second.operationId})).phase,'uncertain');
 assert.equal(await store.prepare(command()),null,'unknown provider outcome cannot be silently superseded');
 const uncertain=await store.inspect(handle(second));
 await assert.rejects(lost('SELECT canvas_connector.stage_lti_service_token').stage(uncertain,bundle,(uncertain.issuedAt+3600)*1000),/lti_service_store_unavailable/);
 const reconciled=await store.stage(uncertain,bundle,(uncertain.issuedAt+3600)*1000);assert.equal(reconciled.phase,'staged');
 await assert.rejects(lost('SELECT canvas_connector.publish_lti_service_token').publish(secondHandle),/lti_service_store_unavailable/);
 const original=await store.publish(secondHandle);assert.equal(original.tokenReference,reconciled.tokenReference);
 await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_service_deadline() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN NEW.prepare_expires_at:=clock_timestamp()+interval '1 second';RETURN NEW;END;$$;
  CREATE TRIGGER synthetic_service_deadline BEFORE INSERT ON canvas_connector.lti_service_attempts
   FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_service_deadline();`);
 let expiring;
 try {expiring=await store.prepare(command());}
 finally {await ownerQuery('DROP TRIGGER synthetic_service_deadline ON canvas_connector.lti_service_attempts;DROP FUNCTION canvas_connector.synthetic_service_deadline();');}
 await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_service_delay() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN IF NEW.phase='exchanging' THEN PERFORM pg_sleep(1.3);END IF;RETURN NEW;END;$$;
  CREATE TRIGGER zz_synthetic_service_delay BEFORE UPDATE ON canvas_connector.lti_service_attempts
   FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_service_delay();`);
 try {
  await assert.rejects(store.begin({...handle(expiring),dispatchId:randomUUID()}),/lti_service_store_unavailable/,
   'deadline crossed during the admission write must roll back the dispatch claim');
  const unchanged=await store.inspect(handle(expiring));assert.equal(unchanged.phase,'prepared');assert.equal(unchanged.dispatchId,null);
 } finally {await ownerQuery('DROP TRIGGER zz_synthetic_service_delay ON canvas_connector.lti_service_attempts;DROP FUNCTION canvas_connector.synthetic_service_delay();');}
 // Material read across a Bao delay must not survive a platform disable.
 const delayed=createLtiServiceStore({pool,keyProvider:{current:keyProvider.current,async byId(id){
  await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${organizationId}' AND id='${platformId}';`);
  return keyProvider.byId(id);
 }}});
 assert.equal(await delayed.currentToken(handle(a)),null);
 assert.equal(await store.currentToken(handle(second)),null);
 assert.equal(await store.permitRead(readHandle),false,'disabled platform invalidates previously published read permission');
 assert.deepEqual(await store.publish(secondHandle),original,'historical receipt readback is not current token authority');
 console.log('LTI service actual PG/OpenBao attempt identity/single dispatcher/ciphertext stage/CAS/unknown replies/digests/current fences PASS');
}
