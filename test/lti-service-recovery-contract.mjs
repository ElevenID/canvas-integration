// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { createLtiToolKeyStore } from '../src/lti-tool-key-store.mjs';
import { createLtiServiceStore } from '../src/lti-service-store.mjs';
import { createLtiServiceRecoveryStore } from '../src/lti-service-recovery-store.mjs';
import { ltiServiceReadScopes } from '../src/lti-service-contract.mjs';

export async function ltiServiceRecoveryContract(pool,{keyProvider,ownerQuery}) {
 const organizationId='service-recovery-org',keys=createLtiToolKeyStore({pool,keyProvider}),store=createLtiServiceStore({pool,keyProvider});
 const recovery=createLtiServiceRecoveryStore(pool);
 async function setup() {
  const platformId='platform-'+randomUUID(),registrationId=randomUUID();
  await ownerQuery(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
   VALUES('${organizationId}','${platformId}','https://canvas.example.test',true);
   INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
   VALUES('${registrationId}','${organizationId}','${platformId}','client','deployment','hosted_global','production',
    'https://tool.example.test/lti/registrations/${registrationId}/resource',true);`);
  await keys.administer({organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',action:'provision',
   expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null});
  return {organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',
   expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1,scopes:[ltiServiceReadScopes.results]};
 }
 const handle=a=>({organizationId,operationId:a.operationId}),dispatch=a=>({...handle(a),dispatchId:a.dispatchId});
 const input=(a,action)=>({organizationId,platformId:a.platformId,registrationId:a.registrationId,attemptId:a.operationId,
  operationId:randomUUID(),actorId:'operator',action,expectedPhase:a.phase,expectedPlatformVersion:null,
  expectedRegistrationVersion:null,expectedKeyVersion:null,confirmationReference:null});
 const first=await store.prepare(await setup()),abandon=input(first,'abandon_prepared');
 await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_recovery_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN NEW.actor_id:='rewritten';RETURN NEW;END;$$;
  CREATE TRIGGER synthetic_recovery_rewrite BEFORE INSERT ON canvas_connector.lti_service_recovery_audit
   FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_recovery_rewrite();`);
 try {
  await assert.rejects(recovery.recover(abandon),/lti_service_recovery_unavailable/);
  assert.equal((await store.inspect(handle(first))).phase,'prepared');
 } finally {await ownerQuery('DROP TRIGGER synthetic_recovery_rewrite ON canvas_connector.lti_service_recovery_audit;DROP FUNCTION canvas_connector.synthetic_recovery_rewrite();');}
 const abandoned=await Promise.all(Array.from({length:4},()=>recovery.recover(abandon)));
 for(const item of abandoned)assert.deepEqual(item,abandoned[0]);assert.equal(abandoned[0].providerDisposition,'not_dispatched');
 assert.equal((await store.inspect(handle(first))).phase,'resolved');
 assert.equal(await store.begin({...handle(first),dispatchId:randomUUID()}),null);
 assert.equal(await recovery.recover({...abandon,actorId:'other'}),null);
 const receiptHandle={organizationId,platformId:first.platformId,registrationId:first.registrationId,attemptId:first.operationId,operationId:abandon.operationId};
 assert.deepEqual(await recovery.receipt(receiptHandle),abandoned[0]);assert.equal(await recovery.receipt({...receiptHandle,organizationId:'foreign'}),null);
 const command=await setup(),prepared=await store.prepare(command),unknown=await store.begin({...handle(prepared),dispatchId:randomUUID()});
 await store.uncertain(dispatch(unknown));
 const resolve={...input({...unknown,phase:'uncertain'},'resolve_unknown'),expectedPlatformVersion:2,expectedRegistrationVersion:2,
  expectedKeyVersion:2,confirmationReference:randomUUID()};
 assert.equal(await recovery.recover(resolve),null,'attestation alone cannot override enabled local configuration');
 await keys.administer({organizationId,platformId:unknown.platformId,registrationId:unknown.registrationId,operationId:randomUUID(),actorId:'operator',
  action:'deactivate',expectedPlatformVersion:null,expectedRegistrationVersion:null,expectedKeyVersion:1});
 await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${organizationId}' AND id='${unknown.platformId}';
  UPDATE canvas_connector.lti_registrations SET enabled=false WHERE id='${unknown.registrationId}';`);
 const resolved=await recovery.recover(resolve);assert.equal(resolved.providerDisposition,'operator_attested_external_disposition');
 assert.equal(await store.permitDispatch(dispatch(unknown)),false);
 const late={accessToken:'synthetic_late_inflight_service_token_00001',scopes:unknown.scopes};
 const retained=await store.stage(unknown,late,(unknown.issuedAt+30)*1000);
 assert.equal(retained.phase,'resolved');assert.notEqual(retained.tokenReference,null,'late in-flight credential retains encrypted custody without reopening authorization');
 assert.equal(await store.currentToken(handle(unknown)),null);assert.equal(await store.publish(dispatch(unknown)),null);
 assert.deepEqual(await recovery.recover(resolve),resolved,'original attestation receipt is unchanged by late custody');
 assert.equal(await store.prepare({...command,operationId:randomUUID()}),null,'resolution does not reenable disabled configuration');
 const knownPrepared=await store.prepare(await setup()),known=await store.begin({...handle(knownPrepared),dispatchId:randomUUID()});
 await store.stage(known,{accessToken:'synthetic_short_ttl_service_token_00002',scopes:known.scopes},(known.issuedAt+3)*1000);
 const original=await store.publish(dispatch(known));assert.notEqual(original,null);
 const retire=input({...known,phase:'published'},'retire_known');assert.equal(await recovery.recover(retire),null,'usable deadline alone never proves the provider TTL elapsed');
 const time=(await pool.query(`SELECT (extract(epoch FROM retire_after-clock_timestamp()))::float8 AS remaining,
  retire_after>expires_at AS conservative FROM canvas_connector.lti_service_tokens WHERE organization_id=$1 AND operation_id=$2::uuid`,[organizationId,known.operationId])).rows[0];
 assert.equal(time.conservative,true);assert.ok(time.remaining>0&&time.remaining<=3);
 await setTimeout(Math.ceil(time.remaining*1000)+30);
 const retired=await recovery.recover(retire);assert.equal(retired.providerDisposition,'elapsed_provider_ttl_after_custody');
 const historical=await store.inspect(handle(known));assert.equal(historical.phase,'resolved');assert.equal(historical.tokenReference,original.tokenReference);
 assert.deepEqual(historical.receipt,original);assert.deepEqual(await store.publish(dispatch(known)),original);
 assert.equal(await store.currentToken(handle(known)),null);
 await assert.rejects(pool.query('DELETE FROM canvas_connector.lti_service_recovery_audit WHERE organization_id=$1',[organizationId]));
 console.log('Actual PG LTI recovery immutable actor receipts/CAS/rollback/disabled-config external attestation/late encrypted custody/conservative TTL retirement PASS');
}
