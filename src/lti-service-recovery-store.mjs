// SPDX-License-Identifier: AGPL-3.0-only
import { ltiId,ltiUuid,ltiVersion } from './lti-registration-contract.mjs';
import { ltiServiceExact } from './lti-service-contract.mjs';

const unavailable=()=>{throw Error('lti_service_recovery_unavailable');};
function scope(value) {
 if(!ltiId(value.organizationId)||!ltiId(value.platformId)||!ltiUuid(value.registrationId)||!ltiUuid(value.attemptId))unavailable();
}
function command(value) {
 ltiServiceExact(value,['organizationId','platformId','registrationId','attemptId','operationId','actorId','action','expectedPhase',
  'expectedPlatformVersion','expectedRegistrationVersion','expectedKeyVersion','confirmationReference']);scope(value);
 if(!ltiUuid(value.operationId)||!ltiId(value.actorId)||!['abandon_prepared','retire_known','resolve_unknown'].includes(value.action))unavailable();
 if(value.action==='resolve_unknown') {
  if(!['exchanging','uncertain'].includes(value.expectedPhase)||!ltiUuid(value.confirmationReference)
   ||![value.expectedPlatformVersion,value.expectedRegistrationVersion,value.expectedKeyVersion].every(ltiVersion))unavailable();
 } else if(value.confirmationReference!==null||value.expectedPlatformVersion!==null||value.expectedRegistrationVersion!==null||value.expectedKeyVersion!==null
  ||(value.action==='abandon_prepared'?value.expectedPhase!=='prepared':!['staged','published'].includes(value.expectedPhase)))unavailable();
 return Object.freeze({...value});
}
function receipt(value,expected) {
 ltiServiceExact(value,['operationId','attemptId','actorId','platformId','registrationId','action','priorPhase','phase','tokenReference','confirmationReference','providerDisposition']);
 scope({...expected,attemptId:value.attemptId});
 if(value.platformId!==expected.platformId||value.registrationId!==expected.registrationId||value.attemptId!==expected.attemptId
  ||value.operationId!==expected.operationId||!ltiId(value.actorId)||value.phase!=='resolved')unavailable();
 if(value.action==='resolve_unknown') {
  if(!['exchanging','uncertain'].includes(value.priorPhase)||!ltiUuid(value.confirmationReference))unavailable();
 } else if(value.confirmationReference!==null||!['abandon_prepared','retire_known'].includes(value.action)
  ||(value.action==='abandon_prepared'?value.priorPhase!=='prepared':!['staged','published'].includes(value.priorPhase)))unavailable();
 const disposition={abandon_prepared:'not_dispatched',retire_known:'elapsed_provider_ttl_after_custody',resolve_unknown:'operator_attested_external_disposition'}[value.action];
 if(value.providerDisposition!==disposition||(value.action==='retire_known'?!ltiUuid(value.tokenReference):value.tokenReference!==null))unavailable();
 return Object.freeze({...value});
}
export function createLtiServiceRecoveryStore(pool) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')unavailable();
 async function one(sql,values) {const result=await pool.query(sql,values);if(result?.rows?.length!==1||!Object.hasOwn(result.rows[0],'result'))unavailable();return result.rows[0].result;}
 return Object.freeze({
  async recover(value) {
   try {
    const input=command(value),result=await one(`SELECT canvas_connector.recover_lti_service_attempt($1,$2,$3::uuid,$4::uuid,
     $5::uuid,$6,$7,$8,$9::bigint,$10::bigint,$11::bigint,$12::uuid) AS result`,
    [input.organizationId,input.platformId,input.registrationId,input.attemptId,input.operationId,input.actorId,input.action,input.expectedPhase,
     input.expectedPlatformVersion,input.expectedRegistrationVersion,input.expectedKeyVersion,input.confirmationReference]);
    if(result===null)return null;const saved=receipt(result,input);
    if(saved.actorId!==input.actorId||saved.action!==input.action||saved.priorPhase!==input.expectedPhase
     ||saved.confirmationReference!==input.confirmationReference)unavailable();return saved;
   }catch{unavailable();}
  },
  async receipt(value) {
   try {
    ltiServiceExact(value,['organizationId','platformId','registrationId','attemptId','operationId']);scope(value);if(!ltiUuid(value.operationId))unavailable();
    const input={...value},result=await one(`SELECT (SELECT receipt FROM canvas_connector.lti_service_recovery_audit
     WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND attempt_id=$4::uuid AND operation_id=$5::uuid) AS result`,
    [input.organizationId,input.platformId,input.registrationId,input.attemptId,input.operationId]);
    return result===null?null:receipt(result,input);
   }catch{unavailable();}
  },
 });
}
