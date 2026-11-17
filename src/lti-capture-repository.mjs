// SPDX-License-Identifier: AGPL-3.0-only
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {ltiServiceExact} from './lti-service-contract.mjs';
import {prepareLtiCaptureRouteIntent} from './lti-capture-contract.mjs';
import {encodeExternalObservation} from './observation-submit.mjs';
const fail=()=>{throw Error('lti_capture_repository_unavailable');};
function scope(org,producer,capture,lease) {
 if(!ltiId(org)||!ltiId(producer)||capture!==undefined&&!ltiUuid(capture)||lease!==undefined&&!ltiUuid(lease))fail();
}
export function createLtiCaptureRepository(pool) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')fail();
 async function one(sql,values,{empty=false}={}) {
  try {
   const result=await pool.query(sql,values);
   if(empty&&result?.rows?.length===0)return null;
   if(result?.rows?.length!==1||Object.keys(result.rows[0]).join(',')!=='result'||result.rows[0].result===undefined)fail();
   return result.rows[0].result;
  }catch{fail();}
 }
 async function boolean(sql,values) {const result=await one(sql,values);if(typeof result!=='boolean')fail();return result;}
 return Object.freeze({
  async schedule(value) {
   try {
    ltiServiceExact(value,['organizationId','producerRef','routeId','expectedRouteVersion','captureId']);
    const v={...value};scope(v.organizationId,v.producerRef,v.captureId);
    if(!ltiId(v.routeId)||!ltiVersion(v.expectedRouteVersion))fail();
    return await boolean('SELECT canvas_connector.schedule_lti_capture($1,$2,$3,$4::bigint,$5::uuid) AS result',
     [v.organizationId,v.producerRef,v.routeId,v.expectedRouteVersion,v.captureId]);
   }catch{fail();}
  },
  async claim(org,producer) {
   try {
    scope(org,producer);
    const value=await one(`SELECT jsonb_build_object('organizationId',organization_id,'producerRef',producer_ref,
     'captureId',capture_id,'leaseId',lease_id,'attempts',attempts,'definition',definition,'canvasOrigin',canvas_origin,
     'platformVersion',platform_version,'registrationVersion',registration_version,'keyVersion',key_version,
     'serviceOperationId',service_operation_id,'tokenReference',token_reference) AS result
     FROM canvas_connector.claim_lti_capture($1,$2)`,[org,producer],{empty:true});
    if(value===null)return null;
    ltiServiceExact(value,['organizationId','producerRef','captureId','leaseId','attempts','definition','canvasOrigin',
     'platformVersion','registrationVersion','keyVersion','serviceOperationId','tokenReference']);
    if(value.organizationId!==org||value.producerRef!==producer||!ltiUuid(value.captureId)||!ltiUuid(value.leaseId)
     ||!ltiUuid(value.serviceOperationId)||!ltiUuid(value.tokenReference)||!Number.isSafeInteger(value.attempts)||value.attempts<1
     ||![value.platformVersion,value.registrationVersion,value.keyVersion].every(ltiVersion))fail();
    const definition=prepareLtiCaptureRouteIntent(value.definition);if(definition.producerRef!==producer)fail();
    return Object.freeze({...value,definition});
   }catch{fail();}
  },
  async permit(org,producer,capture,lease) {
   scope(org,producer,capture,lease);
   return boolean(`SELECT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs j WHERE organization_id=$1 AND producer_ref=$2
    AND capture_id=$3::uuid AND lease_id=$4::uuid AND phase='leased' AND lease_expires_at>clock_timestamp()
    AND canvas_connector.lti_capture_current(j)) AS result`,[org,producer,capture,lease]);
  },
  async complete(org,producer,capture,lease,result) {
   try {
    scope(org,producer,capture,lease);ltiServiceExact(result,['observedAtMs','effectiveAtMs','claims']);
    const observed=result.observedAtMs,effective=result.effectiveAtMs;
    if(observed!==effective)fail();
    const claims=JSON.parse(encodeExternalObservation({binding_id:'validation',binding_revision:1,observation_id:capture,sequence:1,
     observed_at_ms:observed,effective_at_ms:effective,claims:result.claims})).claims;
    return await boolean('SELECT canvas_connector.complete_lti_capture($1,$2,$3::uuid,$4::uuid,$5::bigint,$6::bigint,$7::jsonb) AS result',
     [org,producer,capture,lease,observed,effective,JSON.stringify(claims)]);
   }catch{fail();}
  },
  async defer(org,producer,capture,lease,code,park) {
   scope(org,producer,capture,lease);
   if(!['provider_unavailable','configuration_changed','observation_missing','attempt_limit'].includes(code)||typeof park!=='boolean')fail();
   return boolean('SELECT canvas_connector.defer_lti_capture($1,$2,$3::uuid,$4::uuid,$5,$6::boolean) AS result',[org,producer,capture,lease,code,park]);
  },
  async inspect(org,producer,capture) {
   scope(org,producer,capture);
   const result=await one(`SELECT (SELECT jsonb_build_object('captureId',capture_id,'phase',phase,'attempts',attempts,'result',result)
    FROM canvas_connector.lti_capture_jobs WHERE organization_id=$1 AND producer_ref=$2 AND capture_id=$3::uuid) AS result`,[org,producer,capture]);
   if(result===null)return null;
   ltiServiceExact(result,['captureId','phase','attempts','result']);
   if(result.captureId!==capture||!['pending','leased','retry','completed','parked'].includes(result.phase)
    ||!Number.isSafeInteger(result.attempts)||result.attempts<0||(result.phase==='completed')!==(result.result!==null))fail();
   return Object.freeze(result);
  },
 });
}
