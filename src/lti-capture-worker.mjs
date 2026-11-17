// SPDX-License-Identifier: AGPL-3.0-only
import {createCanvasLtiServiceReader,CanvasLtiServiceError} from './canvas-lti-service-client.mjs';
import {canvasOrigin,approvedPrivateAddresses} from './canvas-rest-network.mjs';
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {ltiServiceExact,ltiServiceAttempt} from './lti-service-contract.mjs';
import {prepareLtiCaptureRouteIntent,prepareLtiCaptureRequirement,projectLtiCapture} from './lti-capture-contract.mjs';
const fail=()=>{throw Error('lti_capture_worker_unavailable');};
function snapshot(value,organizationId,producerRef) {
 ltiServiceExact(value,['organizationId','producerRef','captureId','leaseId','attempts','definition','canvasOrigin',
  'platformVersion','registrationVersion','keyVersion','serviceOperationId','tokenReference']);
 if(value.organizationId!==organizationId||value.producerRef!==producerRef||!ltiUuid(value.captureId)||!ltiUuid(value.leaseId)
  ||!Number.isSafeInteger(value.attempts)||value.attempts<1
  ||![value.platformVersion,value.registrationVersion,value.keyVersion].every(ltiVersion)
  ||!ltiUuid(value.serviceOperationId)||!ltiUuid(value.tokenReference)||typeof value.canvasOrigin!=='string'
  ||canvasOrigin(value.canvasOrigin)!==value.canvasOrigin)fail();
 const definition=prepareLtiCaptureRouteIntent(value.definition);if(definition.producerRef!==producerRef)fail();
 return Object.freeze({...value,definition});
}
// A repository must fence lease/config/token revisions again in its atomic
// complete-and-enqueue transaction. This worker cannot grant Core authority.
export function createLtiCaptureWorker(configuration) {
 try {
  if(typeof globalThis.window!=='undefined')fail();
  const names=['repository','tokenStore','organizationId','producerRef','ca','allowedPrivateAddresses','timeoutMs','maxResponseBytes','maxPages','maxAttempts'];
  if(configuration===null||typeof configuration!=='object'||Array.isArray(configuration)||Object.keys(configuration).some(n=>!names.includes(n)))fail();
  const {repository,tokenStore,organizationId,producerRef,ca,timeoutMs=15000,maxResponseBytes=1048576,maxPages=8,maxAttempts=8}=configuration;
  if(!ltiId(organizationId)||!ltiId(producerRef)||['claim','permit','complete','defer'].some(n=>typeof repository?.[n]!=='function')
   ||['inspect','currentToken','permitRead'].some(n=>typeof tokenStore?.[n]!=='function')
   ||!Number.isInteger(maxAttempts)||maxAttempts<1||maxAttempts>32||!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>120000
   ||!Number.isInteger(maxResponseBytes)||maxResponseBytes<256||maxResponseBytes>8388608||!Number.isInteger(maxPages)||maxPages<1||maxPages>16
   ||ca!==undefined&&(typeof ca!=='string'||ca.length>65536||!ca.includes('-----BEGIN CERTIFICATE-----')||/PRIVATE KEY/.test(ca)))fail();
  const addresses=approvedPrivateAddresses(configuration.allowedPrivateAddresses);
  return Object.freeze({async runOnce() {
   let value;try{value=await repository.claim(organizationId,producerRef);}catch{return Object.freeze({state:'storage_unavailable'});}
   if(value===null)return Object.freeze({state:'idle'});
   let job;try{job=snapshot(value,organizationId,producerRef);}catch{return Object.freeze({state:'reconciliation_required'});}
   const outcome=state=>Object.freeze({state,captureId:job.captureId});
   const handle={organizationId,operationId:job.serviceOperationId},permitHandle={...handle,tokenReference:job.tokenReference};
   let result,park=false,code='provider_unavailable';
   try {
    if(job.attempts>maxAttempts){park=true;code='attempt_limit';}
    else {
     const aValue=await tokenStore.inspect(handle),a=aValue===null?null:ltiServiceAttempt(aValue);
     const plan=prepareLtiCaptureRequirement(job.definition.requirement);
     if(a===null||a.phase!=='published'||a.organizationId!==organizationId||a.operationId!==job.serviceOperationId
      ||a.platformId!==job.definition.platformId||a.registrationId!==job.definition.registrationId||a.canvasOrigin!==job.canvasOrigin
      ||a.platformVersion!==job.platformVersion||a.registrationVersion!==job.registrationVersion||a.keyVersion!==job.keyVersion
      ||a.tokenReference!==job.tokenReference||plan.scopes.some(scope=>!a.receipt.scopes.includes(scope))) {
      park=true;code='configuration_changed';
     } else {
      const token=await tokenStore.currentToken(handle);
      if(token===null||plan.scopes.some(scope=>!token.scopes.includes(scope))) {park=true;code='configuration_changed';}
      else {
       const reader=createCanvasLtiServiceReader({canvasOrigin:job.canvasOrigin,ca,allowedPrivateAddresses:addresses,
        timeoutMs,maxResponseBytes,maxPages,beforeRead:async({signal})=>{
         if(signal.aborted||await repository.permit(organizationId,producerRef,job.captureId,job.leaseId)!==true||signal.aborted)return false;
         return await tokenStore.permitRead(permitHandle)===true&&!signal.aborted;
        }});
       const r=plan.requirement;let observation;
       if(plan.factType==='canvas.ags_result') {
        const line=await reader.readLineItem({token,courseId:r.courseId,lineItemId:r.lineItemId});
        if(line.resourceLinkId!==r.resourceLinkId){park=true;code='configuration_changed';}
        else observation=await reader.readResults({token,courseId:r.courseId,lineItemId:r.lineItemId,userId:r.userId});
       } else observation=await reader.readMembership({token,courseId:r.courseId,userId:r.userId,contextId:r.contextId,resourceLinkId:r.resourceLinkId});
       if(!park) {
        if(observation===null){code='observation_missing';}
        else result=projectLtiCapture(job.definition,observation,{platformOrigin:job.canvasOrigin,observedAtMs:Date.now()});
       }
      }
     }
    }
   }catch(error){
    if(error instanceof CanvasLtiServiceError) {
     park=[400,401,403,404].includes(error.status)||['dispatch_denied','resource_mismatch','invalid_payload','invalid_resource'].includes(error.code);
     if(park)code='configuration_changed';
    }
   }
   if(result!==undefined) {
    try{return outcome(await repository.complete(organizationId,producerRef,job.captureId,job.leaseId,result)===true?'captured':'reconciliation_required');}
    catch{return outcome('reconciliation_required');}
   }
   if(!park&&job.attempts>=maxAttempts){park=true;code='attempt_limit';}
   try{return outcome(await repository.defer(organizationId,producerRef,job.captureId,job.leaseId,code,park)===true?park?'parked':'retry_scheduled':'reconciliation_required');}
   catch{return outcome('reconciliation_required');}
  }});
 }catch{fail();}
}
