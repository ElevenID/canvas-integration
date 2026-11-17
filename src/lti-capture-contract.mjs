// SPDX-License-Identifier: AGPL-3.0-only
// Provider query data only. Canonical subject/application authority stays in Gateway.
import {exactRecord,canvasId} from './canvas-rest-contract.mjs';
import {canvasOrigin} from './canvas-rest-network.mjs';
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {ltiServiceReadScopes} from './lti-service-contract.mjs';
import {encodeExternalObservation} from './observation-submit.mjs';
const fail=()=>{throw Error('lti_capture_unavailable');};
const opaque=v=>typeof v==='string'&&/^[\x21-\x7e]{1,255}$/.test(v);
function exact(v,names) {exactRecord(v,names,'invalid_lti_capture');if(Object.keys(v).length!==names.length)fail();}
const fields={
 'canvas.ags_result':['score','score_maximum','score_percent'],
 'canvas.nrps_membership':['provider_state'],
};
export function prepareLtiCaptureRequirement(value) {
 try {
  const result=value?.factType==='canvas.ags_result',names=['factType','courseId','userId','resourceLinkId',result?'lineItemId':'contextId'];
  exact(value,names);
  if(!Object.hasOwn(fields,value.factType)||!opaque(value.userId)||!opaque(value.resourceLinkId)
   ||typeof value.courseId!=='string'||canvasId(value.courseId)!==value.courseId
   ||(result?typeof value.lineItemId!=='string'||canvasId(value.lineItemId)!==value.lineItemId:!opaque(value.contextId)))fail();
  const requirement=Object.freeze(Object.fromEntries(names.map(name=>[name,value[name]])));
  return Object.freeze({requirement,factType:value.factType,scope:Object.freeze({course_id:value.courseId,user_id:value.userId,
   resource_link_id:value.resourceLinkId,...result?{line_item_id:value.lineItemId}:{context_id:value.contextId}}),
   scopes:Object.freeze(result?[ltiServiceReadScopes.lineitems,ltiServiceReadScopes.results].sort():[ltiServiceReadScopes.memberships]),
   claimNames:Object.freeze([...fields[value.factType]])});
 }catch{fail();}
}
export function prepareLtiCaptureRouteIntent(value) {
 try {
  if(typeof globalThis.window!=='undefined')fail();
  exact(value,['producerRef','platformId','registrationId','bindingId','bindingRevision','requirement','claimNames','effectiveTimePolicy']);
  if(!ltiId(value.producerRef)||!ltiId(value.platformId)||!ltiUuid(value.registrationId)||typeof value.bindingId!=='string'
   ||!/^[A-Za-z0-9_-]{1,128}$/.test(value.bindingId)||!ltiVersion(value.bindingRevision)||value.effectiveTimePolicy!=='as_of_read')fail();
  const plan=prepareLtiCaptureRequirement(value.requirement);
  if(!Array.isArray(value.claimNames)||!value.claimNames.length||new Set(value.claimNames).size!==value.claimNames.length
   ||value.claimNames.some(name=>!plan.claimNames.includes(name)))fail();
  return Object.freeze({producerRef:value.producerRef,platformId:value.platformId,registrationId:value.registrationId,
   bindingId:value.bindingId,bindingRevision:value.bindingRevision,requirement:plan.requirement,
   claimNames:Object.freeze([...value.claimNames].sort()),effectiveTimePolicy:'as_of_read'});
 }catch{fail();}
}
export function prepareLtiCaptureRoute(value,snapshot,{platformOrigin,nowMs=Date.now()}={}) {
 try {
  value=prepareLtiCaptureRouteIntent(value);const plan=prepareLtiCaptureRequirement(value.requirement);
  if(!ltiVersion(nowMs)||typeof platformOrigin!=='string'||canvasOrigin(platformOrigin)!==platformOrigin)fail();
  exact(snapshot,['found','record','snapshot_at_ms']);
  if(snapshot.found!==true||!ltiVersion(snapshot.snapshot_at_ms)||Math.abs(snapshot.snapshot_at_ms-nowMs)>30000)fail();
  const binding=snapshot.record;
  if(binding===null||typeof binding!=='object'||Array.isArray(binding)||Object.keys(binding).length>32
   ||binding.id!==value.bindingId||binding.revision!==value.bindingRevision||binding.active!==true
   ||binding.source_id!==value.producerRef||binding.provider!=='canvas'||binding.fact_type!==plan.factType
   ||!['pending','under_review'].includes(binding.application_status)||!ltiVersion(binding.application_revision)
   ||!ltiVersion(binding.application_expires_at_ms)||binding.application_expires_at_ms<=Math.max(nowMs,snapshot.snapshot_at_ms))fail();
  const scope={canvas_origin:platformOrigin,registration_id:value.registrationId,...plan.scope};exact(binding.resource_scope,Object.keys(scope));
  if(Object.entries(scope).some(([name,item])=>binding.resource_scope[name]!==item))fail();
  const rules=binding.claim_rules;
  if(rules===null||typeof rules!=='object'||Array.isArray(rules)||Object.keys(rules).length>32)fail();
  const selected=[...value.claimNames,'effective_time_source'];
  for(const [name,rule] of Object.entries(rules))
   if(rule===null||typeof rule!=='object'||Array.isArray(rule)||typeof rule.required!=='boolean'||(rule.required&&!selected.includes(name)))fail();
  for(const name of selected) {
   const rule=rules[name],number=name!=='provider_state'&&name!=='effective_time_source';
   exact(rule,number?['kind','required','nullable','minimum','maximum']:['kind','required','nullable','max_bytes']);
   if(rule.kind!==(number?'number':'text')||typeof rule.required!=='boolean'||typeof rule.nullable!=='boolean'
    ||(number&&!rule.nullable)||(name==='effective_time_source'&&(rule.required!==true||rule.nullable!==false))
    ||(number? !Number.isFinite(rule.minimum)||!Number.isFinite(rule.maximum)||rule.minimum>rule.maximum:
     !Number.isInteger(rule.max_bytes)||rule.max_bytes<16||rule.max_bytes>512))fail();
  }
  return value;
 }catch{fail();}
}
// Absence/transport failure never becomes a negative fact. These APIs provide
// no event time; an explicitly configured read-time policy is required.
export function projectLtiCapture(value,observation,{platformOrigin,observedAtMs}={}) {
 try {
  const route=prepareLtiCaptureRouteIntent(value),plan=prepareLtiCaptureRequirement(route.requirement);
  if(!ltiVersion(observedAtMs)||observation===null||typeof platformOrigin!=='string'||canvasOrigin(platformOrigin)!==platformOrigin)fail();let assertions;
  if(plan.factType==='canvas.ags_result') {
   exact(observation,['userId','resultScore','resultMaximum','lineItemUrl']);
   if(observation.userId!==plan.requirement.userId||typeof observation.lineItemUrl!=='string')fail();
   if(observation.lineItemUrl!==`${platformOrigin}/api/lti/courses/${plan.requirement.courseId}/line_items/${plan.requirement.lineItemId}`
    ||observation.resultScore!==null&&(typeof observation.resultScore!=='number'||!Number.isFinite(observation.resultScore))
    ||typeof observation.resultMaximum!=='number'||!Number.isFinite(observation.resultMaximum)||observation.resultMaximum<0)fail();
   assertions={score:observation.resultScore,score_maximum:observation.resultMaximum,
    score_percent:observation.resultScore===null||observation.resultMaximum===0?null:100*observation.resultScore/observation.resultMaximum};
  } else {
   exact(observation,['userId','contextId','status','roles']);
   if(observation.userId!==plan.requirement.userId||observation.contextId!==plan.requirement.contextId
    ||!['Active','Inactive','Deleted'].includes(observation.status)||!Array.isArray(observation.roles)||observation.roles.length>64)fail();
   assertions={provider_state:observation.status};
  }
  const claims=Object.fromEntries(route.claimNames.map(name=>[name,assertions[name]]));claims.effective_time_source='observation_read';
  encodeExternalObservation({binding_id:route.bindingId,binding_revision:route.bindingRevision,observation_id:'projection-check',sequence:1,
   observed_at_ms:observedAtMs,effective_at_ms:observedAtMs,claims});
  return Object.freeze({observedAtMs,effectiveAtMs:observedAtMs,claims:Object.freeze(claims)});
 }catch{fail();}
}
