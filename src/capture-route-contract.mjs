// SPDX-License-Identifier: AGPL-3.0-only
// Connector query configuration, never a grant, identity mirror or admission.
import {prepareRequirement,exactRecord} from './canvas-rest-contract.mjs';
import {canvasOrigin} from './canvas-rest-network.mjs';
const unavailable=()=>new Error('connector_capture_route_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const bindingId=value=>typeof value==='string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const revision=value=>Number.isSafeInteger(value) && value>=1;
const numeric=new Set(['score','score_maximum','score_percent','requirement_count','requirement_completed_count']);
const nullable=new Set([...numeric,'provider_state']);
const selected=new Set(['completed',...nullable]);
function object(value,max) {
  if(value===null || typeof value!=='object' || Array.isArray(value)
    || ![Object.prototype,null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length>max
    || Reflect.ownKeys(value).some(key=>typeof key!=='string' || !('value' in Object.getOwnPropertyDescriptor(value,key)))) throw unavailable();
}
function rule(value,kind,canBeNull) {
  object(value,6);
  const fields=kind==='number'?['kind','required','nullable','minimum','maximum']:
    kind==='text'?['kind','required','nullable','max_bytes']:['kind','required','nullable'];
  if(Object.keys(value).sort().join(',')!==fields.slice().sort().join(',') || value.kind!==kind
    || typeof value.required!=='boolean' || typeof value.nullable!=='boolean' || (canBeNull && !value.nullable)) throw unavailable();
  if(kind==='number' && (!Number.isFinite(value.minimum) || !Number.isFinite(value.maximum) || value.minimum>value.maximum)) throw unavailable();
  if(kind==='text' && (!Number.isInteger(value.max_bytes) || value.max_bytes<16 || value.max_bytes>512)) throw unavailable();
}

/** Validate a fresh public-Gateway snapshot, then discard all Core authority
 * metadata. The HTTP adapter must obtain this snapshot itself and reauthorize
 * its session. Nothing returned here authorizes delivery, verification or issue. */
export function prepareCaptureRoute(value,snapshot,{platformOrigin,nowMs=Date.now()}={}) {
  try {
    if(typeof globalThis.window!=='undefined') throw unavailable();
    exactRecord(value,['producerRef','platformId','bindingId','bindingRevision','requirement','claimNames','effectiveTimePolicy'],'invalid_route');
    if(!id(value.producerRef) || !id(value.platformId) || !bindingId(value.bindingId) || !revision(value.bindingRevision)
      || !['require_provider_time','as_of_read'].includes(value.effectiveTimePolicy) || !revision(nowMs)) throw unavailable();
    if(typeof platformOrigin!=='string' || Buffer.byteLength(platformOrigin)>512 || canvasOrigin(platformOrigin)!==platformOrigin) throw unavailable();
    object(value.requirement,5);
    for(const name of ['courseId','userId','activityId','moduleId'])
      if(Object.hasOwn(value.requirement,name) && typeof value.requirement[name]!=='string') throw unavailable();
    const plan=prepareRequirement(value.requirement);
    if(!Array.isArray(value.claimNames) || value.claimNames.length<1 || value.claimNames.length>7
      || new Set(value.claimNames).size!==value.claimNames.length || value.claimNames.some(name=>!selected.has(name))) throw unavailable();
    object(snapshot,3);
    if(Object.keys(snapshot).sort().join(',')!=='found,record,snapshot_at_ms' || snapshot.found!==true
      || !revision(snapshot.snapshot_at_ms) || Math.abs(snapshot.snapshot_at_ms-nowMs)>30000) throw unavailable();
    const binding=snapshot.record;object(binding,32);
    if(binding.id!==value.bindingId || binding.revision!==value.bindingRevision || binding.active!==true
      || binding.source_id!==value.producerRef || binding.provider!=='canvas' || binding.fact_type!==plan.factType
      || !['pending','under_review'].includes(binding.application_status) || !revision(binding.application_revision)
      || !revision(binding.application_expires_at_ms) || binding.application_expires_at_ms<=Math.max(nowMs,snapshot.snapshot_at_ms)) throw unavailable();
    // Canvas numeric IDs are instance-local. Require the canonical binding to
    // name its origin as data, so equal IDs on another Canvas cannot be remapped.
    const expected={canvas_origin:platformOrigin,...plan.scope};object(binding.resource_scope,5);
    if(Object.keys(binding.resource_scope).sort().join(',')!==Object.keys(expected).sort().join(',')
      || Object.entries(expected).some(([key,item])=>binding.resource_scope[key]!==item)) throw unavailable();
    object(binding.claim_rules,32);
    const names=new Set([...value.claimNames,'effective_time_source']);
    for(const [name,definition] of Object.entries(binding.claim_rules)) {
      object(definition,6);
      if(typeof definition.required!=='boolean' || (definition.required && !names.has(name))) throw unavailable();
    }
    for(const name of value.claimNames) {
      if(!Object.hasOwn(binding.claim_rules,name)) throw unavailable();
      rule(binding.claim_rules[name],name==='completed'?'boolean':numeric.has(name)?'number':'text',nullable.has(name));
    }
    const provenance=binding.claim_rules.effective_time_source;
    rule(provenance,'text',false);
    if(provenance.required!==true || provenance.nullable!==false) throw unavailable();
    // Reconstruct primitive configuration; no application, subject, permission,
    // approval, grant, key or snapshot is persisted as local authority.
    const requirement={factType:plan.factType,courseId:plan.scope.course_id,userId:plan.scope.user_id};
    if(plan.scope.activity_id!==undefined) requirement.activityId=plan.scope.activity_id;
    if(plan.scope.module_id!==undefined) requirement.moduleId=plan.scope.module_id;
    return Object.freeze({producerRef:value.producerRef,platformId:value.platformId,bindingId:value.bindingId,
      bindingRevision:value.bindingRevision,requirement:Object.freeze(requirement),
      claimNames:Object.freeze([...value.claimNames].sort()),effectiveTimePolicy:value.effectiveTimePolicy});
  } catch {throw unavailable();}
}
