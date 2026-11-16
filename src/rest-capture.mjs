// SPDX-License-Identifier: AGPL-3.0-only
import {createCanvasRestReader,CanvasReadError} from './canvas-rest-reader.mjs';
import {prepareRequirement,exactRecord} from './canvas-rest-contract.mjs';
import {canvasOrigin,approvedPrivateAddresses} from './canvas-rest-network.mjs';
import {encodeExternalObservation} from './observation-submit.mjs';
const unavailable=()=>new Error('connector_capture_unavailable');
const label=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const fields=['completed','score','score_maximum','score_percent','provider_state','requirement_count','requirement_completed_count'];
const timestamp=value=>{
 if(typeof value!=='string')throw unavailable();const ms=Date.parse(value);
 if(!Number.isSafeInteger(ms)||ms<=0||new Date(ms).toISOString()!==value)throw unavailable();return ms;
};
export function projectCanvasRestCapture(job,observation) {
 try {
  const plan=prepareRequirement(job.requirement);
  if(!['require_provider_time','as_of_read'].includes(job.effective_time_policy))throw unavailable();
  exactRecord(observation,['schema','source','fact_type','canvas_origin','scope','assertion','source_payload','verification_method','observed_at','effective_at'],'invalid_observation');
  if(observation.schema!=='elevenid.canvas-rest-observation/v1'||observation.source!=='canvas_rest'||observation.fact_type!==plan.factType
    ||observation.canvas_origin!==canvasOrigin(job.canvas_origin)||observation.verification_method!=='CANVAS_OAUTH_API_READ')throw unavailable();
  exactRecord(observation.scope,Object.keys(plan.scope),'invalid_observation');
  if(Object.keys(observation.scope).length!==Object.keys(plan.scope).length||Object.entries(plan.scope).some(([key,value])=>observation.scope[key]!==value))throw unavailable();
  exactRecord(observation.assertion,fields,'invalid_observation');
  if(Object.keys(observation.assertion).length!==fields.length||typeof observation.assertion.completed!=='boolean')throw unavailable();
  for(const name of ['score','score_maximum','score_percent'])if(observation.assertion[name]!==null
   && (typeof observation.assertion[name]!=='number'||!Number.isFinite(observation.assertion[name])))throw unavailable();
  for(const name of ['requirement_count','requirement_completed_count'])if(observation.assertion[name]!==null
   &&(!Number.isSafeInteger(observation.assertion[name])||observation.assertion[name]<0))throw unavailable();
  if(observation.assertion.provider_state!==null&&typeof observation.assertion.provider_state!=='string')throw unavailable();
  if(!Array.isArray(job.claim_names)||!job.claim_names.length||new Set(job.claim_names).size!==job.claim_names.length
   ||job.claim_names.some(name=>!fields.includes(name)))throw unavailable();
  const observed=timestamp(observation.observed_at);let effective;let source;
  if(observation.effective_at===null) {
   if(job.effective_time_policy!=='as_of_read')throw unavailable();effective=observed;source='observation_read';
  } else {effective=timestamp(observation.effective_at);source='provider_event';}
  const claims=Object.fromEntries(job.claim_names.map(name=>[name,observation.assertion[name]]));claims.effective_time_source=source;
  const envelope={binding_id:job.binding_id,binding_revision:job.binding_revision,observation_id:job.capture_id,
   sequence:1,observed_at_ms:observed,effective_at_ms:effective,claims};
  encodeExternalObservation(envelope);
  return Object.freeze({observedAtMs:observed,effectiveAtMs:effective,claims:Object.freeze(claims)});
 }catch{throw unavailable();}
}
const projection=`organization_id AS "organizationId",producer_ref AS "producerRef",capture_id,route_id,route_version::float8 AS route_version,
 platform_id,binding_id,binding_revision::float8 AS binding_revision,requirement,claim_names,effective_time_policy,
 phase,attempts,lease_id,canvas_origin,platform_config_version::float8 AS platform_config_version,
 connection_revision::float8 AS connection_revision,access_token_ref,capabilities,scopes`;
export function createRestCaptureRepository(pool) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')throw unavailable();
 const first=async(sql,values)=>{try{return (await pool.query(sql,values)).rows[0]??null;}catch{throw unavailable();}};
 const scope=(org,producer)=>{if(!label(org)||!label(producer))throw unavailable();};
 return Object.freeze({
  async schedule(org,producer,route,capture) {
   scope(org,producer);if(!label(route)||typeof capture!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(capture))throw unavailable();
   return (await first('SELECT canvas_connector.schedule_rest_capture($1,$2,$3,$4) AS ok',[org,producer,route,capture]))?.ok===true;
  },
  async claim(org,producer) {scope(org,producer);return first(`SELECT ${projection} FROM canvas_connector.claim_rest_capture($1,$2)`,[org,producer]);},
  async complete(org,producer,capture,lease,result) {
   scope(org,producer);return (await first('SELECT canvas_connector.complete_rest_capture($1,$2,$3,$4,$5,$6,$7::jsonb) AS ok',
    [org,producer,capture,lease,result.observedAtMs,result.effectiveAtMs,JSON.stringify(result.claims)]))?.ok===true;
  },
  async defer(org,producer,capture,lease,code,park) {
   scope(org,producer);return (await first('SELECT canvas_connector.defer_rest_capture($1,$2,$3,$4,$5,$6) AS ok',
    [org,producer,capture,lease,code,park]))?.ok===true;
  },
 });
}
const capabilities={
 'canvas.assignment_score':['native_activity_scores','url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id','url:GET|/api/v1/courses/:course_id/assignments/:id'],
 'canvas.quiz_score':['native_activity_scores','url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id','url:GET|/api/v1/courses/:course_id/assignments/:id'],
 'canvas.module_completion':['module_completion','url:GET|/api/v1/courses/:course_id/modules/:id'],
 'canvas.course_completion':['course_completion','url:GET|/api/v1/courses/:course_id/users/:user_id/progress'],
};
export function createCanvasRestCaptureWorker(configuration={}) {
 if(configuration===null||typeof configuration!=='object'||Array.isArray(configuration)
  ||Object.keys(configuration).some(name=>!['repository','secretVault','organizationId','producerRef','canvasCa','allowedPrivateAddresses','timeoutMs','maxAttempts'].includes(name)))throw unavailable();
 const {repository,secretVault,organizationId,producerRef,canvasCa,timeoutMs=15000,maxAttempts=8}=configuration;
 if(typeof globalThis.window!=='undefined'||!label(organizationId)||!label(producerRef)||typeof secretVault?.get!=='function'
  ||['claim','complete','defer'].some(name=>typeof repository?.[name]!=='function')||!Number.isSafeInteger(maxAttempts)||maxAttempts<1||maxAttempts>32
  ||!Number.isSafeInteger(timeoutMs)||timeoutMs<50||timeoutMs>120000
  ||(canvasCa!==undefined&&(typeof canvasCa!=='string'||canvasCa.length>65536||!canvasCa.includes('-----BEGIN CERTIFICATE-----')||/PRIVATE KEY/.test(canvasCa))))throw unavailable();
 const addresses=approvedPrivateAddresses(configuration.allowedPrivateAddresses);
 return Object.freeze({async runOnce() {
  let job;try{job=await repository.claim(organizationId,producerRef);}catch{return Object.freeze({state:'storage_unavailable'});}
  if(job===null)return Object.freeze({state:'idle'});
  const outcome=state=>Object.freeze({state,captureId:job?.capture_id});
  if(job?.organizationId!==organizationId||job.producerRef!==producerRef||job.phase!=='leased'
   ||typeof job.lease_id!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(job.lease_id)
   ||!Number.isSafeInteger(job.attempts)||job.attempts<1)return outcome('reconciliation_required');
  let result;let code='provider_unavailable';let park=false;
  try {
   const plan=prepareRequirement(job.requirement);const required=capabilities[plan.factType];canvasOrigin(job.canvas_origin);
   if(!label(job.platform_id)||!Array.isArray(job.capabilities)||!job.capabilities.includes(required[0])
    ||!Array.isArray(job.scopes)||required.slice(1).some(scope=>!job.scopes.includes(scope))) {code='configuration_changed';park=true;}
   else if(job.attempts>maxAttempts){code='attempt_limit';park=true;}
   else {
    const token=await secretVault.get(organizationId,job.access_token_ref,{platformId:job.platform_id,provider:'canvas',purpose:'oauth_access_token'});
    const reader=createCanvasRestReader({canvasOrigin:job.canvas_origin,accessToken:token,ca:canvasCa,allowedPrivateAddresses:addresses,timeoutMs});
    const observation=await reader.readRequirement(job.requirement);
    try{result=projectCanvasRestCapture(job,observation);}catch{code='invalid_observation';park=true;}
   }
  }catch(error){park=error instanceof CanvasReadError&&[400,401,403,404].includes(error.status);}
  if(result!==undefined) {
   try{return outcome(await repository.complete(organizationId,producerRef,job.capture_id,job.lease_id,result)?'captured':'reconciliation_required');}
   catch{return outcome('reconciliation_required');}
  }
  if(!park&&job.attempts>=maxAttempts){code='attempt_limit';park=true;}
  try{return outcome(await repository.defer(organizationId,producerRef,job.capture_id,job.lease_id,code,park)?(park?'parked':'retry_scheduled'):'reconciliation_required');}
  catch{return outcome('reconciliation_required');}
 }});
}
