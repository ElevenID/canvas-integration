// SPDX-License-Identifier: AGPL-3.0-only
import { encodeExternalObservation,ObservationSubmissionError } from './observation-submit.mjs';
const unavailable=()=>new Error('connector_outbox_unavailable');
const label=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const identifier=value=>typeof value==='string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const projection=`organization_id AS "organizationId",producer_ref AS "producerRef",observation_id,binding_id,
  binding_revision::float8 AS binding_revision,sequence::float8 AS sequence,
  observed_at_ms::float8 AS observed_at_ms,effective_at_ms::float8 AS effective_at_ms,claims,
  body,phase,attempts,lease_id,receipt_id,replayed`;
const bodyFor=item=>encodeExternalObservation({binding_id:item.binding_id,binding_revision:item.binding_revision,
  observation_id:item.observation_id,sequence:item.sequence,observed_at_ms:item.observed_at_ms,
  effective_at_ms:item.effective_at_ms,claims:item.claims});
/** Atomic counter/ledger allocation, then recoverable canonical-byte sealing.
 * Only connector routing labels; no key secret, core authority or transaction
 * handle is stored or required. Every query must autocommit before returning.
 */
export function createObservationOutbox(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function')throw unavailable();
  const query=async(text,values)=>{try{return await pool.query(text,values);}catch{throw unavailable();}};
  const first=async(text,values)=>(await query(text,values)).rows[0]??null;
  const scope=(org,producer)=>{if(!label(org)||!label(producer))throw unavailable();};
  const seal=async item=>{
    const body=bodyFor(item);
    if(item.body!==null && item.body!==body)throw unavailable();
    if(item.body===null) {
      const result=await first('SELECT canvas_connector.seal_observation($1,$2,$3,$4) AS ok',
        [item.organizationId,item.producerRef,item.observation_id,body]);
      if(result?.ok!==true)throw unavailable();
    }
    return Object.freeze({observationId:item.observation_id,sequence:item.sequence,body});
  };
  return Object.freeze({
    async enqueue(org,producer,input) {
      scope(org,producer);
      const fields=['binding_id','binding_revision','observation_id','observed_at_ms','effective_at_ms','claims'];
      if(input===null || typeof input!=='object' || ![Object.prototype,null].includes(Object.getPrototypeOf(input))
          || Object.getOwnPropertySymbols(input).length)throw unavailable();
      const descriptors=Object.getOwnPropertyDescriptors(input);
      if(Object.keys(descriptors).length!==fields.length || fields.some(name=>!Object.hasOwn(descriptors,name)
          || !('value' in descriptors[name]) || !descriptors[name].enumerable))throw unavailable();
      const value=Object.fromEntries(fields.map(name=>[name,descriptors[name].value]));
      // Validate without choosing the real sequence. Database allocation and
      // ledger insertion are one transaction; failed insertion rolls both back.
      let validated;
      try {validated=JSON.parse(encodeExternalObservation({...value,sequence:1}));}catch{throw unavailable();}
      const item=await first(`SELECT ${projection} FROM canvas_connector.enqueue_observation($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
        [org,producer,validated.binding_id,validated.binding_revision,validated.observation_id,validated.observed_at_ms,
          validated.effective_at_ms,JSON.stringify(validated.claims)]);
      if(!item)throw unavailable();return seal(item);
    },
    async prepareNext(org,producer) {
      scope(org,producer);
      const item=await first(`SELECT ${projection} FROM canvas_connector.observation_outbox
        WHERE organization_id=$1 AND producer_ref=$2 AND phase='preparing'
        ORDER BY created_at,binding_id,sequence LIMIT 1`,[org,producer]);
      if(!item)return false;await seal(item);return true;
    },
    async claim(org,producer) {
      scope(org,producer);return first(`SELECT ${projection} FROM canvas_connector.claim_observation($1,$2)`,[org,producer]);
    },
    async acknowledge(org,producer,observation,lease,receipt) {
      scope(org,producer);
      const result=await first('SELECT canvas_connector.acknowledge_observation($1,$2,$3,$4,$5,$6) AS ok',
        [org,producer,observation,lease,receipt.receipt_id,receipt.replayed]);return result?.ok===true;
    },
    async defer(org,producer,observation,lease,code,status,park) {
      scope(org,producer);
      const result=await first('SELECT canvas_connector.defer_observation($1,$2,$3,$4,$5,$6,$7) AS ok',
        [org,producer,observation,lease,code,status??null,park]);return result?.ok===true;
    },
  });
}
/** One configured organization/credential slot per worker. Only submit(body)
 * is invoked; this worker cannot select a URL or supply authority headers.
 */
export function createObservationDeliveryWorker(configuration={}) {
  if(configuration===null || typeof configuration!=='object' || Array.isArray(configuration)
      || Object.keys(configuration).some(name=>!['repository','submitter','organizationId','producerRef','maxAttempts'].includes(name)))throw unavailable();
  const {repository,submitter,organizationId,producerRef,maxAttempts=8}=configuration;
  if(typeof globalThis.window!=='undefined' || !label(organizationId)||!label(producerRef)
      || typeof submitter?.submit!=='function' || !Number.isSafeInteger(maxAttempts)||maxAttempts<1||maxAttempts>32
      || ['prepareNext','claim','acknowledge','defer'].some(name=>typeof repository?.[name]!=='function'))throw unavailable();
  return Object.freeze({
    async runOnce() {
      let item;
      try {await repository.prepareNext(organizationId,producerRef);item=await repository.claim(organizationId,producerRef);}
      catch{return Object.freeze({state:'storage_unavailable'});}
      if(item===null)return Object.freeze({state:'idle'});
      const outcome=state=>Object.freeze({state,observationId:item?.observation_id});
      if(item?.organizationId!==organizationId || item.producerRef!==producerRef || !identifier(item.observation_id)
          || item.phase!=='leased' || typeof item.lease_id!=='string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(item.lease_id)
          || !Number.isSafeInteger(item.attempts)||item.attempts<1)return outcome('reconciliation_required');
      let code;let status;let park=false;let receipt;
      try {
        if(item.body!==bodyFor(item))throw new ObservationSubmissionError('invalid_observation');
        if(item.attempts>maxAttempts){code='delivery_attempt_limit';park=true;}
        else {
          receipt=await submitter.submit(item.body);
          if(receipt===null || typeof receipt!=='object' || Object.keys(receipt).length!==2
              || !identifier(receipt.receipt_id)||typeof receipt.replayed!=='boolean')
            throw new ObservationSubmissionError('submission_outcome_unknown');
        }
      } catch(error) {
        receipt=undefined;
        if(error instanceof ObservationSubmissionError && error.code==='invalid_observation') {
          code='invalid_stored_observation';park=true;
        } else {
          status=error instanceof ObservationSubmissionError&&Number.isInteger(error.status)&&error.status>=300&&error.status<=599?error.status:undefined;
          code=error instanceof ObservationSubmissionError&&error.code==='submission_rejected'?'submission_rejected':'submission_outcome_unknown';
          park=code==='submission_rejected' && status!==429;
          if(!park && item.attempts>=maxAttempts){code='delivery_attempt_limit';park=true;}
        }
      }
      try {
        if(receipt!==undefined) {
          const committed=await repository.acknowledge(organizationId,producerRef,item.observation_id,item.lease_id,receipt);
          return outcome(committed?'acknowledged':'reconciliation_required');
        }
        const committed=await repository.defer(organizationId,producerRef,item.observation_id,item.lease_id,code,status,park);
        return outcome(committed?(park?'parked':'retry_scheduled'):'reconciliation_required');
      } catch{return outcome('reconciliation_required');}
    },
  });
}
