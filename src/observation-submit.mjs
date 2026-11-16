// SPDX-License-Identifier: AGPL-3.0-only
import { request as httpsRequest } from 'node:https';

export class ObservationSubmissionError extends Error {
  constructor(code,status) {
    super(code);this.name='ObservationSubmissionError';this.code=code;
    if(status!==undefined)this.status=status;
  }
}
const fail=()=>{throw new ObservationSubmissionError('invalid_observation');};
const identifier=value=>typeof value==='string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const positive=value=>Number.isSafeInteger(value) && value>0;
const reserved=new Set(['verified','verification','policy_allowed','approved','organization_id','subject_id',
  'application_id','provider','fact_type','scope','issuer_key','signing_key','private_key','token','access_token',
  'refresh_token','client_secret','password','__proto__','constructor','prototype','tojson']);
function properties(value) {
  if(value===null || typeof value!=='object' || ![Object.prototype,null].includes(Object.getPrototypeOf(value))
      || Object.getOwnPropertySymbols(value).length)fail();
  const descriptors=Object.getOwnPropertyDescriptors(value);
  for(const descriptor of Object.values(descriptors))if(!('value' in descriptor) || !descriptor.enumerable)fail();
  return descriptors;
}
/** Stable original bytes for a durable outbox. No identity, subject, provider,
 * policy, approval or verified status can be supplied by this envelope.
 */
export function encodeExternalObservation(input) {
  const fields=['binding_id','binding_revision','observation_id','sequence','observed_at_ms','effective_at_ms','claims'];
  const descriptors=properties(input);
  if(Object.keys(descriptors).length!==fields.length || fields.some(name=>!Object.hasOwn(descriptors,name)))fail();
  const values=Object.fromEntries(fields.map(name=>[name,descriptors[name].value]));
  if(!identifier(values.binding_id) || !identifier(values.observation_id)
      || !['binding_revision','sequence','observed_at_ms','effective_at_ms'].every(name=>positive(values[name]))
      || values.effective_at_ms>values.observed_at_ms)fail();
  const claimDescriptors=properties(values.claims);const names=Object.keys(claimDescriptors).sort();
  if(!names.length || names.length>32)fail();
  const claims=Object.create(null);
  for(const name of names) {
    if(!/^[A-Za-z0-9_.:-]{1,128}$/.test(name) || reserved.has(name.toLowerCase()))fail();
    const value=claimDescriptors[name].value;
    if(value!==null && typeof value!=='boolean') {
      if(typeof value==='number') {if(!Number.isFinite(value) || Math.abs(value)>Number.MAX_SAFE_INTEGER)fail();}
      else if(typeof value!=='string' || !value.length || Buffer.byteLength(value)>512
          || /[\x00-\x1f\x7f-\x9f]/.test(value) || Buffer.from(value).toString('utf8')!==value)fail();
    }
    claims[name]=value;
  }
  const body=JSON.stringify({...values,claims});if(Buffer.byteLength(body)>65536)fail();return body;
}
function decodeReceipt(body) {
  // Exact two-member JSON shape, either order; no duplicate/escaped names,
  // extra authority, coerced booleans, invalid UTF-8 or error body reflection.
  const whitespace='[ \t\r\n]*';
  for(const [first,second] of [['receipt_id','replayed'],['replayed','receipt_id']]) {
    const token=name=>name==='receipt_id'?'"([A-Za-z0-9_-]{1,128})"':'(true|false)';
    const pattern=new RegExp('^'+whitespace+'\\{'+whitespace+'"'+first+'"'+whitespace+':'+whitespace+token(first)
      +whitespace+','+whitespace+'"'+second+'"'+whitespace+':'+whitespace+token(second)+whitespace+'\\}'+whitespace+'$');
    const match=pattern.exec(body);
    if(match)return Object.freeze({receipt_id:match[first==='receipt_id'?1:2],replayed:match[first==='replayed'?1:2]==='true'});
  }
  throw new ObservationSubmissionError('submission_outcome_unknown');
}
/** One public Common Gateway operation only. Fresh organization API-key custody
 * per attempt; tenant derives from authenticated key, never a caller header.
 * No redirects, retries, cache, Canvas token, private core or issuance API.
 */
export function createObservationSubmitter(configuration={}) {
  const invalid=()=>new ObservationSubmissionError('invalid_submission_configuration');
  if(configuration===null || typeof configuration!=='object' || Array.isArray(configuration))throw invalid();
  const {gatewayOrigin,apiKeyProvider,ca,timeoutMs=15000}=configuration;
  let origin;try{origin=new URL(gatewayOrigin);}catch{throw invalid();}
  if(typeof globalThis.window!=='undefined' || Object.keys(configuration).some(name=>!['gatewayOrigin','apiKeyProvider','ca','timeoutMs'].includes(name))
      || origin.protocol!=='https:' || origin.origin!==gatewayOrigin || origin.pathname!=='/' || origin.username || origin.password
      || origin.search || origin.hash || origin.hostname.endsWith('.') || origin.hostname==='169.254.169.254'
      || /^(?:issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(origin.hostname)
      || /(?:\.svc|\.cluster\.local|\.internal)$/i.test(origin.hostname) || typeof apiKeyProvider?.getApiKey!=='function'
      || !Number.isSafeInteger(timeoutMs) || timeoutMs<50 || timeoutMs>120000
      || (ca!==undefined && (typeof ca!=='string' || !ca.includes('-----BEGIN CERTIFICATE-----') || ca.length>65536 || /PRIVATE KEY/.test(ca))))throw invalid();
  return Object.freeze({
    async submit(body) {
      let envelope;
      try {
        if(typeof body!=='string' || Buffer.byteLength(body)>65536)fail();
        envelope=JSON.parse(body);
        if(encodeExternalObservation(envelope)!==body)fail();
      } catch {throw new ObservationSubmissionError('invalid_observation');}
      const controller=new AbortController();let timer;let request;
      try {
        return await Promise.race([(async()=>{
          let apiKey;
          try {apiKey=await apiKeyProvider.getApiKey({signal:controller.signal});}
          catch {throw new ObservationSubmissionError('submission_outcome_unknown');}
          if(controller.signal.aborted || typeof apiKey!=='string' || !/^[A-Za-z0-9._~-]{32,512}$/.test(apiKey))
            throw new ObservationSubmissionError('submission_outcome_unknown');
          return await new Promise((resolve,reject)=>{
            if(controller.signal.aborted){reject(new ObservationSubmissionError('submission_outcome_unknown'));return;}
            let settled=false;
            const finish=(error,value)=>{
              if(settled)return;settled=true;
              if(error){request?.destroy();reject(error);}else resolve(value);
            };
            request=httpsRequest(new URL('/v1/evidence/observations',origin),{method:'POST',agent:false,
              rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,signal:controller.signal,...(ca===undefined?{}:{ca}),
              headers:{'Content-Type':'application/json',Accept:'application/json','Accept-Encoding':'identity',
                'Content-Length':Buffer.byteLength(body),'Idempotency-Key':envelope.observation_id,'X-API-Key':apiKey}},response=>{
              const unknown=()=>finish(new ObservationSubmissionError('submission_outcome_unknown'));
              response.on('error',unknown);response.on('aborted',unknown);
              const status=response.statusCode;
              if(status!==200)return finish(new ObservationSubmissionError(status>=400&&status<500?'submission_rejected':'submission_outcome_unknown',status));
              const count=name=>response.rawHeaders.filter((value,index)=>index%2===0&&value.toLowerCase()===name).length;
              if(count('content-type')!==1 || count('content-encoding')>1
                  || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(String(response.headers['content-type']??''))
                  || !['','identity'].includes(String(response.headers['content-encoding']??'')))return unknown();
              let size=0;const chunks=[];
              response.on('data',chunk=>{size+=chunk.length;if(size>2048)return unknown();if(!settled)chunks.push(chunk);});
              response.on('end',()=>{
                if(settled)return;
                try {
                  if(!response.complete)throw new Error();
                  finish(null,decodeReceipt(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))));
                } catch {unknown();}
              });
            });
            request.on('error',()=>finish(new ObservationSubmissionError('submission_outcome_unknown')));request.end(body);
          });
        })(),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();request?.destroy();reject(new ObservationSubmissionError('submission_outcome_unknown'));},timeoutMs);})]);
      } catch(error) {
        const status=error instanceof ObservationSubmissionError&&Number.isInteger(error.status)&&error.status>=300&&error.status<=599?error.status:undefined;
        throw new ObservationSubmissionError(error instanceof ObservationSubmissionError&&error.code==='submission_rejected'&&status>=400&&status<500
          ?'submission_rejected':'submission_outcome_unknown',status);
      } finally {clearTimeout(timer);controller.abort();}
    },
  });
}
