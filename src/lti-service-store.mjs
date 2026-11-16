// SPDX-License-Identifier: AGPL-3.0-only
import { createCipheriv,createDecipheriv,createHmac,randomBytes,randomUUID,timingSafeEqual } from 'node:crypto';
import { ltiId,ltiUuid } from './lti-registration-contract.mjs';
import { ltiServiceExact,ltiServiceScopes,ltiServiceCommand,ltiServiceHandle,ltiServiceAttempt,ltiServiceReceipt } from './lti-service-contract.mjs';

const unavailable=()=>{throw Error('lti_service_store_unavailable');};
const bearer=value=>typeof value==='string'&&/^[A-Za-z0-9._~+/-]{16,16384}={0,2}$/.test(value);
function keyCopy(value) {if(!Buffer.isBuffer(value)||value.length!==32)unavailable();return Buffer.from(value);}
function identity(a) {return [a.organizationId,a.operationId,a.platformId,a.registrationId,a.actorId,a.platformVersion,
 a.registrationVersion,a.keyVersion,a.kid,a.clientId,a.canvasOrigin,a.toolOrigin,a.scopes,a.dispatchId,a.issuedAt,a.expiresAt];}
function tokenContext(a,row) {return Buffer.from(JSON.stringify([1,'canvas-lti-service-token',identity(a),row.reference,
 row.scopes,row.expiresAtMs,row.wrappingKeyId]));}
function digest(key,a,row,plaintext) {
 const derived=createHmac('sha256',key).update('canvas-lti-service-token-input-key/v1').digest();
 try {return createHmac('sha256',derived).update(JSON.stringify([1,identity(a),row.scopes,row.expiresAtMs])+'\n').update(plaintext).digest();}
 finally {derived.fill(0);}
}
function tokenRow(value,a) {
 ltiServiceExact(value,['reference','scopes','expiresAtMs','wrappingKeyId','inputDigest','ciphertext','nonce','tag']);
 const scopes=ltiServiceScopes(value.scopes);
 if(!ltiUuid(value.reference)||!ltiId(value.wrappingKeyId)||scopes.some(item=>!a.scopes.includes(item))
  ||!Number.isSafeInteger(value.expiresAtMs)||value.expiresAtMs<=a.issuedAt*1000||value.expiresAtMs>(a.issuedAt+86400)*1000
  ||!Buffer.isBuffer(value.inputDigest)||value.inputDigest.length!==32
  ||!Buffer.isBuffer(value.ciphertext)||value.ciphertext.length<16||value.ciphertext.length>16386
  ||!Buffer.isBuffer(value.nonce)||value.nonce.length!==12||!Buffer.isBuffer(value.tag)||value.tag.length!==16)unavailable();
 return {...value,scopes};
}
export function createLtiServiceStore({pool,keyProvider}={}) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function'||typeof keyProvider?.current!=='function'||typeof keyProvider?.byId!=='function')unavailable();
 async function rows(sql,values) {const result=await pool.query(sql,values);if(!Array.isArray(result?.rows))unavailable();return result.rows;}
 async function one(sql,values) {const result=await rows(sql,values);if(result.length!==1||!Object.hasOwn(result[0],'result'))unavailable();return result[0].result;}
 async function inspect(input) {
  const value=await one(`SELECT (SELECT canvas_connector.lti_service_attempt_view(a) FROM canvas_connector.lti_service_attempts a
    WHERE organization_id=$1 AND operation_id=$2::uuid) AS result`,[input.organizationId,input.operationId]);
  if(value===null)return null;const a=ltiServiceAttempt(value);
  if(a.organizationId!==input.organizationId||a.operationId!==input.operationId)unavailable();return a;
 }
 async function load(a) {
  const result=await rows(`SELECT reference,granted_scopes AS scopes,(extract(epoch FROM expires_at)*1000)::float8 AS "expiresAtMs",
    wrapping_key_id AS "wrappingKeyId",input_digest AS "inputDigest",ciphertext,nonce,tag FROM canvas_connector.lti_service_tokens
    WHERE organization_id=$1 AND operation_id=$2::uuid`,[a.organizationId,a.operationId]);
  if(result.length>1)unavailable();return result.length===0?null:tokenRow(result[0],a);
 }
 async function publishedCurrent(a) {
  const result=await one(`SELECT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts a JOIN canvas_connector.lti_service_tokens t
    ON t.organization_id=a.organization_id AND t.operation_id=a.operation_id AND t.reference=a.token_reference
    WHERE a.organization_id=$1 AND a.operation_id=$2::uuid AND a.phase='published' AND t.expires_at>clock_timestamp()
     AND canvas_connector.lti_service_attempt_current(a)) AS result`,[a.organizationId,a.operationId]);
  if(typeof result!=='boolean')unavailable();return result;
 }
 return Object.freeze({
  async inspect(value) {try{return await inspect(ltiServiceHandle(value));}catch{unavailable();}},
  async prepare(value) {
   try {
    const input=ltiServiceCommand(value);
    const result=await one('SELECT canvas_connector.prepare_lti_service_attempt($1,$2,$3::uuid,$4::uuid,$5,$6::bigint,$7::bigint,$8::bigint,$9::text[]) AS result',
     [input.organizationId,input.platformId,input.registrationId,input.operationId,input.actorId,input.expectedPlatformVersion,
      input.expectedRegistrationVersion,input.expectedKeyVersion,input.scopes]);
    if(result===null)return null;const a=ltiServiceAttempt(result);
    if(a.organizationId!==input.organizationId||a.platformId!==input.platformId||a.registrationId!==input.registrationId||a.operationId!==input.operationId
     ||a.actorId!==input.actorId||a.platformVersion!==input.expectedPlatformVersion||a.registrationVersion!==input.expectedRegistrationVersion
     ||a.keyVersion!==input.expectedKeyVersion||JSON.stringify(a.scopes)!==JSON.stringify(input.scopes))unavailable();return a;
   }catch{unavailable();}
  },
  async begin(value) {
   try {
    const h=ltiServiceHandle(value,true),result=await one('SELECT canvas_connector.begin_lti_service_exchange($1,$2::uuid,$3::uuid) AS result',
     [h.organizationId,h.operationId,h.dispatchId]);
    if(result===null)return null;const a=ltiServiceAttempt(result);
    if(a.organizationId!==h.organizationId||a.operationId!==h.operationId||a.dispatchId!==h.dispatchId||a.phase!=='exchanging')unavailable();return a;
   }catch{unavailable();}
  },
  async permitDispatch(value) {
   try {
    const h=ltiServiceHandle(value,true),result=await one(`SELECT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts a
      WHERE organization_id=$1 AND operation_id=$2::uuid AND dispatch_id=$3::uuid AND phase='exchanging'
       AND to_timestamp(assertion_expires_at)>clock_timestamp() AND canvas_connector.lti_service_attempt_current(a)) AS result`,
    [h.organizationId,h.operationId,h.dispatchId]);if(typeof result!=='boolean')unavailable();return result;
   }catch{unavailable();}
  },
  async uncertain(value) {
   try {const h=ltiServiceHandle(value,true),result=await one('SELECT canvas_connector.mark_lti_service_uncertain($1,$2::uuid,$3::uuid) AS result',
    [h.organizationId,h.operationId,h.dispatchId]);if(typeof result!=='boolean')unavailable();return result;}catch{unavailable();}
  },
  async stage(value,bundle,expiresAtMs) {
   let key,plaintext,computed;
   try {
    const supplied=ltiServiceAttempt(value);ltiServiceExact(bundle,['accessToken','scopes']);
    const scopes=ltiServiceScopes(bundle.scopes),accessToken=bundle.accessToken;
    if(!bearer(accessToken)||supplied.dispatchId===null||scopes.some(scope=>!supplied.scopes.includes(scope))
     ||!Number.isSafeInteger(expiresAtMs)||expiresAtMs<=supplied.issuedAt*1000||expiresAtMs>(supplied.issuedAt+86400)*1000)unavailable();
    let a=await inspect({organizationId:supplied.organizationId,operationId:supplied.operationId});
    if(a===null||JSON.stringify(identity(a))!==JSON.stringify(identity(supplied))||!['exchanging','uncertain','staged','published'].includes(a.phase))unavailable();
    plaintext=Buffer.from(accessToken);
    const prior=await load(a);
    if(prior!==null) {
     // Another staging writer may have committed between the attempt and
     // ciphertext reads. Reconcile its associated original attempt first.
     a=await inspect({organizationId:supplied.organizationId,operationId:supplied.operationId});
     if(a===null||JSON.stringify(identity(a))!==JSON.stringify(identity(supplied)))unavailable();
     if(!['staged','published'].includes(a.phase)||a.tokenReference!==prior.reference)unavailable();
     key=keyCopy(await keyProvider.byId(prior.wrappingKeyId));computed=digest(key,a,{scopes,expiresAtMs},plaintext);
     if(prior.expiresAtMs!==expiresAtMs||JSON.stringify(prior.scopes)!==JSON.stringify(scopes)||!timingSafeEqual(computed,prior.inputDigest))return null;
     return a;
    }
    const selected=await keyProvider.current();if(!ltiId(selected?.id))unavailable();key=keyCopy(selected.key);
    const row={reference:randomUUID(),scopes,expiresAtMs,wrappingKeyId:selected.id};computed=digest(key,a,row,plaintext);
    const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});cipher.setAAD(tokenContext(a,row));
    const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
    const result=await one(`SELECT canvas_connector.stage_lti_service_token($1,$2::uuid,$3::uuid,$4::uuid,$5::text[],to_timestamp($6::float8/1000),$7,$8,$9,$10,$11) AS result`,
     [a.organizationId,a.operationId,a.dispatchId,row.reference,scopes,expiresAtMs,row.wrappingKeyId,computed,ciphertext,nonce,cipher.getAuthTag()]);
    if(result===null)return null;const staged=ltiServiceAttempt(result);
    if(JSON.stringify(identity(staged))!==JSON.stringify(identity(a))||!['staged','published'].includes(staged.phase))unavailable();return staged;
   }catch{unavailable();}finally{key?.fill(0);plaintext?.fill(0);computed?.fill(0);}
  },
  async publish(value) {
   try {
    const h=ltiServiceHandle(value,true),a=await inspect(h);
    if(a===null||a.dispatchId!==h.dispatchId)return null;
    const result=await one('SELECT canvas_connector.publish_lti_service_token($1,$2::uuid,$3::uuid) AS result',[h.organizationId,h.operationId,h.dispatchId]);
    if(result===null)return null;
    const saved=await inspect(h);if(saved===null||saved.phase!=='published')unavailable();
    const decoded=ltiServiceReceipt(result,saved);if(JSON.stringify(decoded)!==JSON.stringify(saved.receipt))unavailable();return decoded;
   }catch{unavailable();}
  },
  async currentToken(value) {
   let key,partial,plaintext,computed;
   try {
    const h=ltiServiceHandle(value),a=await inspect(h);
    if(a===null||a.phase!=='published'||!await publishedCurrent(a))return null;
    const row=await load(a);
    if(row===null||row.reference!==a.tokenReference||row.expiresAtMs!==a.receipt.expiresAtMs
     ||JSON.stringify(row.scopes)!==JSON.stringify(a.receipt.scopes))unavailable();
    key=keyCopy(await keyProvider.byId(row.wrappingKeyId));
    const decipher=createDecipheriv('aes-256-gcm',key,row.nonce,{authTagLength:16});decipher.setAAD(tokenContext(a,row));decipher.setAuthTag(row.tag);
    partial=decipher.update(row.ciphertext);plaintext=Buffer.concat([partial,decipher.final()]);
    computed=digest(key,a,row,plaintext);if(!timingSafeEqual(computed,row.inputDigest))unavailable();
    const accessToken=new TextDecoder('utf-8',{fatal:true}).decode(plaintext);if(!bearer(accessToken))unavailable();
    if(!await publishedCurrent(a))return null;
    if(row.expiresAtMs<=Date.now())return null;
    return Object.freeze({accessToken,scopes:row.scopes,expiresAtMs:row.expiresAtMs});
   }catch{unavailable();}finally{key?.fill(0);partial?.fill(0);plaintext?.fill(0);computed?.fill(0);}
  },
 });
}
