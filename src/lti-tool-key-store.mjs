// SPDX-License-Identifier: AGPL-3.0-only
import { createCipheriv, createDecipheriv, createPublicKey, randomBytes } from 'node:crypto';
import { exactRecord } from './canvas-rest-contract.mjs';
import { ltiId, ltiUuid, ltiVersion } from './lti-registration-contract.mjs';
import { generateLtiToolKey, prepareLtiToolKey } from './lti-tool-assertion.mjs';

const unavailable=()=>{throw Error('lti_tool_key_store_unavailable');};
function exact(value,names) {
  exactRecord(value,names,'invalid_lti_tool_key');if(Object.keys(value).length!==names.length)unavailable();
}
function scope(value) {
  if(!ltiId(value.organizationId)||!ltiId(value.platformId)||!ltiUuid(value.registrationId))unavailable();
}
function publicJwk(value,kid) {
  exact(value,['kty','n','e','kid','alg','use']);
  if(value.kty!=='RSA'||value.e!=='AQAB'||value.kid!==kid||!ltiUuid(kid)||value.alg!=='RS256'||value.use!=='sig'
    ||typeof value.n!=='string'||!/^[A-Za-z0-9_-]{342,683}$/.test(value.n))unavailable();
  const key=createPublicKey({key:value,format:'jwk'});
  if(key.asymmetricKeyType!=='rsa'||![2048,3072,4096].includes(key.asymmetricKeyDetails?.modulusLength)
    ||key.asymmetricKeyDetails?.publicExponent!==65537n)unavailable();
  return Object.freeze({kty:'RSA',n:value.n,e:'AQAB',kid,alg:'RS256',use:'sig'});
}
function command(value) {
  exact(value,['organizationId','platformId','registrationId','operationId','actorId','action',
    'expectedPlatformVersion','expectedRegistrationVersion','expectedKeyVersion']);scope(value);
  if(!ltiUuid(value.operationId)||!ltiId(value.actorId)||!['provision','rotate','deactivate'].includes(value.action))unavailable();
  if(value.action==='deactivate' ? value.expectedPlatformVersion!==null||value.expectedRegistrationVersion!==null
    : !ltiVersion(value.expectedPlatformVersion)||!ltiVersion(value.expectedRegistrationVersion))unavailable();
  if(value.action==='provision' ? value.expectedKeyVersion!==null
    : !ltiVersion(value.expectedKeyVersion)||value.expectedKeyVersion>=Number.MAX_SAFE_INTEGER)unavailable();
  return Object.freeze({...value});
}
function intent(value) {return {action:value.action,expectedPlatformVersion:value.expectedPlatformVersion,
  expectedRegistrationVersion:value.expectedRegistrationVersion,expectedKeyVersion:value.expectedKeyVersion};}
function receipt(value,input) {
  exact(value,['operationId','actorId','action','platformId','registrationId','version','kid','publicJwk']);
  if(value.operationId!==input.operationId||value.actorId!==input.actorId||value.action!==input.action
    ||value.platformId!==input.platformId||value.registrationId!==input.registrationId
    ||value.version!==(input.action==='provision'?1:input.expectedKeyVersion+1))unavailable();
  if(input.action==='deactivate') {
    if(value.kid!==null||value.publicJwk!==null)unavailable();return Object.freeze({...value});
  }
  return Object.freeze({...value,publicJwk:publicJwk(value.publicJwk,value.kid)});
}
function keyCopy(value) {if(!Buffer.isBuffer(value)||value.length!==32)unavailable();return Buffer.from(value);}
function aad(value) {
  const j=value.publicJwk;
  return Buffer.from(JSON.stringify([1,'canvas-lti-tool-private-key',value.organizationId,value.platformId,value.registrationId,
    value.kid,value.platformVersion,value.registrationVersion,value.clientId,value.toolOrigin,
    [j.kty,j.n,j.e,j.kid,j.alg,j.use],value.wrappingKeyId]));
}

// Internal connector-only adapter. Public administrator authorization and
// runtime role preflight must be composed before this is mounted anywhere.
export function createLtiToolKeyStore({pool,keyProvider}={}) {
  if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function'
    ||typeof keyProvider?.current!=='function'||typeof keyProvider?.byId!=='function')unavailable();
  async function query(sql,values) {
    const result=await pool.query(sql,values);if(!Array.isArray(result?.rows))unavailable();return result.rows;
  }
  return Object.freeze({
    async administer(value,beforeCommit) {
      let key,plaintext;
      try {
        if(beforeCommit!==undefined&&typeof beforeCommit!=='function')unavailable();
        const input=command(value),parameters=[input.organizationId,input.platformId,input.registrationId,input.operationId,input.actorId];
        const prior=await query(`SELECT platform_id AS "platformId",registration_id AS "registrationId",actor_id AS "actorId",request,receipt
          FROM canvas_connector.lti_tool_key_operation_audit WHERE organization_id=$1 AND operation_id=$2::uuid`,
        [input.organizationId,input.operationId]);
        if(prior.length>1)unavailable();
        if(prior.length) {
          const old=prior[0];
          if(old.platformId!==input.platformId||old.registrationId!==input.registrationId||old.actorId!==input.actorId
            ||JSON.stringify(intent(old.request))!==JSON.stringify(intent(input)))return null;
          return receipt(old.receipt,input);
        }
        let generated=null,sealed=null,metadata=null;
        if(input.action!=='deactivate') {
          const rows=await query(`SELECT p.config_version::float8 AS "platformVersion",r.version::float8 AS "registrationVersion",
            r.client_id AS "clientId",r.target_link_uri AS "targetLinkUri" FROM canvas_connector.platforms p
            JOIN canvas_connector.lti_registrations r ON r.organization_id=p.organization_id AND r.platform_id=p.id
            WHERE p.organization_id=$1 AND p.id=$2 AND r.id=$3::uuid AND p.enabled AND NOT p.archived`,parameters.slice(0,3));
          if(rows.length===0)return null;if(rows.length!==1)unavailable();const row=rows[0];
          if(row.platformVersion!==input.expectedPlatformVersion||row.registrationVersion!==input.expectedRegistrationVersion)return null;
          const target=new URL(row.targetLinkUri);
          if(typeof row.clientId!=='string'||!/^[\x21-\x7e]{1,255}$/.test(row.clientId)||target.protocol!=='https:'
            ||row.targetLinkUri!==target.origin+`/lti/registrations/${input.registrationId}/resource`)unavailable();
          generated=generateLtiToolKey();
          const selected=await keyProvider.current();if(!ltiId(selected?.id))unavailable();key=keyCopy(selected.key);
          metadata={organizationId:input.organizationId,platformId:input.platformId,registrationId:input.registrationId,
            kid:generated.kid,platformVersion:row.platformVersion,registrationVersion:row.registrationVersion,
            clientId:row.clientId,toolOrigin:target.origin,publicJwk:generated.publicJwk,wrappingKeyId:selected.id};
          plaintext=Buffer.from(generated.privateKeyPem);const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});
          cipher.setAAD(aad(metadata));sealed={nonce,ciphertext:Buffer.concat([cipher.update(plaintext),cipher.final()]),tag:cipher.getAuthTag()};
        }
        if(beforeCommit!==undefined&&await beforeCommit()!==true)return null;
        const rows=await query(`SELECT canvas_connector.administer_lti_tool_key($1,$2,$3::uuid,$4::uuid,$5,
          $6,$7::bigint,$8::bigint,$9::bigint,$10::uuid,$11::jsonb,$12,$13,$14,$15) AS receipt`,
        [...parameters,input.action,input.expectedPlatformVersion,input.expectedRegistrationVersion,input.expectedKeyVersion,
          generated?.kid??null,generated===null?null:JSON.stringify(generated.publicJwk),metadata?.wrappingKeyId??null,
          sealed?.ciphertext??null,sealed?.nonce??null,sealed?.tag??null]);
        if(rows.length!==1||!Object.hasOwn(rows[0],'receipt'))unavailable();
        return rows[0].receipt===null?null:receipt(rows[0].receipt,input);
      }catch{unavailable();}finally{key?.fill(0);plaintext?.fill(0);}
    },
    async inspect(value) {
      try {
        exact(value,['organizationId','platformId','registrationId']);scope(value);
        const rows=await query(`SELECT version::float8 AS version,current_kid AS "kid" FROM canvas_connector.lti_tool_key_configurations
          WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid`,[value.organizationId,value.platformId,value.registrationId]);
        if(rows.length===0)return null;if(rows.length!==1)unavailable();exact(rows[0],['version','kid']);
        if(!ltiVersion(rows[0].version)||(rows[0].kid!==null&&!ltiUuid(rows[0].kid)))unavailable();
        return Object.freeze({...rows[0]});
      }catch{unavailable();}
    },
    async receipt(value) {
      try {
        exact(value,['organizationId','platformId','registrationId','operationId']);scope(value);if(!ltiUuid(value.operationId))unavailable();
        const rows=await query(`SELECT actor_id AS "actorId",request,receipt FROM canvas_connector.lti_tool_key_operation_audit
          WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND operation_id=$4::uuid`,
        [value.organizationId,value.platformId,value.registrationId,value.operationId]);
        if(rows.length===0)return null;if(rows.length!==1)unavailable();const old=rows[0];
        const expected=command({...value,actorId:old.actorId,...old.request});return receipt(old.receipt,expected);
      }catch{unavailable();}
    },
    async publicKeys(registrationId) {
      try {
        if(!ltiUuid(registrationId))unavailable();
        const rows=await query(`SELECT canvas_connector.lti_tool_public_keys(id) AS keys FROM canvas_connector.lti_registrations WHERE id=$1::uuid`,[registrationId]);
        if(rows.length===0)return null;if(rows.length!==1||!Array.isArray(rows[0].keys)||rows[0].keys.length>8)unavailable();
        const keys=rows[0].keys.map(value=>publicJwk(value,value.kid));if(new Set(keys.map(value=>value.kid)).size!==keys.length)unavailable();
        return Object.freeze({keys:Object.freeze(keys)});
      }catch{unavailable();}
    },
    async current(value) {
      let key,partial,plaintext;
      try {
        exact(value,['organizationId','platformId','registrationId','expectedPlatformVersion','expectedRegistrationVersion','expectedKeyVersion']);
        scope(value);if(![value.expectedPlatformVersion,value.expectedRegistrationVersion,value.expectedKeyVersion].every(ltiVersion))unavailable();
        const input={...value};
        const selection=`SELECT k.kid,k.platform_version::float8 AS "platformVersion",k.registration_version::float8 AS "registrationVersion",
          k.client_id AS "clientId",k.tool_origin AS "toolOrigin",k.public_jwk AS "publicJwk",k.wrapping_key_id AS "wrappingKeyId",k.ciphertext,k.nonce,k.tag
          FROM canvas_connector.lti_tool_key_configurations c
          JOIN canvas_connector.lti_tool_keys k ON k.organization_id=c.organization_id AND k.platform_id=c.platform_id
            AND k.registration_id=c.registration_id AND k.kid=c.current_kid
          JOIN canvas_connector.platforms p ON p.organization_id=k.organization_id AND p.id=k.platform_id
          JOIN canvas_connector.lti_registrations r ON r.organization_id=k.organization_id AND r.platform_id=k.platform_id AND r.id=k.registration_id
          WHERE c.organization_id=$1 AND c.platform_id=$2 AND c.registration_id=$3::uuid AND c.version=$4::bigint
            AND p.config_version=$5::bigint AND r.version=$6::bigint AND p.enabled AND NOT p.archived AND r.enabled
            AND k.platform_version=p.config_version AND k.registration_version=r.version AND k.client_id=r.client_id
            AND r.target_link_uri=k.tool_origin||'/lti/registrations/'||r.id::text||'/resource'`;
        const parameters=[input.organizationId,input.platformId,input.registrationId,input.expectedKeyVersion,input.expectedPlatformVersion,input.expectedRegistrationVersion];
        const rows=await query(selection,parameters);
        if(rows.length===0)return null;if(rows.length!==1)unavailable();const row=rows[0];
        if(row.platformVersion!==input.expectedPlatformVersion||row.registrationVersion!==input.expectedRegistrationVersion
          ||!ltiId(row.wrappingKeyId)||!Buffer.isBuffer(row.ciphertext)||row.ciphertext.length<1||row.ciphertext.length>8192
          ||!Buffer.isBuffer(row.nonce)||row.nonce.length!==12||!Buffer.isBuffer(row.tag)||row.tag.length!==16)unavailable();
        exact(row,['kid','platformVersion','registrationVersion','clientId','toolOrigin','publicJwk','wrappingKeyId','ciphertext','nonce','tag']);
        const jwk=publicJwk(row.publicJwk,row.kid);key=keyCopy(await keyProvider.byId(row.wrappingKeyId));
        const decipher=createDecipheriv('aes-256-gcm',key,row.nonce,{authTagLength:16});
        decipher.setAAD(aad({...input,...row,publicJwk:jwk}));decipher.setAuthTag(row.tag);
        partial=decipher.update(row.ciphertext);plaintext=Buffer.concat([partial,decipher.final()]);
        const privateKeyPem=new TextDecoder('utf-8',{fatal:true}).decode(plaintext),prepared=prepareLtiToolKey({kid:row.kid,privateKeyPem});
        if(JSON.stringify(prepared.publicJwk)!==JSON.stringify(jwk))unavailable();
        // Bao lookup may have stalled across disable/configuration changes.
        // This is still a snapshot, never an authorization to dispatch: the
        // durable signing attempt must independently fence these revisions.
        const latest=await query(selection,parameters);
        if(latest.length===0)return null;
        if(latest.length!==1||latest[0].kid!==row.kid)unavailable();
        return Object.freeze({kid:row.kid,privateKeyPem,publicJwk:jwk,clientId:row.clientId,toolOrigin:row.toolOrigin,
          platformVersion:row.platformVersion,registrationVersion:row.registrationVersion,keyVersion:input.expectedKeyVersion});
      }catch{unavailable();}finally{key?.fill(0);partial?.fill(0);plaintext?.fill(0);}
    },
  });
}
