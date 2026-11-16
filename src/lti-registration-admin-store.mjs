// SPDX-License-Identifier: AGPL-3.0-only
import { exactRecord } from './canvas-rest-contract.mjs';
import { canvasOrigin } from './canvas-rest-network.mjs';
import { ltiId,ltiUuid,ltiVersion,ltiRegistrationDefinition,ltiRegistrationIntent } from './lti-registration-contract.mjs';

const unavailable=()=>{throw Error('lti_registration_admin_unavailable');};
function exact(value,names) {
  exactRecord(value,names,'invalid_lti_registration');if(Object.keys(value).length!==names.length) unavailable();
}
function scope(value) {
  if(!ltiId(value.organizationId) || !ltiId(value.platformId)) unavailable();
}
function row(value,registrationId) {
  exact(value,['registrationId','platformId','version','enabled','definition']);
  if(!ltiUuid(value.registrationId) || (registrationId!==undefined && value.registrationId!==registrationId) ||
    !ltiId(value.platformId) || !ltiVersion(value.version) || typeof value.enabled!=='boolean') unavailable();
  return Object.freeze({...value,definition:ltiRegistrationDefinition(value.definition,value.registrationId)});
}
function receipt(value,registrationId) {
  exact(value,['operationId','actorId','action','registrationId','platformId','version','enabled','definition']);
  if(!ltiUuid(value.operationId) || !ltiId(value.actorId) || !['create','replace','activate','deactivate'].includes(value.action)) unavailable();
  row({registrationId:value.registrationId,platformId:value.platformId,version:value.version,enabled:value.enabled,definition:value.definition},registrationId);
  return Object.freeze({...value,definition:ltiRegistrationDefinition(value.definition,value.registrationId)});
}
const selection=`jsonb_build_object('registrationId',r.id,'platformId',r.platform_id,'version',r.version,'enabled',r.enabled,
 'definition',jsonb_build_object('clientId',r.client_id,'deploymentId',r.deployment_id,'trustProfile',r.trust_profile,
 'environment',r.environment,'targetLinkUri',r.target_link_uri))`;
function command(value) {
  exact(value,['organizationId','platformId','registrationId','operationId','actorId','action','expectedPlatformVersion','expectedRegistrationVersion','definition']);
  scope(value);if(!ltiUuid(value.registrationId) || !ltiUuid(value.operationId) || !ltiId(value.actorId)) unavailable();
  return ltiRegistrationIntent({action:value.action,expectedPlatformVersion:value.expectedPlatformVersion,
    expectedRegistrationVersion:value.expectedRegistrationVersion,definition:value.definition},value.registrationId);
}
export function createLtiRegistrationAdminStore(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') unavailable();
  async function query(sql,values,decode) {
    try{const result=await pool.query(sql,values);if(result?.rows?.length!==1 || !Object.hasOwn(result.rows[0],'result')) unavailable();
      return result.rows[0].result===null?null:decode(result.rows[0].result);
    }catch{unavailable();}
  }
  return Object.freeze({
    async platform(value) {
      scope(value);
      return query(`SELECT (SELECT jsonb_build_object('platformId',p.id,'canvasOrigin',p.canvas_origin,'configVersion',p.config_version,
       'enabled',p.enabled,'archived',p.archived) FROM canvas_connector.platforms p WHERE organization_id=$1 AND id=$2) AS result`,[value.organizationId,value.platformId],item=>{
        exact(item,['platformId','canvasOrigin','configVersion','enabled','archived']);
        if(item.platformId!==value.platformId || !ltiVersion(item.configVersion) || typeof item.enabled!=='boolean' || typeof item.archived!=='boolean' || canvasOrigin(item.canvasOrigin)!==item.canvasOrigin) unavailable();
        return Object.freeze(item);
      });
    },
    async catalog(value) {
      scope(value);if(value.afterId!==undefined && !ltiUuid(value.afterId)) unavailable();
      const rows=await query(`SELECT COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb) AS result FROM
       (SELECT r.id,${selection} AS item FROM canvas_connector.lti_registrations r WHERE r.organization_id=$1 AND r.platform_id=$2
        AND ($3::uuid IS NULL OR r.id>$3::uuid) ORDER BY r.id LIMIT 21) page`,[value.organizationId,value.platformId,value.afterId??null],items=>{
        if(!Array.isArray(items) || items.length>21) unavailable();return items.map(item=>{
          const decoded=row(item);if(decoded.platformId!==value.platformId) unavailable();return decoded;
        });
      });
      return Object.freeze({registrations:Object.freeze(rows.slice(0,20)),nextCursor:rows.length>20?rows[19].registrationId:null});
    },
    async inspect(value) {
      scope(value);if(!ltiUuid(value.registrationId)) unavailable();
      return query(`SELECT (SELECT ${selection} FROM canvas_connector.lti_registrations r
       WHERE r.organization_id=$1 AND r.platform_id=$2 AND r.id=$3::uuid) AS result`,[value.organizationId,value.platformId,value.registrationId],item=>{
        const decoded=row(item,value.registrationId);if(decoded.platformId!==value.platformId) unavailable();return decoded;
      });
    },
    async receipt(value) {
      scope(value);if(!ltiUuid(value.registrationId) || !ltiUuid(value.operationId)) unavailable();
      return query(`SELECT (SELECT receipt FROM canvas_connector.lti_registration_operation_audit WHERE
       organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND operation_id=$4::uuid) AS result`,
      [value.organizationId,value.platformId,value.registrationId,value.operationId],item=>{
        const decoded=receipt(item,value.registrationId);if(decoded.platformId!==value.platformId || decoded.operationId!==value.operationId) unavailable();return decoded;
      });
    },
    async replay(value) {
      const intent=command(value),{organizationId,platformId,registrationId,operationId,actorId,action}=value;
      return query(`SELECT (SELECT jsonb_build_object('platformId',platform_id,'registrationId',registration_id,'actorId',actor_id,
       'action',action,'request',request,'receipt',receipt) FROM canvas_connector.lti_registration_operation_audit
       WHERE organization_id=$1 AND operation_id=$2::uuid) AS result`,[organizationId,operationId],item=>{
        exact(item,['platformId','registrationId','actorId','action','request','receipt']);
        const previous=receipt(item.receipt,item.registrationId),priorIntent=ltiRegistrationIntent(item.request,item.registrationId);
        if(previous.platformId!==item.platformId || previous.actorId!==item.actorId || previous.action!==item.action || previous.operationId!==operationId) unavailable();
        const conflict=item.platformId!==platformId || item.registrationId!==registrationId || item.actorId!==actorId || item.action!==action || JSON.stringify(intent)!==JSON.stringify(priorIntent);
        return Object.freeze(conflict?{conflict:true}:{conflict:false,receipt:previous});
      });
    },
    async apply(value) {
      const intent=command(value),{organizationId,platformId,actorId,operationId,registrationId}=value;
      return query('SELECT canvas_connector.administer_lti_registration($1,$2,$3,$4::uuid,$5::uuid,$6,$7::bigint,$8::bigint,$9::jsonb) AS result',
        [organizationId,platformId,actorId,operationId,registrationId,intent.action,intent.expectedPlatformVersion,intent.expectedRegistrationVersion,
          intent.definition===null?null:JSON.stringify(intent.definition)],item=>{
          const decoded=receipt(item,registrationId),expectedVersion=intent.action==='create'?1:intent.expectedRegistrationVersion+1;
          if(decoded.operationId!==operationId || decoded.actorId!==actorId || decoded.platformId!==platformId || decoded.action!==intent.action ||
            decoded.version!==expectedVersion || decoded.enabled!==(intent.action==='activate') ||
            (intent.definition!==null && JSON.stringify(decoded.definition)!==JSON.stringify(intent.definition))) unavailable();
          return decoded;
        });
    },
  });
}
