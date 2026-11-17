// SPDX-License-Identifier: AGPL-3.0-only
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {ltiServiceExact} from './lti-service-contract.mjs';
import {prepareLtiCaptureRouteIntent} from './lti-capture-contract.mjs';
import {ltiCaptureAdminScope,ltiCaptureAdminCommand,ltiCaptureAdminReceipt} from './lti-capture-admin-contract.mjs';
import {createPlatformAdminStore} from './platform-admin.mjs';
const fail=()=>{throw Error('lti_capture_admin_unavailable');};
const selected=`jsonb_build_object('routeId',id,'version',version,'enabled',enabled,'serviceOperationId',service_operation_id,'definition',definition)`;
function route(value,context) {
 ltiServiceExact(value,['routeId','version','enabled','serviceOperationId','definition']);
 if(!ltiId(value.routeId)||!ltiVersion(value.version)||typeof value.enabled!=='boolean'||!ltiUuid(value.serviceOperationId))fail();
 const definition=prepareLtiCaptureRouteIntent(value.definition);
 if(definition.platformId!==context.platformId||definition.registrationId!==context.registrationId)fail();
 return Object.freeze({...value,definition});
}
export function createLtiCaptureAdminStore(pool) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')fail();
 const platforms=createPlatformAdminStore(pool);
 async function one(sql,values) {
  try {const result=await pool.query(sql,values);if(result?.rows?.length!==1||Object.keys(result.rows[0]).join(',')!=='result'||result.rows[0].result===undefined)fail();return result.rows[0].result;}
  catch{fail();}
 }
 return Object.freeze({
  platform:value=>platforms.inspect(value),
  async catalog(value) {
   ltiServiceExact(value,['organizationId','platformId','registrationId',...value?.afterId===undefined?[]:['afterId']]);
   const v={...value};if(!ltiId(v.organizationId)||!ltiId(v.platformId)||!ltiUuid(v.registrationId)||v.afterId!==undefined&&!ltiId(v.afterId))fail();
   const rows=await one(`SELECT COALESCE(jsonb_agg(item ORDER BY id COLLATE "C"),'[]'::jsonb) AS result FROM
    (SELECT id,${selected} AS item FROM canvas_connector.lti_capture_routes WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid
     AND ($4::text IS NULL OR id COLLATE "C">$4 COLLATE "C") ORDER BY id COLLATE "C" LIMIT 21) page`,[v.organizationId,v.platformId,v.registrationId,v.afterId??null]);
   if(!Array.isArray(rows)||rows.length>21)fail();const items=rows.map(item=>route(item,v));
   return Object.freeze({routes:Object.freeze(items.slice(0,20)),nextCursor:items.length>20?items[19].routeId:null});
  },
  async inspect(value) {
   const v=ltiCaptureAdminScope(value),found=await one(`SELECT (SELECT ${selected} FROM canvas_connector.lti_capture_routes
    WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND id=$4) AS result`,[v.organizationId,v.platformId,v.registrationId,v.routeId]);
   if(found===null)return null;const decoded=route(found,v);if(decoded.routeId!==v.routeId)fail();return decoded;
  },
  async receipt(value) {
   const v=ltiCaptureAdminScope(value),operationId=value.operationId;if(!ltiUuid(operationId))fail();
   const found=await one(`SELECT (SELECT receipt FROM canvas_connector.lti_capture_operation_audit
    WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND route_id=$4 AND operation_id=$5::uuid) AS result`,
    [v.organizationId,v.platformId,v.registrationId,v.routeId,operationId]);
   return found===null?null:ltiCaptureAdminReceipt(found,{...v,operationId});
  },
  async replay(value) {
   const v=ltiCaptureAdminCommand(value),found=await one(`SELECT (SELECT jsonb_build_object('matching',
    platform_id=$2 AND registration_id=$3::uuid AND route_id=$4 AND actor_id=$6 AND action=$7 AND request=$8::jsonb,
    'receipt',CASE WHEN platform_id=$2 AND registration_id=$3::uuid AND route_id=$4 AND actor_id=$6 AND action=$7 AND request=$8::jsonb THEN receipt ELSE NULL END)
    FROM canvas_connector.lti_capture_operation_audit WHERE organization_id=$1 AND operation_id=$5::uuid) AS result`,
    [v.organizationId,v.platformId,v.registrationId,v.routeId,v.operationId,v.actorId,v.action,JSON.stringify(v.request)]);
   if(found===null)return null;ltiServiceExact(found,['matching','receipt']);if(typeof found.matching!=='boolean')fail();
   if(!found.matching){if(found.receipt!==null)fail();return Object.freeze({conflict:true});}
   const receipt=ltiCaptureAdminReceipt(found.receipt,v);if(receipt.actorId!==v.actorId||receipt.action!==v.action)fail();
   return Object.freeze({conflict:false,receipt});
  },
  async apply(value,beforeCommit,validUntilMs) {
   const v=ltiCaptureAdminCommand(value),r=v.request;
   if(v.action!=='deactivate'&&!ltiVersion(validUntilMs))fail();
   if(beforeCommit!==undefined&&(typeof beforeCommit!=='function'||await beforeCommit()!==true))return null;
   const found=await one('SELECT canvas_connector.administer_lti_capture($1,$2,$3::uuid,$4,$5::uuid,$6,$7,$8::bigint,$9::bigint,$10::bigint,$11::bigint,$12::uuid,$13::jsonb,$14::bigint) AS result',
    [v.organizationId,v.platformId,v.registrationId,v.routeId,v.operationId,v.actorId,v.action,r.expectedPlatformVersion,r.expectedRegistrationVersion,r.expectedKeyVersion,
     r.expectedRouteVersion,r.serviceOperationId,r.definition===null?null:JSON.stringify(r.definition),v.action==='deactivate'?null:validUntilMs]);
   if(found===null)return null;const receipt=ltiCaptureAdminReceipt(found,v);
   if(receipt.actorId!==v.actorId||receipt.action!==v.action||receipt.version!==(v.action==='create'?1:r.expectedRouteVersion+(v.action==='schedule'?0:1))
    ||v.action!=='deactivate'&&receipt.serviceOperationId!==r.serviceOperationId)fail();return receipt;
  },
  async capture(value) {
   const v=ltiCaptureAdminScope(value),captureId=value.captureId;if(!ltiUuid(captureId))fail();
   const found=await one(`SELECT (SELECT jsonb_build_object('captureId',capture_id,'routeId',route_id,'routeVersion',route_version,'phase',phase,
    'attempts',attempts,'availableAtMs',floor(extract(epoch FROM available_at)*1000)::bigint,'lastError',last_error)
    FROM canvas_connector.lti_capture_jobs WHERE organization_id=$1 AND platform_id=$2 AND registration_id=$3::uuid AND route_id=$4 AND capture_id=$5::uuid) AS result`,
    [v.organizationId,v.platformId,v.registrationId,v.routeId,captureId]);
   if(found===null)return null;ltiServiceExact(found,['captureId','routeId','routeVersion','phase','attempts','availableAtMs','lastError']);
   if(found.captureId!==captureId||found.routeId!==v.routeId||!ltiVersion(found.routeVersion)||!['pending','leased','retry','completed','parked'].includes(found.phase)
    ||!Number.isSafeInteger(found.attempts)||found.attempts<0||found.attempts>1000000||!ltiVersion(found.availableAtMs)
    ||![null,'provider_unavailable','configuration_changed','observation_missing','attempt_limit'].includes(found.lastError))fail();return Object.freeze({...found});
  },
 });
}
