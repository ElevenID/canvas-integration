// SPDX-License-Identifier: AGPL-3.0-only
import {prepareCaptureRouteIntent} from './capture-route-contract.mjs';
import {createPlatformAdminStore} from './platform-admin.mjs';
const unavailable=()=>new Error('connector_capture_route_admin_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const revision=value=>Number.isSafeInteger(value) && value>=1;
const keys=(value,names)=>value!==null && typeof value==='object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const actions=['create','replace','activate','deactivate','schedule'];
function scope(value) {if(!id(value?.organizationId) || !id(value.platformId) || !id(value.routeId)) throw unavailable();}
function intent(value) {
  scope(value);
  if(!uuid(value.operationId) || !id(value.actorId) || !actions.includes(value.action)) throw unavailable();
  const create=value.action==='create',disable=value.action==='deactivate';
  if(create?value.expectedRouteVersion!==undefined:!revision(value.expectedRouteVersion)) throw unavailable();
  if(disable?value.expectedPlatformVersion!==undefined:!revision(value.expectedPlatformVersion)) throw unavailable();
  let definition=null;
  if(value.definition!==undefined) {
    if(disable) throw unavailable();definition=prepareCaptureRouteIntent(value.definition);
    if(definition.platformId!==value.platformId) throw unavailable();
  }
  if(['create','replace'].includes(value.action) && definition===null) throw unavailable();
  return {definition,request:{expectedPlatformVersion:value.expectedPlatformVersion??null,expectedRouteVersion:value.expectedRouteVersion??null,
    definition:['create','replace'].includes(value.action)?definition:null}};
}
const receiptFields=['operationId','actorId','action','routeId','platformId','version','enabled','captureId'];
function receipt(value,context) {
  if(!keys(value,receiptFields) || !uuid(value.operationId) || !id(value.actorId) || !actions.includes(value.action)
    || value.routeId!==context.routeId || value.platformId!==context.platformId || value.operationId!==context.operationId
    || !revision(value.version) || typeof value.enabled!=='boolean'
    || (value.action==='schedule'?value.captureId!==value.operationId:value.captureId!==null)
    || (['create','replace','deactivate'].includes(value.action) && value.enabled)
    || (['activate','schedule'].includes(value.action) && !value.enabled)) throw unavailable();
  return value;
}
const selected=`jsonb_build_object('routeId',id,'version',version,'enabled',enabled,'definition',jsonb_build_object(
 'producerRef',producer_ref,'platformId',platform_id,'bindingId',binding_id,'bindingRevision',binding_revision,
 'requirement',requirement,'claimNames',to_jsonb(ARRAY(SELECT name FROM unnest(claim_names) name ORDER BY name COLLATE "C")),
 'effectiveTimePolicy',effective_time_policy))`;
function route(value,platformId) {
  if(!keys(value,['routeId','version','enabled','definition']) || !id(value.routeId) || !revision(value.version) || typeof value.enabled!=='boolean') throw unavailable();
  const definition=prepareCaptureRouteIntent(value.definition);if(definition.platformId!==platformId) throw unavailable();
  return {...value,definition};
}
export function createCaptureRouteAdminStore(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') throw unavailable();
  const platforms=createPlatformAdminStore(pool);
  async function execute(sql,values) {
    try {
      const result=await pool.query(sql,values);
      if(result.rows.length!==1 || !Object.hasOwn(result.rows[0],'result')) throw unavailable();
      return result.rows[0].result;
    } catch {throw unavailable();}
  }
  return Object.freeze({
    platform:value=>platforms.inspect(value),
    async catalog(value) {
      if(!id(value?.organizationId) || !id(value.platformId) || (value.afterId!==undefined && !id(value.afterId))) throw unavailable();
      const rows=await execute(`SELECT COALESCE(jsonb_agg(item ORDER BY id COLLATE "C"),'[]'::jsonb) AS result FROM
       (SELECT id,${selected} AS item FROM canvas_connector.rest_capture_routes WHERE organization_id=$1 AND platform_id=$2
         AND ($3::text IS NULL OR id COLLATE "C">$3 COLLATE "C") ORDER BY id COLLATE "C" LIMIT 21) page`,[value.organizationId,value.platformId,value.afterId??null]);
      if(!Array.isArray(rows) || rows.length>21) throw unavailable();const normalized=rows.map(item=>route(item,value.platformId));
      return {routes:normalized.slice(0,20),nextCursor:normalized.length>20?normalized[19].routeId:null};
    },
    async inspect(value) {
      scope(value);const found=await execute(`SELECT (SELECT ${selected} FROM canvas_connector.rest_capture_routes
       WHERE organization_id=$1 AND platform_id=$2 AND id=$3) AS result`,[value.organizationId,value.platformId,value.routeId]);
      if(found===null) return null;const result=route(found,value.platformId);if(result.routeId!==value.routeId) throw unavailable();return result;
    },
    async receipt(value) {
      scope(value);if(!uuid(value.operationId)) throw unavailable();
      const found=await execute(`SELECT (SELECT receipt FROM canvas_connector.rest_route_operation_audit
        WHERE organization_id=$1 AND platform_id=$2 AND route_id=$3 AND operation_id=$4) AS result`,
      [value.organizationId,value.platformId,value.routeId,value.operationId]);return found===null?null:receipt(found,value);
    },
    async replay(value) {
      const {request}=intent(value);
      const found=await execute(`SELECT (SELECT jsonb_build_object('matching',platform_id=$2 AND route_id=$3 AND actor_id=$5 AND action=$6 AND request=$7::jsonb,
        'receipt',CASE WHEN platform_id=$2 AND route_id=$3 AND actor_id=$5 AND action=$6 AND request=$7::jsonb THEN receipt ELSE NULL END)
        FROM canvas_connector.rest_route_operation_audit WHERE organization_id=$1 AND operation_id=$4) AS result`,
      [value.organizationId,value.platformId,value.routeId,value.operationId,value.actorId,value.action,JSON.stringify(request)]);
      if(found===null) return null;
      if(!keys(found,['matching','receipt']) || typeof found.matching!=='boolean') throw unavailable();
      if(!found.matching) {if(found.receipt!==null) throw unavailable();return {conflict:true};}
      const result=receipt(found.receipt,value);if(result.actorId!==value.actorId || result.action!==value.action) throw unavailable();
      return {conflict:false,receipt:result};
    },
    async apply(value) {
      const {definition}=intent(value);
      const found=await execute('SELECT canvas_connector.administer_rest_route($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) AS result',
        [value.organizationId,value.platformId,value.routeId,value.operationId,value.actorId,value.action,value.expectedPlatformVersion??null,
          value.expectedRouteVersion??null,definition===null?null:JSON.stringify(definition)]);
      if(found===null) return null;const result=receipt(found,value);
      if(result.actorId!==value.actorId || result.action!==value.action
        || result.version!==(value.action==='create'?1:value.expectedRouteVersion+(value.action==='schedule'?0:1))) throw unavailable();return result;
    },
    async capture(value) {
      scope(value);if(!uuid(value.captureId)) throw unavailable();
      const result=await execute(`SELECT (SELECT jsonb_build_object('captureId',j.capture_id,'routeId',j.route_id,'routeVersion',j.route_version,
        'phase',j.phase,'attempts',j.attempts,'availableAtMs',floor(extract(epoch FROM j.available_at)*1000)::bigint,'lastError',j.last_error)
        FROM canvas_connector.rest_capture_jobs j JOIN canvas_connector.rest_capture_routes r ON r.organization_id=j.organization_id AND r.id=j.route_id
        WHERE j.organization_id=$1 AND r.platform_id=$2 AND j.route_id=$3 AND j.capture_id=$4) AS result`,
      [value.organizationId,value.platformId,value.routeId,value.captureId]);
      if(result!==null && (!keys(result,['captureId','routeId','routeVersion','phase','attempts','availableAtMs','lastError'])
        || result.captureId!==value.captureId || result.routeId!==value.routeId || !revision(result.routeVersion)
        || !['pending','leased','retry','completed','parked'].includes(result.phase) || !Number.isInteger(result.attempts) || result.attempts<0 || result.attempts>1000000
        || !revision(result.availableAtMs) || ![null,'provider_unavailable','configuration_changed','invalid_observation','attempt_limit'].includes(result.lastError))) throw unavailable();
      return result;
    },
  });
}
