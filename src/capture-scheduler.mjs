// SPDX-License-Identifier: AGPL-3.0-only
import {createHash} from 'node:crypto';
import {exactRecord} from './canvas-rest-contract.mjs';
const unavailable=()=>new Error('connector_capture_scheduler_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const revision=value=>Number.isSafeInteger(value) && value>=1;
function keys(value,names) {
 exactRecord(value,names,'invalid_capture_schedule');if(Object.keys(value).length!==names.length)throw unavailable();
}
export function prepareCaptureSchedule(value) {
 try {
  keys(value,['organizationId','producerRef','routeId','configurationId','expectedRevision','routeVersion','intervalMs','enabled']);
  if(!id(value.organizationId)||!id(value.producerRef)||!id(value.routeId)||!uuid(value.configurationId)
   || !Number.isSafeInteger(value.expectedRevision)||value.expectedRevision<0||value.expectedRevision>=Number.MAX_SAFE_INTEGER
   || !revision(value.routeVersion)||!Number.isInteger(value.intervalMs)||value.intervalMs<1000||value.intervalMs>86400000
   || typeof value.enabled!=='boolean')throw unavailable();
  return Object.freeze({...value});
 }catch{throw unavailable();}
}
function decode(value,schedule) {
 keys(value,['configuration','current','capture','enqueued','reason']);
 const config=value.configuration;
 keys(config,['configurationId','routeId','producerRef','revision','routeVersion','intervalMs','enabled','configuredAtMs']);
 if(config.configurationId!==schedule.configurationId||config.routeId!==schedule.routeId||config.producerRef!==schedule.producerRef
  || config.revision!==schedule.expectedRevision+1||config.routeVersion!==schedule.routeVersion||config.intervalMs!==schedule.intervalMs
  || config.enabled!==schedule.enabled||!revision(config.configuredAtMs)||typeof value.current!=='boolean'||typeof value.enqueued!=='boolean'
  || ![null,'superseded','disabled','route_changed','not_due','source_unavailable','capture_pending','delivery_pending'].includes(value.reason))throw unavailable();
 if(!value.current?(value.reason!=='superseded'||value.capture!==null||value.enqueued):value.reason==='superseded')throw unavailable();
 if(value.enqueued?(value.reason!==null||!schedule.enabled||value.capture===null):value.reason===null)throw unavailable();
 if(value.capture!==null) {
  const capture=value.capture;
  keys(capture,['captureId','configurationId','routeId','routeVersion','revision','ordinal','enqueuedAtMs']);
  if(capture.configurationId!==schedule.configurationId||capture.routeId!==schedule.routeId||capture.routeVersion!==schedule.routeVersion
   || capture.revision!==config.revision||!revision(capture.ordinal)||capture.ordinal>=Number.MAX_SAFE_INTEGER||!revision(capture.enqueuedAtMs))throw unavailable();
  const expected='schedule_'+createHash('sha256').update(['canvas-rest-capture-v1',schedule.organizationId,schedule.producerRef,
   schedule.routeId,schedule.configurationId,String(capture.ordinal)].join('\n')).digest('hex');
  if(capture.captureId!==expected)throw unavailable();
 }
 return Object.freeze({...value,configuration:Object.freeze({...config}),capture:value.capture===null?null:Object.freeze({...value.capture})});
}
// This is private worker configuration, not a browser command or Core grant.
// Each tick is one database transaction; unknown writes are not retried here.
export function createCaptureScheduler(configuration={}) {
 keys(configuration,['pool','schedule']);const {pool,schedule}=configuration;
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')throw unavailable();
 const selected=prepareCaptureSchedule(schedule);
 return Object.freeze({async runOnce(){
  try {
   const result=await pool.query('SELECT canvas_connector.tick_rest_capture_schedule($1,$2,$3,$4::uuid,$5::bigint,$6::bigint,$7::integer,$8::boolean) AS result',
    [selected.organizationId,selected.producerRef,selected.routeId,selected.configurationId,selected.expectedRevision,selected.routeVersion,selected.intervalMs,selected.enabled]);
   if(result?.rows?.length!==1||Object.keys(result.rows[0]).join(',')!=='result'||result.rows[0].result===undefined)throw unavailable();
   return result.rows[0].result===null?null:decode(result.rows[0].result,selected);
  }catch{throw unavailable();}
 }});
}

export async function preflightCaptureScheduler(pool) {
 try {
 const result=await pool.query(`WITH reachable AS(SELECT oid FROM pg_catalog.pg_roles WHERE pg_has_role(current_user,oid,'MEMBER'))
 SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(SELECT oid FROM reachable)
   AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
  AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_schema_privilege(oid,'canvas_connector','CREATE'))
  AND NOT EXISTS(SELECT 1 FROM (VALUES('rest_schedule_heads'),('rest_schedule_configurations'),('rest_schedule_captures')) required(name)
   JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||required.name)::regclass
   WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
    OR pg_has_role(current_user,c.relowner,'MEMBER')
    OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR NOT has_table_privilege(current_user,c.oid,'INSERT')
    OR EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))
    OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid))
  AND NOT EXISTS(SELECT 1 FROM reachable CROSS JOIN (VALUES('rest_schedule_configurations'),('rest_schedule_captures')) immutable(name)
   WHERE has_any_column_privilege(oid,'canvas_connector.'||immutable.name,'UPDATE'))
  AND NOT EXISTS(SELECT 1 FROM reachable CROSS JOIN unnest(ARRAY['organization_id','route_id','producer_ref']) field(name)
   WHERE has_column_privilege(oid,'canvas_connector.rest_schedule_heads',field.name,'UPDATE'))
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['configuration_id','revision','route_version','interval_ms','enabled','next_ordinal','next_due_at','last_capture_id','updated_at']) field(name)
   WHERE NOT has_column_privilege(current_user,'canvas_connector.rest_schedule_heads',field.name,'UPDATE'))
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['organization_id','capture_id','producer_ref','route_id','route_version','platform_id','binding_id','binding_revision','requirement','claim_names','effective_time_policy','available_at']) field(name)
   WHERE NOT has_column_privilege(current_user,'canvas_connector.rest_capture_jobs',field.name,'INSERT'))
  AND (SELECT count(*)=3 FROM pg_catalog.pg_trigger t JOIN (VALUES
   ('rest_schedule_heads','rest_schedule_head_revision','guard_rest_schedule_head()',19),
   ('rest_schedule_configurations','rest_schedule_configuration_immutable','keep_rest_schedule_audit()',27),
   ('rest_schedule_captures','rest_schedule_capture_immutable','keep_rest_schedule_audit()',27)) expected(relation,name,signature,kind)
   ON t.tgrelid=('canvas_connector.'||expected.relation)::regclass AND t.tgname=expected.name
    AND t.tgfoid=('canvas_connector.'||expected.signature)::regprocedure
   WHERE NOT t.tgisinternal AND t.tgenabled IN('O','A') AND t.tgtype=expected.kind AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
  AND NOT EXISTS(SELECT 1 FROM (VALUES('guard_rest_schedule_head()'),('keep_rest_schedule_audit()'),
   ('tick_rest_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean)')) expected(signature)
   JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||expected.signature)::regprocedure
   WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER'))
  AND has_function_privilege(current_user,'canvas_connector.tick_rest_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean)','EXECUTE') AS ready`);
 if(result?.rows?.length!==1||result.rows[0].ready!==true)throw unavailable();
 }catch{throw unavailable();}
}
