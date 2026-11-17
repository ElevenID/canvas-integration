// SPDX-License-Identifier: AGPL-3.0-only
import {createHash} from 'node:crypto';
import {exactRecord} from './canvas-rest-contract.mjs';
import {prepareCaptureSchedule} from './capture-scheduler.mjs';
const fail=()=>{throw Error('lti_capture_scheduler_unavailable');};
const positive=v=>Number.isSafeInteger(v)&&v>0;
function exact(v,names){exactRecord(v,names,'invalid_lti_schedule');if(Object.keys(v).length!==names.length)fail();}
export function ltiScheduledCaptureId(schedule,ordinal) {
 schedule=prepareCaptureSchedule(schedule);if(!positive(ordinal)||ordinal>=Number.MAX_SAFE_INTEGER)fail();
 const hash=createHash('sha256').update(['canvas-lti-capture-v1',schedule.organizationId,schedule.producerRef,schedule.routeId,schedule.configurationId,String(ordinal)].join('\n')).digest('hex').slice(0,32);
 return [hash.slice(0,8),hash.slice(8,12),hash.slice(12,16),hash.slice(16,20),hash.slice(20)].join('-');
}
function decode(value,schedule) {
 exact(value,['configuration','current','capture','enqueued','reason']);const c=value.configuration;
 exact(c,['configurationId','routeId','producerRef','revision','routeVersion','intervalMs','enabled','configuredAtMs']);
 if(c.configurationId!==schedule.configurationId||c.routeId!==schedule.routeId||c.producerRef!==schedule.producerRef||c.revision!==schedule.expectedRevision+1
  ||c.routeVersion!==schedule.routeVersion||c.intervalMs!==schedule.intervalMs||c.enabled!==schedule.enabled||!positive(c.configuredAtMs)
  ||typeof value.current!=='boolean'||typeof value.enqueued!=='boolean'
  ||![null,'superseded','disabled','route_changed','not_due','source_unavailable','capture_pending','delivery_pending'].includes(value.reason))fail();
 if(!value.current?(value.reason!=='superseded'||value.capture!==null||value.enqueued):value.reason==='superseded')fail();
 if(value.enqueued?(value.reason!==null||!schedule.enabled||value.capture===null):value.reason===null)fail();
 if(value.capture!==null) {
  const a=value.capture;exact(a,['captureId','configurationId','routeId','routeVersion','revision','ordinal','enqueuedAtMs']);
  if(a.configurationId!==schedule.configurationId||a.routeId!==schedule.routeId||a.routeVersion!==schedule.routeVersion||a.revision!==c.revision
   ||!positive(a.enqueuedAtMs)||a.captureId!==ltiScheduledCaptureId(schedule,a.ordinal))fail();
 }
 return Object.freeze({...value,configuration:Object.freeze({...c}),capture:value.capture===null?null:Object.freeze({...value.capture})});
}
// One durable tick. Reconciliation uses the same configuration UUID/cursor;
// uncertain SQL responses never produce a replacement ID or a retry here.
export function createLtiCaptureScheduler({pool,schedule}={}) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')fail();
 const selected=prepareCaptureSchedule(schedule);
 return Object.freeze({async runOnce(){
  try {
   const r=await pool.query('SELECT canvas_connector.tick_lti_capture_schedule($1,$2,$3,$4::uuid,$5::bigint,$6::bigint,$7::integer,$8::boolean) AS result',
    [selected.organizationId,selected.producerRef,selected.routeId,selected.configurationId,selected.expectedRevision,selected.routeVersion,selected.intervalMs,selected.enabled]);
   if(r?.rows?.length!==1||Object.keys(r.rows[0]).join(',')!=='result'||r.rows[0].result===undefined)fail();
   return r.rows[0].result===null?null:decode(r.rows[0].result,selected);
  }catch{fail();}
 }});
}
