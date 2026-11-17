// SPDX-License-Identifier: AGPL-3.0-only
import {createConnectorPostgresPool} from './postgres-pool.mjs';
import {createPostgresRepository} from './postgres-repository.mjs';
import {createOpenBaoKeyProvider} from './openbao-key-provider.mjs';
import {createEncryptedVault} from './encrypted-vault.mjs';
import {createCanvasOAuthProvider} from './canvas-oauth-provider.mjs';
import {createRefreshWorker} from './refresh-worker.mjs';
import {createRevocationWorker} from './revocation-worker.mjs';
import {createRestCaptureRepository,createCanvasRestCaptureWorker} from './rest-capture.mjs';
import {createObservationOutbox,createObservationDeliveryWorker} from './observation-outbox.mjs';
import {createObservationSubmitter} from './observation-submit.mjs';
import {createWorkerLoop} from './worker-loop.mjs';
import {prepareCaptureSchedule,createCaptureScheduler,preflightCaptureScheduler} from './capture-scheduler.mjs';
import {createLtiCaptureRepository} from './lti-capture-repository.mjs';
import {createLtiCaptureWorker} from './lti-capture-worker.mjs';
import {createLtiServiceStore} from './lti-service-store.mjs';
import {createLtiCaptureScheduler} from './lti-capture-scheduler.mjs';
import {preflightLtiWorker} from './lti-worker-preflight.mjs';
const unavailable=()=>new Error('connector_worker_runtime_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
function fields(value,allowed) {
  if(value===null || typeof value!=='object' || Array.isArray(value) || Object.keys(value).some(key=>!allowed.includes(key))) throw unavailable();
}
export async function createConnectorWorkerRuntime(configuration) {
  let pool,loop;
  try {
    fields(configuration,['database','keyCustody','canvas','gateway','refreshTargets','producers','pollIntervalMs','captureSchedules','captureMode']);
    const {database,keyCustody,canvas,gateway,refreshTargets,producers,pollIntervalMs=1000,captureSchedules=[],captureMode='rest'}=configuration;
    if(!['rest','lti'].includes(captureMode))throw unavailable();const ltiMode=captureMode==='lti';
    fields(keyCustody,['openbaoOrigin','mount','keyPath','keyNamespace','tokenProvider','ca','timeoutMs']);
    fields(canvas,['ca','allowedPrivateAddresses','timeoutMs','maxResponseBytes']);
    fields(gateway,['gatewayOrigin','ca','timeoutMs']);
    if(!Array.isArray(refreshTargets) || refreshTargets.length>32 || !Array.isArray(producers) || producers.length>32
      || !Array.isArray(captureSchedules)||captureSchedules.length>32
      || !Number.isSafeInteger(pollIntervalMs) || pollIntervalMs<100 || pollIntervalMs>60000) throw unavailable();
    if(ltiMode&&(refreshTargets.length!==0||producers.length===0))throw unavailable();
    const targets=refreshTargets.map(value=>{
      fields(value,['organizationId','platformId']);if(!id(value.organizationId)||!id(value.platformId)) throw unavailable();
      return Object.freeze({...value});
    });
    const slots=producers.map(value=>{
      fields(value,['organizationId','producerRef','apiKeyProvider']);
      if(!id(value.organizationId)||!id(value.producerRef)||typeof value.apiKeyProvider?.getApiKey!=='function') throw unavailable();
      return Object.freeze({...value});
    });
    if(new Set(targets.map(v=>v.organizationId+':'+v.platformId)).size!==targets.length
      || new Set(slots.map(v=>v.organizationId+':'+v.producerRef)).size!==slots.length) throw unavailable();
    const schedules=captureSchedules.map(value=>prepareCaptureSchedule(value));
    if(new Set(schedules.map(v=>v.organizationId+':'+v.routeId)).size!==schedules.length
      || new Set(schedules.map(v=>v.organizationId+':'+v.configurationId)).size!==schedules.length
      || schedules.some(schedule=>!slots.some(slot=>slot.organizationId===schedule.organizationId&&slot.producerRef===schedule.producerRef)))throw unavailable();
    const keyProvider=createOpenBaoKeyProvider(keyCustody),provider=ltiMode?undefined:createCanvasOAuthProvider(canvas);
    pool=createConnectorPostgresPool(database);
    const repository=ltiMode?undefined:createPostgresRepository(pool),secretVault=ltiMode?undefined:createEncryptedVault({pool,keyProvider});
    const revocation=ltiMode?undefined:createRevocationWorker({repository,secretVault,provider});
    const refresh=ltiMode?undefined:createRefreshWorker({repository,secretVault,provider});
    const captureRepository=ltiMode?createLtiCaptureRepository(pool):createRestCaptureRepository(pool),outbox=createObservationOutbox(pool);
    const tokenStore=ltiMode?createLtiServiceStore({pool,keyProvider}):undefined;
    const tasks=ltiMode?[]:[()=>revocation.runOnce()];
    for(const target of targets) tasks.push(()=>refresh.runOnce(target.organizationId,target.platformId));
    for(const slot of slots) {
      const capture=ltiMode?createLtiCaptureWorker({repository:captureRepository,tokenStore,organizationId:slot.organizationId,producerRef:slot.producerRef,
        ca:canvas.ca,allowedPrivateAddresses:canvas.allowedPrivateAddresses,timeoutMs:canvas.timeoutMs,maxResponseBytes:canvas.maxResponseBytes}):createCanvasRestCaptureWorker({repository:captureRepository,secretVault,
        organizationId:slot.organizationId,producerRef:slot.producerRef,canvasCa:canvas.ca,
        allowedPrivateAddresses:canvas.allowedPrivateAddresses,timeoutMs:canvas.timeoutMs});
      const delivery=createObservationDeliveryWorker({repository:outbox,
        submitter:createObservationSubmitter({...gateway,apiKeyProvider:slot.apiKeyProvider}),
        organizationId:slot.organizationId,producerRef:slot.producerRef});
      tasks.push(()=>capture.runOnce(),()=>delivery.runOnce());
    }
    for(const schedule of schedules) {
      const scheduler=ltiMode?createLtiCaptureScheduler({pool,schedule}):createCaptureScheduler({pool,schedule});tasks.push(()=>scheduler.runOnce());
    }
    loop=createWorkerLoop(tasks,pollIntervalMs);
    const tables=ltiMode?[]:[['secrets','SELECT'],['secrets','DELETE'],['revocation_jobs','SELECT'],['revocation_jobs','UPDATE']];
    const functions=ltiMode?[]:['claim_revocation()','record_provider_revocation(uuid,uuid)','finish_revocation(uuid,uuid)','retry_revocation(uuid,uuid)'];
    if(targets.length) {
      tables.push(['platforms','SELECT'],['connections','SELECT'],['refresh_attempts','SELECT'],['refresh_attempts','INSERT'],['refresh_attempts','UPDATE'],['secrets','INSERT']);
      functions.push('claim_refresh(text,text)','begin_refresh_exchange(uuid,uuid)','require_refresh_reconciliation(uuid,uuid)',
        'abandon_unstarted_refresh(uuid,uuid)','publish_refresh(uuid,uuid)',
        'stage_refresh_result(uuid,uuid,text,text,text,text,bytea,bytea,bytea,text,text,bytea,bytea,bytea,timestamp with time zone)');
    }
    if(slots.length&&!ltiMode) {
      tables.push(['platforms','SELECT'],['connections','SELECT'],['rest_capture_routes','SELECT'],['rest_capture_jobs','SELECT'],['rest_capture_jobs','UPDATE'],
        ['observation_counters','SELECT'],['observation_counters','INSERT'],['observation_counters','UPDATE'],
        ['observation_outbox','SELECT'],['observation_outbox','INSERT'],['observation_outbox','UPDATE']);
      functions.push('valid_outbox_claims(jsonb)','claim_rest_capture(text,text)','complete_rest_capture(text,text,text,uuid,bigint,bigint,jsonb)',
        'defer_rest_capture(text,text,text,uuid,text,boolean)','enqueue_observation(text,text,text,bigint,text,bigint,bigint,jsonb)',
        'seal_observation(text,text,text,text)','claim_observation(text,text)',
        'acknowledge_observation(text,text,text,uuid,text,boolean)','defer_observation(text,text,text,uuid,text,integer,boolean)');
    }
    async function preflight() {
      const result=await pool.query(`SELECT
        NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS required(name text,privilege text)
          WHERE NOT has_table_privilege(current_user,'canvas_connector.'||required.name,required.privilege))
        AND NOT EXISTS(SELECT 1 FROM unnest($2::text[]) signature
          WHERE NOT has_function_privilege(current_user,'canvas_connector.'||signature,'EXECUTE')) AS ready`,
      [JSON.stringify(tables.map(([name,privilege])=>({name,privilege}))),functions]);
      if(result.rows.length!==1 || result.rows[0].ready!==true) throw unavailable();
      if(!ltiMode&&(targets.length || slots.length)) {
        const locks=['platforms',...(slots.length?['connections','rest_capture_routes']:[])];
        const lockResult=await pool.query(`SELECT NOT EXISTS(SELECT 1 FROM unnest($1::text[]) name
          WHERE NOT has_any_column_privilege(current_user,'canvas_connector.'||name,'UPDATE')) AS ready`,[locks]);
        if(lockResult.rows.length!==1 || lockResult.rows[0].ready!==true) throw unavailable();
      }
      if(targets.length) {
        const secretLocks=await pool.query(`SELECT has_column_privilege(current_user,'canvas_connector.secrets','created_at','UPDATE')
          AND has_column_privilege(current_user,'canvas_connector.connections','access_token_ref','UPDATE')
          AND has_column_privilege(current_user,'canvas_connector.connections','refresh_token_ref','UPDATE')
          AND has_column_privilege(current_user,'canvas_connector.connections','token_expires_at','UPDATE')
          AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='canvas_connector.secrets'::regclass
            AND tgname='secret_creation_time' AND tgfoid='canvas_connector.keep_secret_created_at()'::regprocedure
            AND NOT tgisinternal AND tgenabled IN ('O','A') AND tgtype=19 AND tgqual IS NULL AND tgnargs=0 AND tgattr=''::int2vector) AS ready`);
        if(secretLocks.rows.length!==1 || secretLocks.rows[0].ready!==true) throw unavailable();
      }
      if(ltiMode)await preflightLtiWorker(pool,{scheduling:schedules.length>0});
      else if(schedules.length)await preflightCaptureScheduler(pool);
      const selected=await keyProvider.current();
      try {if(!Buffer.isBuffer(selected?.key)||selected.key.length!==32) throw unavailable();}
      finally {if(Buffer.isBuffer(selected?.key)) selected.key.fill(0);}
    }
    let state='created',starting,closing;
    function close() {
      if(closing) return closing;
      state='closing';
      closing=(async()=>{
        await loop.close();
        if(starting) await starting.catch(()=>{});
        await pool.close();state='closed';
      })();return closing;
    }
    return Object.freeze({
      async start() {
        if(state!=='created') throw unavailable();state='starting';
        starting=(async()=>{await preflight();if(state!=='starting') throw unavailable();loop.start();state='running';})();
        try {await starting;} catch {await close();throw unavailable();}
      },close,
    });
  } catch {
    try {await loop?.close();await pool?.close();} catch { /* redacted construction failure */ }
    throw unavailable();
  }
}
