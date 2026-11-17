// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as pause} from 'node:timers/promises';
import {createLtiCaptureScheduler} from '../src/lti-capture-scheduler.mjs';
import {preflightLtiWorker} from '../src/lti-worker-preflight.mjs';
import {createConnectorWorkerRuntime} from '../src/connector-worker-runtime.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
import {ltiWorkerCliContract} from './lti-worker-cli-contract.mjs';

export async function ltiWorkerRuntimeContract(configuration,{pool,organizationId:org,platformId:platform,registrationId:registration,serviceOperationId:service,definition,peer,keyCustody,ownerQuery}) {
 const role='canvas_lti_capture_runtime',gateway=await httpsFixture(),workers=[];
 await ownerQuery(`GRANT UPDATE(body,phase,attempts,available_at,lease_id,lease_expires_at,receipt_id,replayed,last_error,last_status) ON canvas_connector.observation_outbox TO ${role};
  GRANT SELECT ON canvas_connector.lti_schedule_configurations,canvas_connector.lti_schedule_heads,canvas_connector.lti_schedule_captures TO ${role};
  GRANT INSERT(organization_id,configuration_id,producer_ref,route_id,intent,receipt) ON canvas_connector.lti_schedule_configurations TO ${role};
  GRANT INSERT(organization_id,capture_id,configuration_id,route_id,ordinal,receipt) ON canvas_connector.lti_schedule_captures TO ${role};
  GRANT INSERT(organization_id,route_id,producer_ref,configuration_id,revision,route_version,interval_ms,enabled,next_due_at,updated_at),
   UPDATE(configuration_id,revision,route_version,interval_ms,enabled,next_ordinal,next_due_at,last_capture_id,updated_at) ON canvas_connector.lti_schedule_heads TO ${role};
  GRANT EXECUTE ON FUNCTION canvas_connector.tick_lti_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean),
   canvas_connector.seal_observation(text,text,text,text),canvas_connector.claim_observation(text,text),
   canvas_connector.acknowledge_observation(text,text,text,uuid,text,boolean),canvas_connector.defer_observation(text,text,text,uuid,text,integer,boolean) TO ${role};`);
 const producer='lti-worker',routeId='worker-route',binding='lti-worker-binding',workerDefinition={...definition,producerRef:producer,bindingId:binding};
 const schedule={organizationId:org,producerRef:producer,routeId,configurationId:randomUUID(),expectedRevision:0,routeVersion:1,intervalMs:1000,enabled:true};
 const key='synthetic_lti_worker_gateway_api_key_000001';let keyReads=0,submissions=0,expectedKey=key;
 let holdNext=false,release,entered;
 const held=new Promise(r=>{entered=r;}),gate=new Promise(r=>{release=r;});
 try {
  await preflightLtiWorker(pool,{scheduling:true});
  for(const [bad,restore] of [
   [`GRANT SELECT(ciphertext) ON canvas_connector.lti_tool_keys TO ${role}`,`REVOKE SELECT(ciphertext) ON canvas_connector.lti_tool_keys FROM ${role}`],
   [`GRANT SELECT ON canvas_connector.secrets TO ${role}`,`REVOKE SELECT ON canvas_connector.secrets FROM ${role}`],
   [`GRANT INSERT(actor_id) ON canvas_connector.lti_capture_operation_audit TO ${role}`,`REVOKE INSERT(actor_id) ON canvas_connector.lti_capture_operation_audit FROM ${role}`],
   [`GRANT UPDATE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq TO ${role}`,`REVOKE UPDATE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq FROM ${role}`],
   [`GRANT UPDATE(version) ON canvas_connector.lti_capture_routes TO ${role}`,`REVOKE UPDATE(version) ON canvas_connector.lti_capture_routes FROM ${role}`],
   [`REVOKE UPDATE(body) ON canvas_connector.observation_outbox FROM ${role}`,`GRANT UPDATE(body) ON canvas_connector.observation_outbox TO ${role}`],
   [`ALTER TABLE canvas_connector.lti_schedule_captures DISABLE TRIGGER lti_schedule_capture_immutable`,`ALTER TABLE canvas_connector.lti_schedule_captures ENABLE TRIGGER lti_schedule_capture_immutable`],
   [`ALTER FUNCTION canvas_connector.tick_lti_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean) SECURITY DEFINER`,
    `ALTER FUNCTION canvas_connector.tick_lti_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean) SECURITY INVOKER`],
   [`CREATE ROLE canvas_lti_worker_hidden NOINHERIT;GRANT SELECT(ciphertext) ON canvas_connector.lti_tool_keys TO canvas_lti_worker_hidden;GRANT canvas_lti_worker_hidden TO ${role} WITH INHERIT FALSE`,
    `REVOKE canvas_lti_worker_hidden FROM ${role};DROP OWNED BY canvas_lti_worker_hidden;DROP ROLE canvas_lti_worker_hidden`],
  ]) {
   await ownerQuery(bad);try{await assert.rejects(preflightLtiWorker(pool,{scheduling:true}),/lti_worker_runtime_unavailable/);}
   finally{await ownerQuery(restore);}await preflightLtiWorker(pool,{scheduling:true});
  }
  await ownerQuery(`INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES('${org}','${routeId}','${producer}','${platform}','${registration}','${JSON.stringify(workerDefinition)}'::jsonb,'${service}',true);`);
  gateway.setHandler((req,res)=>{void(async()=>{
   assert.equal(req.url,'/v1/evidence/observations');assert.equal(req.method,'POST');assert.equal(req.headers['x-api-key'],expectedKey);
   assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.authorization,undefined);assert.equal(req.headers['x-organization-id'],undefined);
   let text='';for await(const c of req)text+=c;const body=JSON.parse(text);assert.equal(body.binding_id,binding);assert.equal(body.binding_revision,1);
   assert.equal(req.headers['idempotency-key'],body.observation_id);assert.equal(/synthetic_capture_lti_bearer|private|completed|role|subject|application/.test(text),false);
   submissions++;if(holdNext){holdNext=false;entered();await gate;}json(res,{receipt_id:'lti-worker-receipt-'+submissions,replayed:false});
  })().catch(()=>res.destroy());});
  const runtimeConfig={database:{...configuration,user:role,credentialProvider:{getPassword:async()=>'synthetic-lti-capture-password'}},keyCustody,
   canvas:{ca:peer.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:5000},gateway:{gatewayOrigin:gateway.origin,ca:gateway.ca},
   captureMode:'lti',refreshTargets:[],producers:[{organizationId:org,producerRef:producer,apiKeyProvider:{getApiKey:async()=>{keyReads++;return key;}}}],captureSchedules:[schedule],pollIntervalMs:100};
  const fresh=async()=>{const w=await createConnectorWorkerRuntime(runtimeConfig);workers.push(w);return w;};
  const wait=async check=>{const deadline=Date.now()+6000;while(Date.now()<deadline){if(await check())return;await pause(20);}assert.fail('LTI runtime bounded qualification timeout');};
  const first=await fresh();await first.start();
  await wait(async()=>submissions>=1&&(await pool.query("SELECT count(*)::float8 AS n FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND producer_ref=$2 AND phase='acknowledged'",[org,producer])).rows[0].n===1);
  await first.close();assert.equal(keyReads,1);assert.equal(submissions,1);
  const tick=createLtiCaptureScheduler({pool,schedule}),before=await tick.runOnce();assert.equal(before.current,true);assert.ok(before.capture);
  const lost=createLtiCaptureScheduler({schedule,pool:{async query(sql,args){await pool.query(sql,args);throw Error('lost durable schedule reply');}}});
  await assert.rejects(lost.runOnce(),/lti_capture_scheduler_unavailable/);
  const reconciled=await tick.runOnce();assert.equal(reconciled.configuration.configurationId,schedule.configurationId);
  // Restart continues the same durable configuration/cursor and public outbox.
  const second=await fresh();await second.start();await wait(async()=>submissions>=2);await second.close();
  const rows=(await pool.query('SELECT observation_id,sequence::float8 AS sequence FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND producer_ref=$2 ORDER BY sequence',[org,producer])).rows;
  assert.equal(rows.length,2);assert.deepEqual(rows.map(r=>r.sequence),[1,2]);assert.notEqual(rows[0].observation_id,rows[1].observation_id);
  const disabled={...schedule,configurationId:randomUUID(),expectedRevision:1,enabled:false};
  const off=await createLtiCaptureScheduler({pool,schedule:disabled}).runOnce();assert.equal(off.reason,'disabled');
  const stale=await tick.runOnce();assert.equal(stale.current,false);assert.equal(stale.reason,'superseded');
  if(process.platform!=='win32') {
   holdNext=true;
   await ltiWorkerCliContract(runtimeConfig,{configurationId:randomUUID(),expectedRevision:2,key,held,release,wait,pool,organizationId:org,producerRef:producer,
    count:()=>submissions,setKey:value=>{expectedKey=value;}});
  }
  const denied=await createConnectorWorkerRuntime({...runtimeConfig,database:{...runtimeConfig.database,user:'canvas_lti_services',credentialProvider:{getPassword:async()=>'synthetic-lti-services-password'}}});
  workers.push(denied);await assert.rejects(denied.start(),/connector_worker_runtime_unavailable/);
  console.log('Actual keyless LTI worker: restricted startup, private-key/OAuth denial, automatic cadence -> Canvas TLS -> atomic outbox -> public Gateway, original cursor/restart/disabled/superseded PASS');
 }finally{release();for(const w of workers)await w.close();await gateway.close();}
}
