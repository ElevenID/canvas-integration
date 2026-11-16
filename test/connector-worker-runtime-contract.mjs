// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync,spawn} from 'node:child_process';
import {setTimeout as pause,setImmediate} from 'node:timers/promises';
import {createConnectorPostgresPool} from '../src/postgres-pool.mjs';
import {createPostgresRepository} from '../src/postgres-repository.mjs';
import {createOpenBaoKeyProvider} from '../src/openbao-key-provider.mjs';
import {createEncryptedVault} from '../src/encrypted-vault.mjs';
import {createRestCaptureRepository} from '../src/rest-capture.mjs';
import {createObservationOutbox} from '../src/observation-outbox.mjs';
import {createConnectorWorkerRuntime} from '../src/connector-worker-runtime.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const file=process.argv[2],container=process.argv[3];
assert.match(file??'',/canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);
assert.match(container??'',/^canvas-pg-driver-[a-f0-9]{32}$/);
const f=JSON.parse(await readFile(file,'utf8')),directory=dirname(resolve(file));
const owner=sql=>execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,stdio:['pipe','pipe','pipe']});
const database={host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_runtime',ca:f.ca,
  credentialProvider:{getPassword:async()=> 'synthetic-driver-runtime'},connectTimeoutMs:1000,queryTimeoutMs:5000,maxConnections:4};
const pool=createConnectorPostgresPool(database),repo=createPostgresRepository(pool);
const keyCustody={openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}};
const vault=createEncryptedVault({pool,keyProvider:createOpenBaoKeyProvider(keyCustody)});
const canvas=await httpsFixture(),gateway=await httpsFixture(),runtimes=[];
const org='scheduled-worker-org',platform='refresh-platform',producer='scheduled-producer';
const CLIENT='synthetic_worker_canvas_client_secret',OLD='synthetic_worker_old_access_token',OLD_REFRESH='synthetic_worker_old_refresh_token';
const ACCESS='synthetic_worker_new_access_token',REFRESH='synthetic_worker_new_refresh_token',REVOKE='synthetic_worker_revocation_token';
const KEY='synthetic_worker_gateway_organization_key_0001',KEY2='synthetic_worker_gateway_organization_key_0002';
let key=KEY,refreshes=0,revokes=0,reads=0,posts=0;
let refreshEntered,releaseRefresh,deliveryEntered,releaseDelivery;
const refreshing=new Promise(resolve=>{refreshEntered=resolve;}),refreshHeld=new Promise(resolve=>{releaseRefresh=resolve;});
const delivering=new Promise(resolve=>{deliveryEntered=resolve;}),deliveryHeld=new Promise(resolve=>{releaseDelivery=resolve;});
canvas.setHandler(async(req,res)=>{
  assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers.cookie,undefined);
  if(req.method==='DELETE') {assert.equal(req.url,'/login/oauth2/token');assert.equal(req.headers.authorization,'Bearer '+REVOKE);revokes++;return json(res,{});}
  if(req.method==='POST') {
    assert.equal(req.url,'/login/oauth2/token');const chunks=[];for await(const chunk of req) chunks.push(chunk);
    const form=new URLSearchParams(Buffer.concat(chunks).toString());assert.equal(form.get('client_secret'),CLIENT);assert.equal(form.get('refresh_token'),OLD_REFRESH);
    refreshes++;refreshEntered();await refreshHeld;return json(res,{access_token:ACCESS,refresh_token:REFRESH,expires_in:3600,token_type:'Bearer'});
  }
  assert.equal(req.method,'GET');assert.equal(req.headers.authorization,'Bearer '+ACCESS);reads++;
  json(res,{course_id:'17',user_id:'29',requirement_count:3,requirement_completed_count:0});
});
gateway.setHandler(async(req,res)=>{
  assert.equal(req.url,'/v1/evidence/observations');assert.equal(req.method,'POST');
  assert.equal(req.headers['x-api-key'],key);assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);
  assert.equal(req.headers['x-organization-id'],undefined);const chunks=[];for await(const chunk of req) chunks.push(chunk);
  const body=JSON.parse(Buffer.concat(chunks).toString());assert.equal(req.headers['idempotency-key'],body.observation_id);posts++;
  if(body.observation_id==='worker-drain') {deliveryEntered();await deliveryHeld;}
  json(res,{receipt_id:'receipt-'+body.observation_id,replayed:false});
});
const configuration={database:{...database,user:'canvas_scheduled_worker',credentialProvider:{getPassword:async()=> 'synthetic-worker-password'}},keyCustody,
  canvas:{ca:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:10000},gateway:{gatewayOrigin:gateway.origin,ca:gateway.ca,timeoutMs:10000},
  refreshTargets:[{organizationId:org,platformId:platform}],producers:[{organizationId:org,producerRef:producer,apiKeyProvider:{getApiKey:async()=>key}}],pollIntervalMs:100};
const posix=process.platform!=='win32',workerFile=join(directory,'worker-private.json'),apiFile=join(directory,'worker-gateway-key');
async function privateFile(path,value) {await writeFile(path+'.next',value,{mode:0o600});await rename(path+'.next',path);}
async function until(probe) {
  const deadline=Date.now()+15000;
  while(Date.now()<deadline) {if(await probe()) return;await pause(10);}
  throw Error('synthetic_worker_condition_not_observed');
}
async function start() {
  if(!posix) {
    const runtime=await createConnectorWorkerRuntime(configuration);await runtime.start();runtimes.push(runtime);
    return {async close(){await runtime.close();},async drain(){let closed=false;const work=runtime.close().then(()=>{closed=true;});await setImmediate();assert.equal(closed,false);return {work};}};
  }
  const child=spawn(process.execPath,[fileURLToPath(new URL('../bin/serve-workers.mjs',import.meta.url))],{
    env:{PATH:process.env.PATH,CANVAS_CONNECTOR_WORKER_CONFIG_FILE:workerFile},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='',running=false,draining=false,stopped=false;
  child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>8192) child.kill('SIGKILL');
    running=stdout.includes('"state":"running"');draining=stdout.includes('"state":"draining"');stopped=stdout.includes('"state":"stopped"');});
  child.stderr.on('data',chunk=>{stderr+=chunk;if(stderr.length>8192) child.kill('SIGKILL');});
  const exited=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code,signal)=>resolve({code,signal}));});
  let closing;
  const watchdog=setTimeout(()=>child.kill('SIGKILL'),25000);
  const close=()=>closing??=(async()=>{
    if(child.exitCode===null && !child.killed) child.kill('SIGTERM');
    const outcome=await exited;clearTimeout(watchdog);assert.deepEqual(outcome,{code:0,signal:null});assert.equal(stopped,true);assert.equal(stderr,'');
    for(const secret of [CLIENT,OLD,OLD_REFRESH,ACCESS,REFRESH,REVOKE,KEY,KEY2,f.baoToken]) assert.equal(stdout.includes(secret)||stderr.includes(secret),false);
  })();
  const handle={close,async drain(){const work=close();await until(async()=>draining);assert.equal(child.exitCode,null);assert.equal(child.signalCode,null);assert.equal(stopped,false);return {work};}};
  runtimes.push(handle);await until(async()=>{if(child.exitCode!==null||child.signalCode!==null) throw Error('synthetic_worker_cli_start_failed');return running;});return handle;
}
try {
  // Other contracts deliberately retain unknown/retryable jobs. Preserve them
  // while isolating this database-wide revocation scheduler's ready fixture.
  owner("UPDATE canvas_connector.revocation_jobs SET available_at=clock_timestamp()+interval '1 day' WHERE completed_at IS NULL;");
  owner(`CREATE ROLE canvas_scheduled_worker LOGIN PASSWORD 'synthetic-worker-password';
    GRANT CONNECT ON DATABASE canvas_driver_test TO canvas_scheduled_worker;GRANT USAGE ON SCHEMA canvas_connector TO canvas_scheduled_worker;
    GRANT SELECT ON canvas_connector.secrets,canvas_connector.revocation_jobs,canvas_connector.platforms,canvas_connector.connections,
      canvas_connector.refresh_attempts,canvas_connector.rest_capture_routes,canvas_connector.rest_capture_jobs,
      canvas_connector.observation_counters,canvas_connector.observation_outbox TO canvas_scheduled_worker;
    GRANT DELETE ON canvas_connector.secrets TO canvas_scheduled_worker;
    GRANT INSERT ON canvas_connector.secrets,canvas_connector.refresh_attempts,canvas_connector.observation_counters,canvas_connector.observation_outbox TO canvas_scheduled_worker;
    GRANT UPDATE ON canvas_connector.revocation_jobs,canvas_connector.refresh_attempts,canvas_connector.rest_capture_jobs,
      canvas_connector.observation_counters,canvas_connector.observation_outbox TO canvas_scheduled_worker;
    GRANT UPDATE(access_token_ref,refresh_token_ref,token_expires_at) ON canvas_connector.connections TO canvas_scheduled_worker;
    GRANT UPDATE(created_at) ON canvas_connector.secrets TO canvas_scheduled_worker;
    GRANT UPDATE(id) ON canvas_connector.rest_capture_routes TO canvas_scheduled_worker;
    GRANT EXECUTE ON FUNCTION canvas_connector.claim_revocation(),canvas_connector.record_provider_revocation(uuid,uuid),
      canvas_connector.finish_revocation(uuid,uuid),canvas_connector.retry_revocation(uuid,uuid),canvas_connector.claim_refresh(text,text),
      canvas_connector.begin_refresh_exchange(uuid,uuid),canvas_connector.require_refresh_reconciliation(uuid,uuid),canvas_connector.abandon_unstarted_refresh(uuid,uuid),
      canvas_connector.publish_refresh(uuid,uuid),canvas_connector.stage_refresh_result(uuid,uuid,text,text,text,text,bytea,bytea,bytea,text,text,bytea,bytea,bytea,timestamptz),
      canvas_connector.valid_outbox_claims(jsonb),canvas_connector.claim_rest_capture(text,text),canvas_connector.complete_rest_capture(text,text,text,uuid,bigint,bigint,jsonb),
      canvas_connector.defer_rest_capture(text,text,text,uuid,text,boolean),canvas_connector.enqueue_observation(text,text,text,bigint,text,bigint,bigint,jsonb),
      canvas_connector.seal_observation(text,text,text,text),canvas_connector.claim_observation(text,text),
      canvas_connector.acknowledge_observation(text,text,text,uuid,text,boolean),canvas_connector.defer_observation(text,text,text,uuid,text,integer,boolean) TO canvas_scheduled_worker;`);
  const missing=await createConnectorWorkerRuntime(configuration);await assert.rejects(missing.start(),{message:'connector_worker_runtime_unavailable'});
  owner('GRANT UPDATE(id) ON canvas_connector.platforms TO canvas_scheduled_worker;');
  const limited=createConnectorPostgresPool(configuration.database);
  try {
    for(const sql of ["UPDATE canvas_connector.platforms SET enabled=true","UPDATE canvas_connector.rest_capture_routes SET enabled=true",
      'DELETE FROM canvas_connector.connections','SELECT * FROM canvas_connector.authorization_recovery_audit',
      "UPDATE canvas_connector.secrets SET created_at=clock_timestamp()-interval '1 day'",'CREATE TABLE canvas_connector.forbidden(value text)']) await assert.rejects(limited.query(sql));
  } finally {await limited.close();}
  for(const id of [platform,'revocation-platform']) await pool.query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES($1,$2,$3,true)',[org,id,canvas.origin]);
  const store=async(id,purpose,value)=>vault.put(org,{platformId:id,provider:'canvas',purpose},value);
  const client=await store(platform,'oauth_client_secret',CLIENT),access=await store(platform,'oauth_access_token',OLD),refresh=await store(platform,'oauth_refresh_token',OLD_REFRESH);
  await repo.publishConnection({organizationId:org,platformId:platform,platformConfigVersion:1,canvasOrigin:canvas.origin,clientId:'worker-client',clientSecretRef:client,
    accessTokenRef:access,refreshTokenRef:refresh,tokenExpiresAt:Date.now()+60000,capabilities:['course_completion'],scopes:['url:GET|/api/v1/courses/:course_id/users/:user_id/progress']},1);
  const revoke=await store('revocation-platform','oauth_access_token',REVOKE);
  await pool.query('INSERT INTO canvas_connector.revocation_jobs(organization_id,platform_id,canvas_origin,access_token_ref) VALUES($1,$2,$3,$4)',[org,'revocation-platform',canvas.origin,revoke]);
  await pool.query(`INSERT INTO canvas_connector.rest_capture_routes(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
    VALUES($1,'worker-route',$2,$3,'worker-binding',1,$4::jsonb,$5,'as_of_read',true)`,[org,producer,platform,JSON.stringify({factType:'canvas.course_completion',courseId:'17',userId:'29'}),['completed','requirement_count','requirement_completed_count']]);
  const captures=createRestCaptureRepository(pool),outbox=createObservationOutbox(pool);
  await captures.schedule(org,producer,'worker-route','worker-capture');
  await outbox.enqueue('other-worker-org','unconfigured-producer',{binding_id:'foreign-binding',binding_revision:1,observation_id:'foreign-worker-item',observed_at_ms:1794804000000,effective_at_ms:1794804000000,claims:{completed:false}});
  if(posix) {
    const password=join(directory,'worker-password'),token=join(directory,'worker-bao-token'),ca=join(directory,'worker-db-ca'),baoCa=join(directory,'worker-bao-ca'),canvasCa=join(directory,'worker-canvas-ca'),gatewayCa=join(directory,'worker-gateway-ca');
    for(const [path,value] of [[password,'synthetic-worker-password'],[token,f.baoToken],[apiFile,KEY],[ca,f.ca],[baoCa,f.baoCa],[canvasCa,canvas.ca],[gatewayCa,gateway.ca]]) await privateFile(path,value);
    const {credentialProvider,ca:unused,...db}=configuration.database;
    await privateFile(workerFile,JSON.stringify({schemaVersion:1,database:{...db,passwordFile:password,caFile:ca},
      keyCustody:{openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',tokenFile:token,caFile:baoCa},
      canvas:{caFile:canvasCa,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:10000},gateway:{gatewayOrigin:gateway.origin,caFile:gatewayCa,timeoutMs:10000},
      refreshTargets:configuration.refreshTargets,producers:[{organizationId:org,producerRef:producer,apiKeyFile:apiFile}],pollIntervalMs:100}));
  }
  const first=await start();await refreshing;const refreshDrain=await first.drain();assert.equal(refreshes,1);releaseRefresh();await refreshDrain.work;
  assert.equal((await pool.query('SELECT phase FROM canvas_connector.refresh_attempts WHERE organization_id=$1',[org])).rows[0].phase,'published');
  assert.equal((await pool.query('SELECT phase FROM canvas_connector.rest_capture_jobs WHERE organization_id=$1',[org])).rows[0].phase,'pending');
  assert.equal(await vault.metadata(org,access),null);assert.equal(await vault.metadata(org,refresh),null);assert.equal(await vault.metadata(org,revoke),null);
  const second=await start();
  await until(async()=>(await pool.query('SELECT phase FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND observation_id=$2',[org,'worker-capture'])).rows[0]?.phase==='acknowledged');
  assert.equal(refreshes,1);assert.equal(revokes,1);assert.equal(reads,1);assert.equal(posts,1);
  key=KEY2;if(posix) await privateFile(apiFile,KEY2);
  await outbox.enqueue(org,producer,{binding_id:'worker-binding',binding_revision:1,observation_id:'worker-drain',observed_at_ms:1794804000000,effective_at_ms:1794804000000,claims:{completed:false}});
  await delivering;const deliveryDrain=await second.drain();releaseDelivery();await deliveryDrain.work;
  assert.equal((await pool.query('SELECT phase FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND observation_id=$2',[org,'worker-drain'])).rows[0].phase,'acknowledged');
  assert.equal(posts,2);assert.equal((await pool.query("SELECT phase FROM canvas_connector.observation_outbox WHERE observation_id='foreign-worker-item'")).rows[0].phase,'pending');
  console.log('Actual scheduled worker refresh/revocation/capture/Gateway delivery, restricted role, scope and drain/restart contracts passed');
  if(posix) console.log('Actual standalone POSIX worker CLI private configuration, fresh Gateway file rotation and SIGTERM drain during refresh and delivery passed');
  else console.log('Windows physical worker runtime passed with explicit synthetic providers; POSIX worker CLI/files require Linux qualification');
} finally {
  releaseRefresh();releaseDelivery();for(const runtime of runtimes) await runtime.close();
  await pool.close();await canvas.close();await gateway.close();
}
