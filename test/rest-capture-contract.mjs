// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import PgClient from 'pg/lib/client.js';
import {createConnectorPostgresPool} from '../src/postgres-pool.mjs';
import {createPostgresRepository} from '../src/postgres-repository.mjs';
import {createOpenBaoKeyProvider} from '../src/openbao-key-provider.mjs';
import {createEncryptedVault} from '../src/encrypted-vault.mjs';
import {createRestCaptureRepository,createCanvasRestCaptureWorker} from '../src/rest-capture.mjs';
import {createObservationOutbox,createObservationDeliveryWorker} from '../src/observation-outbox.mjs';
import {createObservationSubmitter} from '../src/observation-submit.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const file=process.argv[2],container=process.argv[3];
assert.match(file??'',/canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);assert.match(container??'',/^canvas-pg-driver-[a-f0-9]{32}$/);
const f=JSON.parse(await readFile(file,'utf8'));const pool=createConnectorPostgresPool({host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_runtime',ca:f.ca,
 credentialProvider:{getPassword:async()=> 'synthetic-driver-runtime'},maxConnections:16,queryTimeoutMs:10000,connectTimeoutMs:1000});
const keyProvider=createOpenBaoKeyProvider({openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}});
const vault=createEncryptedVault({pool,keyProvider});const storage=createPostgresRepository(pool);const captures=createRestCaptureRepository(pool);
const outbox=createObservationOutbox(pool);const canvas=await httpsFixture();const gateway=await httpsFixture();
const TOKEN='synthetic_canvas_capture_token_000000001',KEY='synthetic_capture_gateway_key_00000000001';
let behavior='course';let hook;let canvasReads=[];const gatewayPosts=[];
canvas.setHandler(async(req,res)=>{
 canvasReads.push({url:req.url,key:req.headers.authorization,coreKey:req.headers['x-api-key']});
 if(hook){const run=hook;hook=undefined;await run();}
 if(typeof behavior==='number')return json(res,{error:'synthetic provider denial'},behavior);
 if(req.url.endsWith('/submissions/29'))return json(res,{assignment_id:'31',user_id:'29',course_id:'17',workflow_state:'graded',score:40,
  grade_matches_current_submission:true,graded_at:'2026-11-15T00:00:00.000Z'});
 if(req.url.endsWith('/assignments/31'))return json(res,{id:'31',course_id:'17',points_possible:80});
 json(res,{course_id:'17',user_id:'29',requirement_count:3,requirement_completed_count:0});
});
gateway.setHandler(async(req,res)=>{const chunks=[];for await(const c of req)chunks.push(c);const body=Buffer.concat(chunks).toString('utf8');
 gatewayPosts.push({body,key:req.headers['x-api-key'],providerKey:req.headers.authorization});json(res,{receipt_id:'receipt-'+JSON.parse(body).observation_id,replayed:false});});
const submitter=createObservationSubmitter({gatewayOrigin:gateway.origin,ca:gateway.ca,apiKeyProvider:{getApiKey:async()=>KEY}});
const delivery=createObservationDeliveryWorker({repository:outbox,submitter,organizationId:'capture-org',producerRef:'producer-one'});
const worker=(repository=captures,secretVault=vault)=>createCanvasRestCaptureWorker({repository,secretVault,organizationId:'capture-org',producerRef:'producer-one',
 canvasCa:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1']});
const job=async id=>(await pool.query('SELECT * FROM canvas_connector.rest_capture_jobs WHERE organization_id=$1 AND capture_id=$2',['capture-org',id])).rows[0];
const ledger=async id=>(await pool.query('SELECT * FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND observation_id=$2',['capture-org',id])).rows[0];
const expire=async id=>pool.query("UPDATE canvas_connector.rest_capture_jobs SET lease_expires_at=clock_timestamp()-interval '1 second',available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND capture_id=$2",['capture-org',id]);
const owner=source=>execFileSync('docker',['exec','-i',container,'psql','-X','-q','-A','-t','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:source,encoding:'utf8',stdio:['pipe','pipe','pipe']});
const route=async(id,{policy='as_of_read',assignment=false}={})=>pool.query(`INSERT INTO canvas_connector.rest_capture_routes
 (organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
 VALUES ('capture-org',$1,'producer-one','capture-platform',$2,1,$3::jsonb,$4,$5,true)`,[id,'binding-'+id,
 JSON.stringify(assignment?{factType:'canvas.assignment_score',courseId:'17',activityId:'31',userId:'29'}:{factType:'canvas.course_completion',courseId:'17',userId:'29'}),
 assignment?['completed','score','score_maximum','score_percent']:['completed','requirement_count','requirement_completed_count'],policy]);
try {
 await pool.query("INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ('capture-org','capture-platform',$1,true)",[canvas.origin]);
 let ref=await vault.put('capture-org',{platformId:'capture-platform',provider:'canvas',purpose:'oauth_access_token'},TOKEN);
 const capabilities=['native_activity_scores','course_completion'];const scopes=['url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id',
  'url:GET|/api/v1/courses/:course_id/assignments/:id','url:GET|/api/v1/courses/:course_id/users/:user_id/progress'];
 assert.equal(await storage.publishConnection({organizationId:'capture-org',platformId:'capture-platform',canvasOrigin:canvas.origin,platformConfigVersion:1,
  clientId:'synthetic-client',clientSecretRef:'synthetic-client-ref',accessTokenRef:ref,refreshTokenRef:null,tokenExpiresAt:Date.now()+3600000,capabilities,scopes},1),true);
 await route('negative');assert.equal(await captures.schedule('capture-org','producer-one','negative','negative-capture'),true);
 assert.equal((await worker().runOnce()).state,'captured');assert.equal((await job('negative-capture')).phase,'completed');
 const unsealed=await ledger('negative-capture');assert.equal(unsealed.body,null);assert.equal(unsealed.claims.completed,false);
 assert.equal(unsealed.claims.effective_time_source,'observation_read');assert.equal(unsealed.observed_at_ms,unsealed.effective_at_ms);
 assert.equal((await delivery.runOnce()).state,'acknowledged');assert.equal(JSON.parse(gatewayPosts.at(-1).body).claims.completed,false);
 assert.equal(gatewayPosts.at(-1).key,KEY);assert.equal(gatewayPosts.at(-1).providerKey,undefined);
 assert.equal(canvasReads[0].key,'Bearer '+TOKEN);assert.equal(canvasReads[0].coreKey,undefined);
 // Genuine provider timestamps, original denominator and provenance project explicitly.
 await route('assignment',{assignment:true,policy:'require_provider_time'});await captures.schedule('capture-org','producer-one','assignment','graded-capture');
 assert.equal((await worker().runOnce()).state,'captured');const graded=await ledger('graded-capture');
 assert.equal(graded.claims.score,40);assert.equal(graded.claims.score_maximum,80);assert.equal(graded.claims.score_percent,50);
 assert.equal(graded.claims.effective_time_source,'provider_event');assert.equal(Number(graded.effective_at_ms),Date.parse('2026-11-15T00:00:00.000Z'));
 assert.equal((await delivery.runOnce()).state,'acknowledged');
 // No silent event-time invention: default strict policy parks timestamp-free reads.
 await route('strict',{policy:'require_provider_time'});await captures.schedule('capture-org','producer-one','strict','missing-time');
 assert.equal((await worker().runOnce()).state,'parked');assert.equal(await ledger('missing-time'),undefined);
 // HTTP failure never produces a negative learning observation.
 for(const status of [403,429,503]) {
  await route('http-'+status);await captures.schedule('capture-org','producer-one','http-'+status,'failed-'+status);behavior=status;
  assert.equal((await worker().runOnce()).state,status===403?'parked':'retry_scheduled');assert.equal(await ledger('failed-'+status),undefined);
  // Park synthetic retry fixtures to keep later cases isolated, not delete them.
  if(status!==403)await pool.query("UPDATE canvas_connector.rest_capture_jobs SET phase='parked' WHERE capture_id=$1",['failed-'+status]);
 }behavior='course';
 // Duplicate schedule and concurrent workers permit one current capture lease.
 await route('concurrency');const scheduled=await Promise.all(Array.from({length:8},()=>captures.schedule('capture-org','producer-one','concurrency','concurrent-capture')));
 assert.deepEqual(scheduled,Array(8).fill(true));const claimed=await Promise.all(Array.from({length:8},()=>captures.claim('capture-org','producer-one')));
 assert.equal(claimed.filter(Boolean).length,1);await expire('concurrent-capture');assert.equal((await worker().runOnce()).state,'captured');
 // Uncertain capture commit preserves original times/ID and does not re-read Canvas.
 await route('uncertain');await captures.schedule('capture-org','producer-one','uncertain','uncertain-capture');
 const uncertain=createRestCaptureRepository({async query(sql,values){const result=await pool.query(sql,values);if(sql.includes('complete_rest_capture'))throw Error('synthetic lost capture reply');return result;}});
 assert.equal((await worker(uncertain).runOnce()).state,'reconciliation_required');const original=await ledger('uncertain-capture');
 assert.equal((await job('uncertain-capture')).phase,'completed');const count=canvasReads.length;assert.equal((await worker().runOnce()).state,'idle');assert.equal(canvasReads.length,count);
 while((await delivery.runOnce()).state!=='idle'){}assert.equal((await ledger('uncertain-capture')).observed_at_ms,original.observed_at_ms);
 // Disable during the GET fences publication; expired old work parks without another read.
 await route('disable');await captures.schedule('capture-org','producer-one','disable','disabled-capture');
 hook=()=>pool.query("UPDATE canvas_connector.rest_capture_routes SET enabled=false WHERE id='disable'");
 assert.equal((await worker().runOnce()).state,'reconciliation_required');assert.equal(await ledger('disabled-capture'),undefined);
 await expire('disabled-capture');const beforeDisable=canvasReads.length;assert.equal((await worker().runOnce()).state,'idle');assert.equal(canvasReads.length,beforeDisable);
 assert.equal((await job('disabled-capture')).phase,'parked');
 // Connection revision/ref changes cannot publish an old-token read (including ABA identities).
 await route('rotation');await captures.schedule('capture-org','producer-one','rotation','rotated-capture');
 const replacement=await vault.put('capture-org',{platformId:'capture-platform',provider:'canvas',purpose:'oauth_access_token'},TOKEN+'2');
 hook=()=>pool.query("UPDATE canvas_connector.connections SET access_token_ref=$1 WHERE organization_id='capture-org'",[replacement]);
 assert.equal((await worker().runOnce()).state,'reconciliation_required');assert.equal(await ledger('rotated-capture'),undefined);
 await expire('rotated-capture');assert.equal((await worker().runOnce()).state,'captured');assert.equal(canvasReads.at(-1).key,'Bearer '+TOKEN+'2');
 // Delayed outbox insertion crossing lease expiry rolls capture/counter/ledger back together.
 await route('expiry');await captures.schedule('capture-org','producer-one','expiry','expiry-capture');const expiring=await captures.claim('capture-org','producer-one');
 owner("CREATE FUNCTION canvas_connector.capture_delay_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.observation_id='expiry-capture' THEN PERFORM pg_sleep(0.2); END IF; RETURN NEW; END $$; CREATE TRIGGER capture_delay_fixture BEFORE INSERT ON canvas_connector.observation_outbox FOR EACH ROW EXECUTE FUNCTION canvas_connector.capture_delay_fixture();");
 await pool.query("UPDATE canvas_connector.rest_capture_jobs SET lease_expires_at=clock_timestamp()+interval '100 milliseconds' WHERE capture_id='expiry-capture'");
 const now=Date.now();await assert.rejects(()=>captures.complete('capture-org','producer-one','expiry-capture',expiring.lease_id,{observedAtMs:now,effectiveAtMs:now,
  claims:{completed:false,requirement_count:3,requirement_completed_count:0,effective_time_source:'observation_read'}}),/connector_capture_unavailable/);
 assert.equal(await ledger('expiry-capture'),undefined);assert.equal((await job('expiry-capture')).phase,'leased');
 assert.equal((await pool.query("SELECT count(*)::int AS n FROM canvas_connector.observation_counters WHERE binding_id='binding-expiry'")).rows[0].n,0);
 for(const sql of ["UPDATE canvas_connector.rest_capture_jobs SET requirement='{}'::jsonb WHERE capture_id='negative-capture'",
  "DELETE FROM canvas_connector.rest_capture_jobs WHERE capture_id='negative-capture'"])
  await assert.rejects(()=>pool.query(sql),/connector_database_unavailable/);
 // Controlled MVCC window: a real claimant reads pending eligibility and
 // blocks on a platform lock. Install the coherent state of an intervening
 // owner, use actual defer_rest_capture to schedule future backoff, then let
 // the stale claimant reach its final job-row check.
 await pool.query(`INSERT INTO canvas_connector.rest_capture_routes
  (organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
  VALUES ('capture-org','race-route','race-producer','capture-platform','binding-race',1,
  '{"factType":"canvas.course_completion","courseId":"17","userId":"29"}'::jsonb,ARRAY['completed'],'as_of_read',true)`);
 await captures.schedule('capture-org','race-producer','race-route','race-capture');
 const ownerConfig={host:'localhost',port:f.port,database:'canvas_driver_test',user:'postgres',password:'synthetic-driver-bootstrap',
  ssl:{ca:f.ca,rejectUnauthorized:true},application_name:'rest-capture-race-owner',connectionTimeoutMillis:1000,query_timeout:5000,statement_timeout:5000};
 const control=new PgClient(ownerConfig),locker=new PgClient(ownerConfig);await control.connect();await locker.connect();
 let stale;
 try {
  const lockerPid=(await locker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  await locker.query('BEGIN');await locker.query("SELECT 1 FROM canvas_connector.platforms WHERE organization_id='capture-org' AND id='capture-platform' FOR UPDATE");
  stale=captures.claim('capture-org','race-producer');stale.catch(()=>{});
  let observed=false;
  for(let n=0;n<100;n++) {
   const waiting=await control.query(`SELECT pid FROM pg_stat_activity WHERE application_name='elevenid-canvas-connector' AND ${lockerPid}=ANY(pg_blocking_pids(pid))`);
   if(waiting.rows.length){observed=true;break;}await new Promise(r=>setTimeout(r,10));
  }
  assert.equal(observed,true,'claim must be observed blocked after its initial eligibility read');
  const intervening=(await control.query(`UPDATE canvas_connector.rest_capture_jobs j SET phase='leased',lease_id=gen_random_uuid(),
   lease_expires_at=clock_timestamp()+interval '3 minutes',attempts=1,access_token_ref=c.access_token_ref,
   connection_revision=c.revision,canvas_origin=c.canvas_origin,platform_config_version=c.platform_config_version,
   capabilities=c.capabilities,scopes=c.scopes FROM canvas_connector.connections c
   WHERE j.capture_id='race-capture' AND j.organization_id=c.organization_id AND j.platform_id=c.platform_id RETURNING j.lease_id`)).rows[0];
  assert.equal(await captures.defer('capture-org','race-producer','race-capture',intervening.lease_id,'provider_unavailable',false),true);
  assert.equal((await control.query("SELECT available_at>clock_timestamp() AS future FROM canvas_connector.rest_capture_jobs WHERE capture_id='race-capture'")).rows[0].future,true);
  await locker.query('COMMIT');assert.equal(await stale,null);
  const delayed=await job('race-capture');assert.equal(delayed.phase,'retry');assert.equal(delayed.attempts,1);
  assert.equal(await captures.claim('capture-org','race-producer'),null);
  console.log('Observed PostgreSQL lock wait plus intervening owner defer preserves future capture backoff');
 }finally {await locker.query('ROLLBACK');await Promise.allSettled([stale].filter(Boolean));await locker.end();await control.end();}
 console.log('Real Canvas HTTPS -> scoped encrypted vault -> durable capture -> immutable outbox -> public Gateway HTTPS contracts passed; errors/uncertain commits/config and lease fences retained original state');
}finally{await pool.close();await canvas.close();await gateway.close();}
