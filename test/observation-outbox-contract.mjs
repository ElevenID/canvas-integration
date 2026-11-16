// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createConnectorPostgresPool} from '../src/postgres-pool.mjs';
import {createObservationOutbox,createObservationDeliveryWorker} from '../src/observation-outbox.mjs';
import {createObservationSubmitter} from '../src/observation-submit.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const file=process.argv[2],container=process.argv[3];
assert.match(file??'',/canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);
assert.match(container??'',/^canvas-pg-driver-[a-f0-9]{32}$/);
const fixture=JSON.parse(await readFile(file,'utf8'));
const configuration={host:'localhost',port:fixture.port,database:'canvas_driver_test',user:'canvas_runtime',ca:fixture.ca,
 credentialProvider:{getPassword:async()=> 'synthetic-driver-runtime'},connectTimeoutMs:1000,queryTimeoutMs:2000,maxConnections:16};
let pool=createConnectorPostgresPool(configuration);const gateway=await httpsFixture();
let mode='success';const requests=[];const receipts=new Map();
gateway.setHandler(async(req,res)=>{
 const chunks=[];for await(const chunk of req)chunks.push(chunk);
 const body=Buffer.concat(chunks).toString('utf8');const value=JSON.parse(body);requests.push({body,id:value.observation_id,key:req.headers['x-api-key']});
 assert.equal(req.url,'/v1/evidence/observations');assert.equal(req.headers['idempotency-key'],value.observation_id);
 const replayed=receipts.has(value.observation_id);
 if(mode==='forbidden')return json(res,{error:'denied'},403);
 if(mode==='outage')return json(res,{error:'unavailable'},503);
 receipts.set(value.observation_id,'receipt-'+value.observation_id);
 if(mode==='lost-reply'){mode='success';req.socket.destroy();return;}
 json(res,{receipt_id:receipts.get(value.observation_id),replayed});
});
const submitter=createObservationSubmitter({gatewayOrigin:gateway.origin,ca:gateway.ca,
 apiKeyProvider:{getApiKey:async()=> 'synthetic_outbox_gateway_key_000000000001'}});
const input=(id,binding='binding-one')=>({binding_id:binding,binding_revision:1,observation_id:id,
 observed_at_ms:1794804000000,effective_at_ms:1794803999000,claims:{completed:false,score:null}});
const worker=(repo,org,options={})=>createObservationDeliveryWorker({repository:repo,submitter,organizationId:org,producerRef:'producer-one',...options});
const state=async(org,id)=>(await pool.query('SELECT * FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND observation_id=$2',[org,id])).rows[0];
const ready=async org=>pool.query("UPDATE canvas_connector.observation_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1",[org]);
const owner=source=>execFileSync('docker',['exec','-i',container,'psql','-X','-q','-A','-t','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:source,encoding:'utf8',stdio:['pipe','pipe','pipe']});
try {
 let repo=createObservationOutbox(pool);
 // Unique captures serialize one binding counter; duplicate captures reuse rows.
 const captures=await Promise.all(Array.from({length:8},(_,i)=>repo.enqueue('outbox-concurrent','producer-one',input('capture-'+i))));
 assert.deepEqual(captures.map(x=>x.sequence).sort((a,b)=>a-b),[1,2,3,4,5,6,7,8]);
 const duplicate=await Promise.all(Array.from({length:8},()=>repo.enqueue('outbox-duplicate','producer-one',input('same-capture'))));
 assert.deepEqual(duplicate.map(x=>x.sequence),Array(8).fill(1));
 assert.equal((await pool.query("SELECT count(*)::int AS n FROM canvas_connector.observation_outbox WHERE organization_id='outbox-duplicate'")).rows[0].n,1);
 await assert.rejects(()=>repo.enqueue('outbox-duplicate','producer-one',{...input('same-capture'),claims:{completed:true}}),/connector_outbox_unavailable/);
 assert.equal(await repo.claim('foreign-org','producer-one'),null);assert.equal(await repo.claim('outbox-duplicate','foreign-producer'),null);
 const claims=await Promise.all(Array.from({length:8},()=>repo.claim('outbox-duplicate','producer-one')));
 assert.equal(claims.filter(Boolean).length,1);const old=claims.find(Boolean);
 await pool.query("UPDATE canvas_connector.observation_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1",['outbox-duplicate']);
 const replacement=await repo.claim('outbox-duplicate','producer-one');assert.notEqual(replacement.lease_id,old.lease_id);
 assert.equal(await repo.acknowledge('outbox-duplicate','producer-one',old.observation_id,old.lease_id,{receipt_id:'old-receipt',replayed:false}),false);
 assert.equal(await repo.acknowledge('outbox-duplicate','producer-one',replacement.observation_id,replacement.lease_id,{receipt_id:'current-receipt',replayed:false}),true);
 // Failed ledger insertion rolls back counter creation/increment in one transaction.
 owner("CREATE FUNCTION canvas_connector.outbox_insert_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.observation_id='enqueue-rollback' THEN RAISE EXCEPTION 'synthetic insert failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER outbox_test_fault BEFORE INSERT ON canvas_connector.observation_outbox FOR EACH ROW EXECUTE FUNCTION canvas_connector.outbox_insert_fault();");
 await assert.rejects(()=>repo.enqueue('outbox-rollback','producer-one',input('enqueue-rollback')),/connector_outbox_unavailable/);
 assert.equal((await pool.query("SELECT count(*)::int AS n FROM canvas_connector.observation_counters WHERE organization_id='outbox-rollback'")).rows[0].n,0);
 assert.equal((await repo.enqueue('outbox-rollback','producer-one',input('after-rollback'))).sequence,1);
 // Unknown enqueue commit leaves a recoverable preparing row; no HTTP until sealed.
 const uncertainEnqueue=createObservationOutbox({async query(sql,values){const result=await pool.query(sql,values);if(sql.includes('enqueue_observation'))throw Error('synthetic lost enqueue reply');return result;}});
 await assert.rejects(()=>uncertainEnqueue.enqueue('outbox-prepare','producer-one',input('prepare-recovery')),/connector_outbox_unavailable/);
 assert.equal((await state('outbox-prepare','prepare-recovery')).phase,'preparing');
 assert.equal((await worker(repo,'outbox-prepare').runOnce()).state,'acknowledged');
 const sealed=await state('outbox-prepare','prepare-recovery');assert.equal(sealed.phase,'acknowledged');assert.ok(sealed.body);assert.equal(sealed.sequence,'1');
 // Unknown sealing commit keeps exact bytes; repeating same capture does not allocate again.
 const uncertainSeal=createObservationOutbox({async query(sql,values){const result=await pool.query(sql,values);if(sql.includes('seal_observation'))throw Error('synthetic lost seal reply');return result;}});
 await assert.rejects(()=>uncertainSeal.enqueue('outbox-seal','producer-one',input('seal-recovery')),/connector_outbox_unavailable/);
 const original=(await state('outbox-seal','seal-recovery')).body;
 assert.equal((await repo.enqueue('outbox-seal','producer-one',input('seal-recovery'))).body,original);
 assert.equal((await worker(repo,'outbox-seal').runOnce()).state,'acknowledged');
 // Gateway commit + lost response retries original bytes/id/sequence and observes replay.
 const pending=await repo.enqueue('outbox-uncertain','producer-one',input('uncertain-delivery'));mode='lost-reply';
 assert.equal((await worker(repo,'outbox-uncertain').runOnce()).state,'retry_scheduled');
 assert.equal((await state('outbox-uncertain','uncertain-delivery')).body,pending.body);
 await ready('outbox-uncertain');assert.equal((await worker(repo,'outbox-uncertain').runOnce()).state,'acknowledged');
 assert.equal((await state('outbox-uncertain','uncertain-delivery')).replayed,true);
 assert.deepEqual(requests.filter(x=>x.id==='uncertain-delivery').map(x=>x.body),[pending.body,pending.body]);
 // Unknown local receipt commit cannot cause new delivery after that commit succeeded.
 await repo.enqueue('outbox-ack','producer-one',input('ack-recovery'));
 const uncertainAck=createObservationOutbox({async query(sql,values){const result=await pool.query(sql,values);if(sql.includes('acknowledge_observation'))throw Error('synthetic lost acknowledgment');return result;}});
 assert.equal((await worker(uncertainAck,'outbox-ack').runOnce()).state,'reconciliation_required');
 assert.equal((await state('outbox-ack','ack-recovery')).phase,'acknowledged');
 const sent=requests.length;assert.equal((await worker(repo,'outbox-ack').runOnce()).state,'idle');assert.equal(requests.length,sent);
 // Parked first item blocks newer rows for that binding, without deleting anything.
 await repo.enqueue('outbox-order','producer-one',input('order-first'));await repo.enqueue('outbox-order','producer-one',input('order-second'));
 mode='forbidden';assert.equal((await worker(repo,'outbox-order').runOnce()).state,'parked');mode='success';
 assert.equal((await worker(repo,'outbox-order').runOnce()).state,'idle');
 await repo.enqueue('outbox-order','producer-one',input('other-binding','binding-two'));
 assert.equal((await worker(repo,'outbox-order').runOnce()).state,'acknowledged');
 assert.equal((await state('outbox-order','order-second')).phase,'pending');
 // A replacement credential slot shares the binding counter and cannot overtake an unresolved original slot.
 await repo.enqueue('outbox-rotation','producer-one',input('old-key-delivery'));
 assert.equal((await repo.enqueue('outbox-rotation','producer-two',input('new-key-delivery'))).sequence,2);
 assert.equal((await worker(repo,'outbox-rotation',{producerRef:'producer-two'}).runOnce()).state,'idle');
 mode='forbidden';assert.equal((await worker(repo,'outbox-rotation').runOnce()).state,'parked');mode='success';
 assert.equal((await worker(repo,'outbox-rotation',{producerRef:'producer-two'}).runOnce()).state,'idle');
 // Bounded outage attempts park durable original content rather than inventing new evidence.
 await repo.enqueue('outbox-limit','producer-one',input('outage-limit'));mode='outage';
 assert.equal((await worker(repo,'outbox-limit',{maxAttempts:2}).runOnce()).state,'retry_scheduled');await ready('outbox-limit');
 assert.equal((await worker(repo,'outbox-limit',{maxAttempts:2}).runOnce()).state,'parked');mode='success';
 assert.equal((await state('outbox-limit','outage-limit')).last_error,'delivery_attempt_limit');
 // Immutable provenance/body and retention are enforced by the actual database.
 for(const sql of ["UPDATE canvas_connector.observation_outbox SET body=body||' ' WHERE organization_id='outbox-seal'",
  "UPDATE canvas_connector.observation_outbox SET observed_at_ms=observed_at_ms+1 WHERE organization_id='outbox-seal'",
  "DELETE FROM canvas_connector.observation_outbox WHERE organization_id='outbox-seal'",
  "UPDATE canvas_connector.observation_outbox SET phase='retry',receipt_id=NULL,replayed=NULL WHERE organization_id='outbox-seal'"])
  await assert.rejects(()=>pool.query(sql),/connector_database_unavailable/);

 // A slow transactional write cannot commit an acknowledgment/defer after lease expiry.
 await repo.enqueue('outbox-expiry','producer-one',input('expiry-after-write'));
 const expiring=await repo.claim('outbox-expiry','producer-one');
 owner("CREATE FUNCTION canvas_connector.outbox_lease_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.observation_id='expiry-after-write' AND NEW.phase IN ('acknowledged','retry') THEN PERFORM pg_sleep(0.2); END IF; RETURN NEW; END $$; CREATE TRIGGER outbox_test_delay BEFORE UPDATE ON canvas_connector.observation_outbox FOR EACH ROW EXECUTE FUNCTION canvas_connector.outbox_lease_delay();");
 for(const operation of [()=>repo.acknowledge('outbox-expiry','producer-one',expiring.observation_id,expiring.lease_id,{receipt_id:'too-late',replayed:false}),
  ()=>repo.defer('outbox-expiry','producer-one',expiring.observation_id,expiring.lease_id,'submission_outcome_unknown',null,false)]) {
  await pool.query("UPDATE canvas_connector.observation_outbox SET lease_expires_at=clock_timestamp()+interval '100 milliseconds' WHERE organization_id='outbox-expiry'");
  await assert.rejects(operation,/connector_outbox_unavailable/);
  assert.equal((await state('outbox-expiry','expiry-after-write')).phase,'leased');
  assert.equal((await state('outbox-expiry','expiry-after-write')).receipt_id,null);
 }
 // Process-local pool replacement and actual database restart preserve counters/ledger.
 await pool.close();execFileSync('docker',['restart',container],{stdio:'pipe'});
 const endpoint=execFileSync('docker',['port',container,'5432/tcp'],{encoding:'utf8'}).trim().split('\n')[0];
 assert.match(endpoint,/^127\.0\.0\.1:[0-9]+$/);configuration.port=Number(endpoint.split(':')[1]);fixture.port=configuration.port;
 await writeFile(file,JSON.stringify(fixture));

 for(let i=0;i<50;i++){try{owner('SELECT 1');break;}catch{if(i===49)throw Error('fixture restart failed');await new Promise(r=>setTimeout(r,100));}}
 pool=createConnectorPostgresPool(configuration);repo=createObservationOutbox(pool);
 assert.equal((await repo.enqueue('outbox-seal','producer-one',input('after-restart'))).sequence,2);
 assert.equal((await state('outbox-seal','seal-recovery')).body,original);
 assert.equal((await state('outbox-order','order-first')).phase,'parked');
 console.log('Real PostgreSQL immutable outbox/counters, concurrency, rollback, lease fencing, HTTPS replay/outage and uncertain-commit/restart contracts passed');
} finally {await pool.close();await gateway.close();}
