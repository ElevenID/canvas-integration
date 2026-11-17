// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createConnectorPostgresPool} from '../src/postgres-pool.mjs';
import {createLtiToolKeyStore} from '../src/lti-tool-key-store.mjs';
import {createLtiServiceStore} from '../src/lti-service-store.mjs';
import {createLtiCaptureRepository} from '../src/lti-capture-repository.mjs';
import {createLtiCaptureWorker} from '../src/lti-capture-worker.mjs';
import {prepareLtiCaptureRouteIntent} from '../src/lti-capture-contract.mjs';
import {ltiServiceReadScopes} from '../src/lti-service-contract.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
import {ltiCaptureAdminContract} from './lti-capture-admin-contract.mjs';

export async function ltiCaptureContract(configuration,{servicePool,keyProvider,ownerQuery}) {
 const role='canvas_lti_capture_runtime',password='synthetic-lti-capture-password';
 await ownerQuery(`CREATE ROLE ${role} LOGIN PASSWORD '${password}';GRANT CONNECT ON DATABASE canvas_driver_test TO ${role};
  GRANT USAGE ON SCHEMA canvas_connector TO ${role};
  GRANT SELECT ON canvas_connector.platforms,canvas_connector.lti_registrations,canvas_connector.lti_tool_key_configurations,
   canvas_connector.lti_service_attempts,canvas_connector.lti_service_tokens,
   canvas_connector.lti_capture_routes,canvas_connector.lti_capture_jobs,canvas_connector.observation_counters,canvas_connector.observation_outbox TO ${role};
  GRANT SELECT(organization_id,platform_id,registration_id,kid,platform_version,registration_version,client_id,tool_origin) ON canvas_connector.lti_tool_keys TO ${role};
  GRANT UPDATE(enabled) ON canvas_connector.platforms,canvas_connector.lti_registrations,canvas_connector.lti_capture_routes TO ${role};
  GRANT UPDATE(current_kid) ON canvas_connector.lti_tool_key_configurations TO ${role};
  GRANT UPDATE(phase) ON canvas_connector.lti_service_attempts TO ${role};
  GRANT INSERT(organization_id,capture_id,producer_ref,route_id,route_version,definition,platform_id,registration_id,service_operation_id,
   token_reference,canvas_origin,platform_version,registration_version,key_version,available_at,created_at),
   UPDATE(phase,attempts,available_at,lease_id,lease_expires_at,last_error,completed_lease_id,result) ON canvas_connector.lti_capture_jobs TO ${role};
  GRANT USAGE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq TO ${role};
  GRANT INSERT(organization_id,binding_id),UPDATE(current_sequence) ON canvas_connector.observation_counters TO ${role};
  GRANT INSERT(organization_id,observation_id,producer_ref,binding_id,binding_revision,sequence,observed_at_ms,effective_at_ms,claims)
   ON canvas_connector.observation_outbox TO ${role};
  GRANT EXECUTE ON FUNCTION canvas_connector.lti_visible_identifier(text),canvas_connector.valid_lti_capture_definition(jsonb),
   canvas_connector.lti_service_attempt_view(canvas_connector.lti_service_attempts),canvas_connector.lti_service_attempt_current(canvas_connector.lti_service_attempts),
   canvas_connector.lock_lti_service_configuration(canvas_connector.lti_service_attempts),
   canvas_connector.lti_capture_current(canvas_connector.lti_capture_jobs),canvas_connector.lock_lti_capture_context(canvas_connector.lti_capture_jobs),
   canvas_connector.schedule_lti_capture(text,text,text,bigint,uuid),canvas_connector.claim_lti_capture(text,text),
   canvas_connector.complete_lti_capture(text,text,uuid,uuid,bigint,bigint,jsonb),canvas_connector.defer_lti_capture(text,text,uuid,uuid,text,boolean),
   canvas_connector.valid_outbox_claims(jsonb),canvas_connector.enqueue_observation(text,text,text,bigint,text,bigint,bigint,jsonb) TO ${role};`);
 const pool=createConnectorPostgresPool({...configuration,user:role,credentialProvider:{getPassword:async()=>password}});
 const peer=await httpsFixture();
 try {
  const org=randomUUID(),platform='lti-capture-platform',registration=randomUUID(),operation=randomUUID();
  const keys=createLtiToolKeyStore({pool:servicePool,keyProvider}),tokens=createLtiServiceStore({pool:servicePool,keyProvider});
  const captureTokens=createLtiServiceStore({pool,keyProvider}),repo=createLtiCaptureRepository(pool);
  await ownerQuery(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES('${org}','${platform}','${peer.origin}',true);
   INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
   VALUES('${registration}','${org}','${platform}','capture-client','deployment','hosted_global','production','https://tool.example/lti/registrations/${registration}/resource',true);`);
  await keys.administer({organizationId:org,platformId:platform,registrationId:registration,operationId:randomUUID(),actorId:'operator',action:'provision',
   expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null});
  await tokens.prepare({organizationId:org,platformId:platform,registrationId:registration,operationId:operation,actorId:'operator',expectedPlatformVersion:1,
   expectedRegistrationVersion:1,expectedKeyVersion:1,scopes:Object.values(ltiServiceReadScopes)});
  const attempt=await tokens.begin({organizationId:org,operationId:operation,dispatchId:randomUUID()});
  const bearer='synthetic_capture_lti_bearer_000001';
  await tokens.stage(attempt,{accessToken:bearer,scopes:Object.values(ltiServiceReadScopes)},(attempt.issuedAt+3600)*1000);
  await tokens.publish({organizationId:org,operationId:operation,dispatchId:attempt.dispatchId});
  const route=prepareLtiCaptureRouteIntent({producerRef:'producer',platformId:platform,registrationId:registration,bindingId:'lti-capture-binding',bindingRevision:1,
   requirement:{factType:'canvas.ags_result',courseId:'11',userId:'opaque:user',resourceLinkId:'link-one',lineItemId:'33'},
   claimNames:['score','score_maximum','score_percent'],effectiveTimePolicy:'as_of_read'});
  await ownerQuery(`INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES('${org}','route','producer','${platform}','${registration}','${JSON.stringify(route)}'::jsonb,'${operation}',true);`);
  const schedule=captureId=>({organizationId:org,producerRef:'producer',routeId:'route',expectedRouteVersion:1,captureId});
  const result={observedAtMs:Date.now(),effectiveAtMs:0,claims:{score:8,score_maximum:10,score_percent:80,effective_time_source:'observation_read'}};result.effectiveAtMs=result.observedAtMs;
  const rewritten=randomUUID();
  await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_lti_schedule_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.available_at:=clock_timestamp()+interval '1 day';RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_schedule_rewrite BEFORE INSERT ON canvas_connector.lti_capture_jobs FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_lti_schedule_rewrite();`);
  try{await assert.rejects(repo.schedule(schedule(rewritten)),/lti_capture_repository_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_schedule_rewrite ON canvas_connector.lti_capture_jobs;DROP FUNCTION canvas_connector.synthetic_lti_schedule_rewrite();');}
  assert.equal(await repo.inspect(org,'producer',rewritten),null,'rewritten scheduling time rolls back the job');
  const id=randomUUID();
  assert.deepEqual(await Promise.all(Array.from({length:4},()=>repo.schedule(schedule(id)))),[true,true,true,true]);
  assert.equal(await repo.schedule({...schedule(id),expectedRouteVersion:2}),false);assert.equal(await repo.inspect('foreign','producer',id),null);
  const jobs=await Promise.all(Array.from({length:4},()=>repo.claim(org,'producer')));assert.equal(jobs.filter(Boolean).length,1);
  const job=jobs.find(Boolean);assert.equal(job.captureId,id);assert.equal(job.serviceOperationId,operation);assert.deepEqual(job.definition,route);
  assert.equal(await repo.permit(org,'producer',id,job.leaseId),true);assert.equal(await repo.permit('foreign','producer',id,job.leaseId),false);
  assert.equal(await repo.complete(org,'producer',id,randomUUID(),result),false);
  const lost=createLtiCaptureRepository({async query(sql,values){const r=await pool.query(sql,values);if(sql.includes('complete_lti_capture'))throw Error('lost committed reply');return r;}});
  const completions=await Promise.allSettled([lost.complete(org,'producer',id,job.leaseId,result),
   ...Array.from({length:3},()=>repo.complete(org,'producer',id,job.leaseId,result))]);
  assert.equal(completions[0].status,'rejected');assert.match(completions[0].reason.message,/lti_capture_repository_unavailable/);
  for(const item of completions.slice(1)){assert.equal(item.status,'fulfilled');assert.equal(item.value,true);}
  assert.deepEqual(await repo.inspect(org,'producer',id),{captureId:id,phase:'completed',attempts:1,result});
  assert.equal(await repo.complete(org,'producer',id,job.leaseId,result),true);
  assert.equal(await repo.complete(org,'producer',id,job.leaseId,{...result,claims:{...result.claims,score:9}}),false);
  assert.equal(await repo.complete(org,'producer',id,randomUUID(),result),false);assert.equal(await repo.permit(org,'producer',id,job.leaseId),false);
  assert.equal((await pool.query('SELECT count(*)::float8 AS count FROM canvas_connector.observation_outbox WHERE organization_id=$1',[org])).rows[0].count,1);
  // Actual encrypted token -> keyless Canvas TLS -> atomic durable capture/outbox.
  peer.setHandler((req,res)=>{
   assert.equal(req.method,'GET');assert.equal(req.headers.authorization,'Bearer '+bearer);assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers.cookie,undefined);
   const line=peer.origin+'/api/lti/courses/11/line_items/33';
   if(req.url.startsWith('/api/lti/courses/11/line_items/33/results?'))return json(res,[{id:line+'/results/44',scoreOf:line,userId:'opaque:user',resultScore:8,resultMaximum:10,comment:'private'}]);
   assert.equal(req.url,'/api/lti/courses/11/line_items/33');return json(res,{id:line,scoreMaximum:10,resourceLinkId:'link-one'});
  });
  const worker=createLtiCaptureWorker({repository:repo,tokenStore:captureTokens,organizationId:org,producerRef:'producer',ca:peer.ca,allowedPrivateAddresses:['127.0.0.1','::1']});
  const second=randomUUID();assert.equal(await repo.schedule(schedule(second)),true);assert.deepEqual(await worker.runOnce(),{state:'captured',captureId:second});
  assert.equal(peer.seen.length,2);assert.equal((await repo.inspect(org,'producer',second)).phase,'completed');
  const outbox=(await pool.query('SELECT sequence::float8 AS sequence,claims FROM canvas_connector.observation_outbox WHERE organization_id=$1 ORDER BY sequence',[org])).rows;
  assert.deepEqual(outbox.map(r=>r.sequence),[1,2]);assert.deepEqual(outbox[1].claims,result.claims);
  // A trigger rewrite must roll back both the counter/outbox and completion.
  const third=randomUUID();await repo.schedule(schedule(third));const claimed=await repo.claim(org,'producer');
  await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_lti_capture_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.result:=jsonb_build_object('rewritten',true);RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_capture_rewrite BEFORE UPDATE ON canvas_connector.lti_capture_jobs FOR EACH ROW WHEN(NEW.phase='completed') EXECUTE FUNCTION canvas_connector.synthetic_lti_capture_rewrite();`);
  try {await assert.rejects(repo.complete(org,'producer',third,claimed.leaseId,result),/lti_capture_repository_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_capture_rewrite ON canvas_connector.lti_capture_jobs;DROP FUNCTION canvas_connector.synthetic_lti_capture_rewrite();');}
  assert.equal((await repo.inspect(org,'producer',third)).phase,'leased');
  assert.equal((await pool.query('SELECT current_sequence::float8 AS n FROM canvas_connector.observation_counters WHERE organization_id=$1',[org])).rows[0].n,2);
  await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_lti_counter_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
   BEGIN UPDATE canvas_connector.observation_counters SET current_sequence=current_sequence+1 WHERE organization_id=NEW.organization_id;RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_counter_rewrite AFTER UPDATE ON canvas_connector.lti_capture_jobs FOR EACH ROW WHEN(NEW.phase='completed') EXECUTE FUNCTION canvas_connector.synthetic_lti_counter_rewrite();`);
  try{await assert.rejects(repo.complete(org,'producer',third,claimed.leaseId,result),/lti_capture_repository_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_counter_rewrite ON canvas_connector.lti_capture_jobs;DROP FUNCTION canvas_connector.synthetic_lti_counter_rewrite();');}
  assert.equal((await repo.inspect(org,'producer',third)).phase,'leased');
  assert.equal((await pool.query('SELECT current_sequence::float8 AS n FROM canvas_connector.observation_counters WHERE organization_id=$1',[org])).rows[0].n,2,'post-completion trigger cannot mutate the committed counter');
  assert.equal(await repo.defer(org,'producer',third,claimed.leaseId,'provider_unavailable',false),true);
  assert.equal(await repo.claim(org,'producer'),null,'backoff is retained, no immediate reclaim');
  assert.equal((await repo.inspect(org,'producer',third)).phase,'retry');
  // A changed route invalidates a pending lease and never emits a negative fact.
  await ownerQuery(`UPDATE canvas_connector.lti_capture_routes SET enabled=false WHERE organization_id='${org}';`);
  assert.equal(await repo.schedule(schedule(randomUUID())),false);
  assert.equal(await repo.complete(org,'producer',third,claimed.leaseId,result),false);
  assert.equal(await repo.complete(org,'producer',id,job.leaseId,result),true,'original committed receipt survives current configuration drift');
  assert.equal(await repo.schedule(schedule(id)),true,'original scheduling replay never creates a replacement capture');
  // Separate route avoids the first route's deliberately retained backoff.
  const parkDefinition={...route,bindingId:'lti-capture-park-binding'},parkId=randomUUID();
  await ownerQuery(`INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES('${org}','park-route','producer','${platform}','${registration}','${JSON.stringify(parkDefinition)}'::jsonb,'${operation}',true);`);
  assert.equal(await repo.schedule({...schedule(parkId),routeId:'park-route'}),true);
  const expired=await repo.claim(org,'producer');assert.equal(expired.captureId,parkId);
  await ownerQuery(`UPDATE canvas_connector.lti_capture_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id='${org}' AND capture_id='${parkId}';`);
  assert.equal(await repo.permit(org,'producer',parkId,expired.leaseId),false);
  assert.equal(await repo.complete(org,'producer',parkId,expired.leaseId,result),false);
  const reclaimed=await repo.claim(org,'producer');assert.equal(reclaimed.captureId,parkId);assert.notEqual(reclaimed.leaseId,expired.leaseId);assert.equal(reclaimed.attempts,2);
  assert.equal(await repo.defer(org,'producer',parkId,expired.leaseId,'provider_unavailable',false),false,'old lease never changes replacement lease');
  await ownerQuery(`UPDATE canvas_connector.lti_capture_routes SET enabled=false WHERE organization_id='${org}' AND id='park-route';
   UPDATE canvas_connector.lti_capture_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id='${org}' AND capture_id='${parkId}';
   CREATE FUNCTION canvas_connector.synthetic_lti_parking_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.available_at:=clock_timestamp()+interval '1 day';RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_parking_rewrite BEFORE UPDATE ON canvas_connector.lti_capture_jobs FOR EACH ROW WHEN(NEW.phase='parked') EXECUTE FUNCTION canvas_connector.synthetic_lti_parking_rewrite();`);
  try{await assert.rejects(repo.claim(org,'producer'),/lti_capture_repository_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_parking_rewrite ON canvas_connector.lti_capture_jobs;DROP FUNCTION canvas_connector.synthetic_lti_parking_rewrite();');}
  assert.equal((await repo.inspect(org,'producer',parkId)).phase,'leased');
  assert.equal(await repo.claim(org,'producer'),null);assert.equal((await repo.inspect(org,'producer',parkId)).phase,'parked');
  const collisionDefinition={...route,bindingId:'lti-capture-collision-binding'},collisionId=randomUUID();
  await ownerQuery(`INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES('${org}','collision-route','producer','${platform}','${registration}','${JSON.stringify(collisionDefinition)}'::jsonb,'${operation}',true);`);
  assert.equal(await repo.schedule({...schedule(collisionId),routeId:'collision-route'}),true);
  const collision=await repo.claim(org,'producer');assert.equal(collision.captureId,collisionId);
  await ownerQuery(`SELECT * FROM canvas_connector.enqueue_observation('${org}','producer','lti-capture-collision-binding',1,'${collisionId}',${result.observedAtMs},${result.effectiveAtMs},'${JSON.stringify(result.claims)}'::jsonb);`);
  await assert.rejects(repo.complete(org,'producer',collisionId,collision.leaseId,result),/lti_capture_repository_unavailable/);
  assert.equal((await repo.inspect(org,'producer',collisionId)).phase,'leased','matching outbox content from another pipeline is not a committed LTI receipt');
  for(const sql of ['DELETE FROM canvas_connector.lti_capture_jobs',"UPDATE canvas_connector.lti_capture_jobs SET definition='{}'::jsonb",'UPDATE canvas_connector.lti_capture_routes SET version=version',
   'UPDATE canvas_connector.lti_service_tokens SET expires_at=clock_timestamp()',
   ...['ciphertext','nonce','tag','wrapping_key_id'].map(column=>`SELECT ${column} FROM canvas_connector.lti_tool_keys`)])await assert.rejects(pool.query(sql));
  await ltiCaptureAdminContract(configuration,{organizationId:org,platformId:platform,registrationId:registration,serviceOperationId:operation,definition:route,ownerQuery});
  console.log('Actual restricted TLS PG/OpenBao LTI capture original-ID/concurrency/lease/config/rollback and keyless Canvas read -> atomic existing outbox PASS');
 }finally{await peer.close();await pool.close();}
}
