// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {request} from 'node:https';
import {createConnectorPostgresPool} from '../src/postgres-pool.mjs';
import {createLtiCaptureAdminStore} from '../src/lti-capture-admin-store.mjs';
import {createGatewayAdminAuthenticator} from '../src/gateway-admin-auth.mjs';
import {createGatewayBindingReader} from '../src/gateway-binding-reader.mjs';
import {createConnectorHttpsService} from '../src/connector-https-service.mjs';
import {preflightLtiCaptureAdministration} from '../src/lti-capture-admin-preflight.mjs';
import PgClient from 'pg/lib/client.js';
import {ltiScheduledCaptureId} from '../src/lti-capture-scheduler.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';

export async function ltiCaptureAdminContract(configuration,{organizationId:org,platformId:platform,registrationId:registration,serviceOperationId:service,definition,ownerQuery}) {
 const role='canvas_lti_capture_admin',password='synthetic-lti-capture-admin-password';
 await ownerQuery(`CREATE ROLE ${role} LOGIN PASSWORD '${password}';GRANT canvas_lti_services TO ${role};
  GRANT SELECT ON canvas_connector.lti_capture_routes,canvas_connector.lti_capture_jobs,canvas_connector.lti_capture_operation_audit TO ${role};
  GRANT INSERT(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled),
   UPDATE(definition,service_operation_id,enabled) ON canvas_connector.lti_capture_routes TO ${role};
  GRANT INSERT(organization_id,capture_id,producer_ref,route_id,route_version,definition,platform_id,registration_id,service_operation_id,
   token_reference,canvas_origin,platform_version,registration_version,key_version,available_at,created_at) ON canvas_connector.lti_capture_jobs TO ${role};
  GRANT USAGE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq TO ${role};
  GRANT INSERT(organization_id,operation_id,platform_id,registration_id,route_id,actor_id,action,request,receipt) ON canvas_connector.lti_capture_operation_audit TO ${role};
  GRANT EXECUTE ON FUNCTION canvas_connector.valid_lti_capture_definition(jsonb),canvas_connector.lti_capture_current(canvas_connector.lti_capture_jobs),
   canvas_connector.lock_lti_capture_context(canvas_connector.lti_capture_jobs),canvas_connector.schedule_lti_capture(text,text,text,bigint,uuid) TO ${role};
  GRANT EXECUTE ON FUNCTION canvas_connector.administer_lti_capture(text,text,uuid,text,uuid,text,text,bigint,bigint,bigint,bigint,uuid,jsonb,bigint) TO ${role};`);
 const pool=createConnectorPostgresPool({...configuration,user:role,credentialProvider:{getPassword:async()=>password}}),store=createLtiCaptureAdminStore(pool);
 const gateway=await httpsFixture();let listener;
 const scope={organizationId:org,platformId:platform,registrationId:registration,routeId:'admin-route'};
 const command=(action,version=1)=>({...scope,operationId:randomUUID(),actorId:'operator',action,...action==='create'?{}:{expectedRouteVersion:version},
  ...action==='deactivate'?{}:{expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1,serviceOperationId:service},
  ...['create','replace'].includes(action)?{definition:{...definition,bindingId:'lti-admin-binding'}}:{}});
 const apply=v=>store.apply(v,async()=>true,Date.now()+30000);
 try {
  await preflightLtiCaptureAdministration(pool);
  for(const [bad,restore] of [
   [`GRANT UPDATE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq TO ${role}`,`REVOKE UPDATE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq FROM ${role}`],
   [`GRANT UPDATE(phase) ON canvas_connector.lti_capture_jobs TO ${role}`,`REVOKE UPDATE(phase) ON canvas_connector.lti_capture_jobs FROM ${role}`],
   [`REVOKE INSERT(created_at) ON canvas_connector.lti_capture_jobs FROM ${role}`,`GRANT INSERT(created_at) ON canvas_connector.lti_capture_jobs TO ${role}`],
   [`ALTER TABLE canvas_connector.lti_capture_operation_audit DISABLE TRIGGER lti_capture_audit_immutable`,`ALTER TABLE canvas_connector.lti_capture_operation_audit ENABLE TRIGGER lti_capture_audit_immutable`],
   [`ALTER FUNCTION canvas_connector.schedule_lti_capture(text,text,text,bigint,uuid) SECURITY DEFINER`,`ALTER FUNCTION canvas_connector.schedule_lti_capture(text,text,text,bigint,uuid) SECURITY INVOKER`],
   [`CREATE ROLE canvas_lti_capture_hidden NOINHERIT;GRANT INSERT(created_at) ON canvas_connector.lti_capture_operation_audit TO canvas_lti_capture_hidden;GRANT canvas_lti_capture_hidden TO ${role} WITH INHERIT FALSE`,
    `REVOKE canvas_lti_capture_hidden FROM ${role};DROP OWNED BY canvas_lti_capture_hidden;DROP ROLE canvas_lti_capture_hidden`],
   [`CREATE ROLE canvas_lti_capture_sequence_hidden NOINHERIT;GRANT UPDATE ON SEQUENCE canvas_connector.lti_capture_jobs_ordinal_seq TO canvas_lti_capture_sequence_hidden;GRANT canvas_lti_capture_sequence_hidden TO ${role} WITH INHERIT FALSE`,
    `REVOKE canvas_lti_capture_sequence_hidden FROM ${role};DROP OWNED BY canvas_lti_capture_sequence_hidden;DROP ROLE canvas_lti_capture_sequence_hidden`],
  ]) {
   await ownerQuery(bad);try{await assert.rejects(preflightLtiCaptureAdministration(pool),/lti_capture_admin_runtime_unavailable/);}
   finally{await ownerQuery(restore);}await preflightLtiCaptureAdministration(pool);
  }
  const create=command('create'),receipts=await Promise.all(Array.from({length:4},()=>apply(create)));
  assert.ok(receipts[0]);for(const r of receipts)assert.deepEqual(r,receipts[0]);assert.equal(receipts[0].enabled,false);
  assert.equal((await store.replay({...create,actorId:'other'})).conflict,true);
  assert.equal(await apply({...command('activate'),expectedKeyVersion:2}),null);
  const active=await apply(command('activate'));assert.equal(active.version,2);assert.equal(active.enabled,true);
  const scheduled=command('schedule',2),result=await apply(scheduled);assert.equal(result.captureId,scheduled.operationId);assert.equal(result.version,2);
  assert.deepEqual(await apply(scheduled),result);assert.equal((await store.capture({...scope,captureId:scheduled.operationId})).phase,'pending');
  assert.equal(await store.inspect({...scope,organizationId:'foreign'}),null);
  assert.equal(await store.receipt({...scope,operationId:create.operationId,registrationId:randomUUID()}),null);
  const lost=createLtiCaptureAdminStore({async query(sql,values){const r=await pool.query(sql,values);if(sql.includes('administer_lti_capture'))throw Error('lost committed reply');return r;}});
  const replace=command('replace',2);
  await assert.rejects(lost.apply(replace,async()=>true,Date.now()+30000),/lti_capture_admin_unavailable/);
  assert.deepEqual((await store.replay(replace)).receipt,await apply(replace));assert.equal((await store.inspect(scope)).version,3);
  const live=await apply(command('activate',3));assert.equal(live.version,4);
  // An automatic scheduler can commit while an administrator waits for the
  // parent lock, after the administrator's first absence check.
  const raceRoute='admin-race-route',raceProducer='admin-race-producer',raceDefinition={...definition,producerRef:raceProducer,bindingId:'lti-admin-race-binding'};
  await ownerQuery(`INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES('${org}','${raceRoute}','${raceProducer}','${platform}','${registration}','${JSON.stringify(raceDefinition)}'::jsonb,'${service}',true);`);
  const raceSchedule={organizationId:org,producerRef:raceProducer,routeId:raceRoute,configurationId:randomUUID(),expectedRevision:0,routeVersion:1,intervalMs:60000,enabled:true};
  const raceId=ltiScheduledCaptureId(raceSchedule,1);
  const blocker=new PgClient({host:configuration.host,port:configuration.port,database:configuration.database,user:'canvas_lti_capture_runtime',password:'synthetic-lti-capture-password',
   ssl:{ca:configuration.ca,rejectUnauthorized:true},connectionTimeoutMillis:1000,query_timeout:5000,statement_timeout:5000});
  await blocker.connect();let pending;
  try {
   await blocker.query('BEGIN');const pid=(await blocker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
   await blocker.query('SELECT id FROM canvas_connector.platforms WHERE organization_id=$1 AND id=$2 FOR UPDATE',[org,platform]);
   pending=apply({...command('schedule'),routeId:raceRoute,operationId:raceId}).then(value=>({value}),error=>({error}));
   let waiting=false;
   for(let i=0;i<40;i++) {
    waiting=(await pool.query('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid))) AS waiting',[pid])).rows[0].waiting;
    if(waiting)break;await new Promise(r=>setTimeout(r,25));
   }
   assert.equal(waiting,true,'original admin operation reached its parent lock wait');
   const automatic=(await blocker.query('SELECT canvas_connector.tick_lti_capture_schedule($1,$2,$3,$4::uuid,0,1,60000,true) AS result',[org,raceProducer,raceRoute,raceSchedule.configurationId])).rows[0].result;
   assert.equal(automatic.capture.captureId,raceId);assert.equal(automatic.enqueued,true);await blocker.query('COMMIT');
   const completed=await pending;if(completed.error)throw completed.error;assert.equal(completed.value,null);
   assert.equal(await store.receipt({...scope,routeId:raceRoute,operationId:raceId}),null,'automatic capture cannot be adopted into an admin receipt');
  }finally{await blocker.query('ROLLBACK').catch(()=>{});await pending;await blocker.end();}
  // Audit-time mutation of the newly scheduled job must roll back job and audit.
  await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_lti_admin_job() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
   BEGIN UPDATE canvas_connector.lti_capture_jobs SET phase='parked' WHERE organization_id=NEW.organization_id AND capture_id=NEW.operation_id;RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_admin_job AFTER INSERT ON canvas_connector.lti_capture_operation_audit FOR EACH ROW WHEN(NEW.action='schedule') EXECUTE FUNCTION canvas_connector.synthetic_lti_admin_job();`);
  const badSchedule=command('schedule',4);
  try{await assert.rejects(apply(badSchedule),/lti_capture_admin_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_admin_job ON canvas_connector.lti_capture_operation_audit;DROP FUNCTION canvas_connector.synthetic_lti_admin_job();');}
  assert.equal(await store.capture({...scope,captureId:badSchedule.operationId}),null);assert.equal(await store.receipt({...scope,operationId:badSchedule.operationId}),null);
  // An ephemeral Gateway snapshot deadline must survive SQL lock/trigger waits.
  const deadline=command('create');deadline.routeId='deadline-route';deadline.definition={...deadline.definition,bindingId:'lti-deadline-binding'};
  await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_lti_admin_deadline() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.7);RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_admin_deadline BEFORE INSERT ON canvas_connector.lti_capture_operation_audit FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_lti_admin_deadline();`);
  try{await assert.rejects(store.apply(deadline,async()=>true,Date.now()+500),/lti_capture_admin_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_admin_deadline ON canvas_connector.lti_capture_operation_audit;DROP FUNCTION canvas_connector.synthetic_lti_admin_deadline();');}
  assert.equal(await store.inspect(deadline),null);assert.equal(await store.receipt(deadline),null);
  assert.equal(await store.apply(deadline,async()=>true,Date.now()-1),null);
  assert.deepEqual(await store.apply(create,async()=>true,1),receipts[0],'original history survives expired transient deadline');
  let permitted=true,bindingAllowed=true,currentOrg=org;
  const publicOrigin='https://localhost',canvasOrigin=(await store.platform(scope)).canvasOrigin;
  const record={id:'lti-http-binding',revision:1,active:true,source_id:'producer',provider:'canvas',fact_type:'canvas.ags_result',application_status:'pending',
   application_revision:1,application_expires_at_ms:Date.now()+60000,subject_id:'private-subject',application_id:'private-application',
   resource_scope:{canvas_origin:canvasOrigin,registration_id:registration,course_id:'11',user_id:'opaque:user',resource_link_id:'link-one',line_item_id:'33'},
   claim_rules:{score:{kind:'number',required:true,nullable:true,minimum:-10000,maximum:10000},score_maximum:{kind:'number',required:true,nullable:true,minimum:0,maximum:10000},
    score_percent:{kind:'number',required:true,nullable:true,minimum:-10000,maximum:10000},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:64}}};
  gateway.setHandler(async(req,res)=>{
   assert.equal(req.headers.cookie,'session=synthetic_operator_session_000001');assert.equal(req.headers['x-api-key'],undefined);assert.equal(req.headers['x-organization-id'],undefined);
   if(req.url==='/v1/auth/me')return json(res,{authenticated:true,user:{user_id:'operator',organization_id:currentOrg}});
   if(req.url.endsWith('/members/me/permissions'))return json(res,{permissions:permitted?['integration-connector:edit']:[]});
   if(req.url===`/v1/organizations/${org}/external-observation-bindings/lti-http-binding/inspect`) {
    assert.equal(req.method,'POST');let b='';for await(const c of req)b+=c;assert.equal(b,'{}');
    return bindingAllowed?json(res,{found:true,record,snapshot_at_ms:Date.now()},200,{'Cache-Control':'no-store'}):json(res,{},403);
   }
   return json(res,{},404);
  });
  const auth={gatewayOrigin:gateway.origin,adminOrigin:publicOrigin,sessionCookieName:'session',ca:gateway.ca};
  let revokeAfterCommit=false;
  const httpStore=createLtiCaptureAdminStore({async query(sql,values){const r=await pool.query(sql,values);if(revokeAfterCommit&&sql.includes('administer_lti_capture')){revokeAfterCommit=false;permitted=false;}return r;}});
  listener=createConnectorHttpsService({publicOrigin,completionUrl:publicOrigin+'/complete',tls:{key:gateway.key,cert:gateway.ca},port:0,
   lifecycle:{start:async()=>{throw Error('unused');},callback:async()=>{throw Error('unused');}},rateLimiter:{consume:async()=>true},
   authenticateAndAuthorize:createGatewayAdminAuthenticator(auth),readBinding:createGatewayBindingReader(auth),ltiCaptureStore:httpStore});
  const address=await listener.listen();
  const call=(action,fields={},routeId='http-route',registrationId=registration)=>new Promise((resolve,reject)=>{
   const body=new URLSearchParams(fields).toString(),path=routeId===null?`/platforms/${platform}/lti/registrations/${registrationId}/capture-routes/catalog`:
    `/platforms/${platform}/lti/registrations/${registrationId}/capture-routes/${routeId}/${action}`;
   const req=request({hostname:'localhost',port:address.port,path,method:'POST',ca:gateway.ca,agent:false,rejectUnauthorized:true,
    headers:{Host:'localhost',Origin:publicOrigin,Cookie:'session=synthetic_operator_session_000001','Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}},res=>{
     const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));
    });req.on('error',reject);req.end(body);
  });
  const httpCreate={operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1',expected_key_version:'1',service_operation_id:service,
   producer_ref:'producer',binding_id:'lti-http-binding',binding_revision:'1',requirement:JSON.stringify(definition.requirement),claim_names:JSON.stringify(definition.claimNames),effective_time_policy:'as_of_read'};
  assert.equal((await call('create',{...httpCreate,organization_id:'foreign'})).status,400);
  record.resource_scope.resource_link_id='other';assert.equal((await call('create',httpCreate)).status,409);record.resource_scope.resource_link_id='link-one';
  const created=await call('create',httpCreate);assert.equal(created.status,200);const original=JSON.parse(created.body).receipt;
  assert.equal(/private-subject|private-application|ciphertext|accessToken/.test(created.body),false);
  const mutation=v=>({operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1',expected_key_version:'1',service_operation_id:service,expected_route_version:String(v)});
  assert.equal((await call('activate',mutation(1))).status,200);
  const schedule=mutation(2);revokeAfterCommit=true;assert.equal((await call('schedule',schedule)).status,403);permitted=true;
  const recovered=await call('receipt',{operation_id:schedule.operation_id});assert.equal(recovered.status,200);assert.equal(JSON.parse(recovered.body).receipt.captureId,schedule.operation_id);
  bindingAllowed=false;record.application_status='approved';
  assert.deepEqual(JSON.parse((await call('create',httpCreate)).body).receipt,original);
  assert.equal((await call('activate',mutation(2))).status,403);
  assert.equal((await call('deactivate',{operation_id:randomUUID(),expected_route_version:'2'})).status,200);
  currentOrg=randomUUID();assert.equal(JSON.parse((await call('inspect')).body).route,null);currentOrg=org;
  assert.deepEqual(JSON.parse((await call('catalog',{},null,randomUUID())).body),{routes:[],nextCursor:null});
  // Deactivation cannot silently mutate a disabled parent through an audit hook.
  await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${org}' AND id='${platform}';
   CREATE FUNCTION canvas_connector.synthetic_lti_admin_parent() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN UPDATE canvas_connector.platforms SET enabled=true WHERE organization_id=NEW.organization_id AND id=NEW.platform_id;RETURN NEW;END;$$;
   CREATE TRIGGER synthetic_lti_admin_parent AFTER INSERT ON canvas_connector.lti_capture_operation_audit FOR EACH ROW WHEN(NEW.action='deactivate') EXECUTE FUNCTION canvas_connector.synthetic_lti_admin_parent();`);
  const disable=command('deactivate',4);
  try{await assert.rejects(apply(disable),/lti_capture_admin_unavailable/);}
  finally{await ownerQuery('DROP TRIGGER synthetic_lti_admin_parent ON canvas_connector.lti_capture_operation_audit;DROP FUNCTION canvas_connector.synthetic_lti_admin_parent();');}
  assert.equal((await store.platform(scope)).enabled,false);assert.equal((await store.inspect(scope)).enabled,true);
  assert.equal((await apply(disable)).enabled,false);assert.deepEqual(await apply(create),receipts[0]);
  for(const sql of ['DELETE FROM canvas_connector.lti_capture_operation_audit',"UPDATE canvas_connector.lti_capture_operation_audit SET actor_id='other'",'UPDATE canvas_connector.lti_capture_routes SET version=99',
   'UPDATE canvas_connector.lti_capture_jobs SET phase=phase',"SELECT * FROM canvas_connector.claim_lti_capture('x','y')"])await assert.rejects(pool.query(sql));
  console.log('Actual public Gateway TLS authority/binding -> connector HTTPS -> restricted LTI route CAS/audit/schedule/receipt, transient deadline, postimage rollback and history PASS');
 }finally{await listener?.close();await gateway.close();await pool.close();}
}
