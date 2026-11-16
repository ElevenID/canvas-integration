// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createCaptureRouteAdminStore} from '../src/capture-route-admin-store.mjs';
import {createPlatformAdminStore} from '../src/platform-admin.mjs';
export async function captureRouteAdministrationContract(pool,{ownerQuery}={}) {
  const query=(sql,values=[])=>pool.query(sql,values),owner=ownerQuery??query;
  const store=createCaptureRouteAdminStore(pool),platforms=createPlatformAdminStore(pool);
  const organizationId='capture-admin-'+randomUUID(),platformId='platform',routeId='route',scope={organizationId,platformId,routeId};
  await platforms.apply({organizationId,platformId,operationId:randomUUID(),actorId:'operator',action:'create',canvasOrigin:'https://canvas.example.test'});
  await platforms.apply({organizationId,platformId,operationId:randomUUID(),actorId:'operator',action:'change',expectedVersion:1,enabled:true,archived:false});
  const definition={producerRef:'source-one',platformId,bindingId:'binding-one',bindingRevision:1,
    requirement:{factType:'canvas.assignment_score',courseId:'11',userId:'22',activityId:'33'},claimNames:['completed','score'],effectiveTimePolicy:'require_provider_time'};
  const op=(action,expectedRouteVersion,extra={})=>({...scope,operationId:randomUUID(),actorId:'operator',action,
    ...(expectedRouteVersion===undefined?{}:{expectedRouteVersion}),...(action==='deactivate'?{}:{expectedPlatformVersion:2,definition}),...extra});
  const create=op('create'),created=await store.apply(create);assert.equal(created.version,1);assert.equal(created.enabled,false);
  assert.deepEqual(await store.apply(create),created);assert.deepEqual(await store.replay(create),{conflict:false,receipt:created});
  assert.deepEqual(await store.receipt(create),created);assert.equal((await store.inspect(scope)).definition.requirement.userId,'22');
  assert.equal(await store.apply({...create,operationId:randomUUID()}),null);
  assert.equal(await store.apply({...create,actorId:'different'}),null);
  assert.deepEqual(await store.replay({...create,actorId:'different'}),{conflict:true});
  assert.equal(await store.inspect({...scope,organizationId:'foreign'}),null);
  assert.equal(await store.receipt({...create,platformId:'foreign'}),null);
  assert.equal(await store.apply(op('activate',1)),null,'activation requires a current connection');
  await query(`INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,
    client_id,client_secret_ref,access_token_ref,capabilities,scopes,status,token_expires_at)
    VALUES($1,$2,2,'https://canvas.example.test','client','client-reference','access-reference',ARRAY['native_activity_scores'],
      ARRAY['url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id','url:GET|/api/v1/courses/:course_id/assignments/:id'],
      'connected',clock_timestamp()+interval '5 minutes')`,[organizationId,platformId]);
  const activate=op('activate',1),active=await store.apply(activate);assert.equal(active.version,2);assert.equal(active.enabled,true);
  assert.equal(await store.apply(op('activate',2)),null);
  const schedule=op('schedule',2),scheduled=await store.apply(schedule);
  assert.equal(scheduled.captureId,schedule.operationId);assert.equal(scheduled.version,2);
  assert.deepEqual(await store.apply(schedule),scheduled);
  const capture=await store.capture({...scope,captureId:scheduled.captureId});assert.equal(capture.phase,'pending');assert.equal(capture.attempts,0);
  assert.ok(!JSON.stringify(capture).includes('reference'),'inspection never exposes token references');
  const disabled=await store.apply(op('deactivate',2));assert.equal(disabled.version,3);assert.equal(disabled.enabled,false);
  const {definition:discarded,...originalSchedule}=schedule;
  assert.deepEqual(await store.replay(originalSchedule),{conflict:false,receipt:scheduled});
  assert.deepEqual(await store.apply(originalSchedule),scheduled,'post-disable retry returns history before current state');
  assert.equal(await store.apply(op('schedule',3)),null);
  assert.equal((await query('SELECT count(*)::integer AS n FROM canvas_connector.rest_capture_jobs WHERE organization_id=$1',[organizationId])).rows[0].n,1);
  assert.equal(await store.apply(op('replace',3)),null,'disabled identical replacement is not a new operation');
  const changed={...definition,bindingRevision:2,requirement:{...definition.requirement,activityId:'44'}};
  const replaced=await store.apply(op('replace',3,{definition:changed}));assert.equal(replaced.version,4);assert.equal(replaced.enabled,false);
  assert.equal(await store.apply(op('activate',4)),null,'checked definition must match the locked current route');
  assert.equal(await store.apply(op('replace',4,{definition:{...changed,producerRef:'different-source'}})),null);
  await assert.rejects(query("UPDATE canvas_connector.rest_capture_routes SET platform_id='different' WHERE organization_id=$1",[organizationId]));
  await assert.rejects(query("UPDATE canvas_connector.rest_capture_routes SET producer_ref='different' WHERE organization_id=$1",[organizationId]));
  await assert.rejects(query('DELETE FROM canvas_connector.rest_route_operation_audit WHERE organization_id=$1',[organizationId]));
  // Original UUID retries serialize even when every writer initially sees no row.
  const concurrent=op('create',undefined,{routeId:'concurrent',definition:{...definition,bindingId:'concurrent-binding'}});
  const results=await Promise.all(Array.from({length:8},()=>store.apply(concurrent)));
  assert.ok(results.every(value=>JSON.stringify(value)===JSON.stringify(results[0])));
  assert.equal((await query('SELECT count(*)::integer AS n FROM canvas_connector.rest_route_operation_audit WHERE organization_id=$1 AND operation_id=$2',[organizationId,concurrent.operationId])).rows[0].n,1);
  await owner(`CREATE FUNCTION canvas_connector.capture_admin_before_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_TABLE_NAME='rest_capture_routes' AND NEW.id='before-route' THEN NEW.enabled:=true; END IF;
    RETURN NEW; END $$;
    CREATE TRIGGER capture_admin_before_fault BEFORE INSERT ON canvas_connector.rest_capture_routes
      FOR EACH ROW EXECUTE FUNCTION canvas_connector.capture_admin_before_fault();`);
  try {
    await assert.rejects(store.apply(op('create',undefined,{routeId:'before-route',definition:{...definition,bindingId:'before-binding'}})));
    assert.equal(await store.inspect({...scope,routeId:'before-route'}),null);
  } finally {await owner('DROP TRIGGER capture_admin_before_fault ON canvas_connector.rest_capture_routes; DROP FUNCTION canvas_connector.capture_admin_before_fault();');}
  await owner(`CREATE FUNCTION canvas_connector.capture_admin_before_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    NEW.requirement:=jsonb_set(NEW.requirement,'{userId}','"999"'::jsonb);RETURN NEW; END $$;
    CREATE TRIGGER capture_admin_before_job BEFORE INSERT ON canvas_connector.rest_capture_jobs
      FOR EACH ROW EXECUTE FUNCTION canvas_connector.capture_admin_before_job();`);
  try {
    const poisoned=op('schedule',1,{routeId:'concurrent',definition:concurrent.definition});
    await store.apply({...poisoned,operationId:randomUUID(),action:'activate'});
    await assert.rejects(store.apply({...poisoned,expectedRouteVersion:2}));
    assert.equal(await store.capture({...scope,routeId:'concurrent',captureId:poisoned.operationId}),null);
    assert.equal(await store.receipt({...poisoned}),null);
  } finally {await owner('DROP TRIGGER capture_admin_before_job ON canvas_connector.rest_capture_jobs; DROP FUNCTION canvas_connector.capture_admin_before_job();');}
  const faultDefinition={...definition,bindingId:'fault-binding'};
  await owner(`CREATE FUNCTION canvas_connector.capture_admin_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.actor_id='synthetic-fault' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF;
    IF NEW.actor_id='synthetic-change' THEN UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=NEW.organization_id AND id=NEW.platform_id; END IF;
    IF NEW.actor_id='synthetic-audit-rewrite' THEN NEW.receipt:=NEW.receipt||'{"forged":true}'::jsonb; END IF;
    IF NEW.actor_id='synthetic-expiry' THEN PERFORM pg_sleep(1.5); END IF;
    RETURN NEW; END $$; CREATE TRIGGER capture_admin_test_fault BEFORE INSERT ON canvas_connector.rest_route_operation_audit
    FOR EACH ROW EXECUTE FUNCTION canvas_connector.capture_admin_test_fault();`);
  try {
    for(const actorId of ['synthetic-fault','synthetic-change','synthetic-audit-rewrite']) {
      await assert.rejects(store.apply(op('create',undefined,{routeId:'rollback',actorId,definition:faultDefinition})));
      assert.equal(await store.inspect({...scope,routeId:'rollback'}),null);assert.equal((await store.platform(scope)).enabled,true);
    }
    await query("UPDATE canvas_connector.connections SET token_expires_at=clock_timestamp()+interval '1 second' WHERE organization_id=$1 AND platform_id=$2",[organizationId,platformId]);
    await assert.rejects(store.apply(op('activate',4,{definition:changed,actorId:'synthetic-expiry'})));
    assert.equal((await store.inspect(scope)).version,4);assert.equal((await store.inspect(scope)).enabled,false);
  } finally {await owner('DROP TRIGGER capture_admin_test_fault ON canvas_connector.rest_route_operation_audit; DROP FUNCTION canvas_connector.capture_admin_test_fault();');}
  const lostValue=op('create',undefined,{routeId:'unknown-reply',definition:{...definition,bindingId:'unknown-reply-binding'}});let calls=0;
  const lost=createCaptureRouteAdminStore({query:async(sql,values)=>{calls++;await query(sql,values);throw Error('synthetic committed reply loss');}});
  await assert.rejects(lost.apply(lostValue));assert.equal(calls,1);assert.ok(await store.receipt(lostValue));
  assert.deepEqual(await store.apply(lostValue),await store.receipt(lostValue));
  const pageOrg=organizationId+'-page';
  await platforms.apply({organizationId:pageOrg,platformId,operationId:randomUUID(),actorId:'operator',action:'create',canvasOrigin:'https://canvas.example.test'});
  for(let i=0;i<25;i++) await store.apply({...create,organizationId:pageOrg,routeId:'r'+String(i).padStart(2,'0'),operationId:randomUUID(),expectedPlatformVersion:1,definition:{...definition,bindingId:'b'+i}});
  const first=await store.catalog({organizationId:pageOrg,platformId});assert.equal(first.routes.length,20);assert.equal(first.nextCursor,'r19');
  const second=await store.catalog({organizationId:pageOrg,platformId,afterId:first.nextCursor});assert.equal(second.routes.length,5);assert.equal(second.nextCursor,null);
  assert.deepEqual(await store.catalog({organizationId:'foreign',platformId}),{routes:[],nextCursor:null});
  console.log('Actual PostgreSQL capture-route CAS/activation/current connection/schedule/disabling history/8-way replay/identity/audit/rollback/late expiry/unknown reply/bounded catalog passed');
}
