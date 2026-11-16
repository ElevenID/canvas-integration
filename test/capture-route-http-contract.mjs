// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
export async function captureRouteHttpContract({send,address,organizationId,canvasOrigin,pool,limitedPool,gateway,owner,bindings,setBindingAllowed}) {
  const query=(sql,values=[])=>pool.query(sql,values),path='/platforms/managed-platform/capture-routes/route/';
  const bindingId='managed-route-binding';
  const record={id:bindingId,source_id:'source-one',provider:'canvas',fact_type:'canvas.assignment_score',revision:3,active:true,
    resource_scope:{canvas_origin:canvasOrigin,course_id:'11',user_id:'22',activity_id:'33'},
    application_id:'private-core-application',subject_id:'private-core-subject',application_status:'pending',
    application_revision:1794844800000000,application_expires_at_ms:Date.now()+600000,
    claim_rules:{completed:{kind:'boolean',required:true,nullable:false},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}}};
  bindings.set(bindingId,record);
  const call=async(action,fields={})=>await send(address,{path:path+action,body:new URLSearchParams(fields).toString()}).response;
  const create={operation_id:randomUUID(),expected_platform_version:'2',producer_ref:'source-one',binding_id:bindingId,binding_revision:'3',
    requirement:JSON.stringify({factType:'canvas.assignment_score',courseId:'11',userId:'22',activityId:'33'}),claim_names:'["completed"]',effective_time_policy:'require_provider_time'};
  // These assertions concern authority, not a freshly reset clock boundary.
  // Explicit quota and backwards-clock contracts run separately in the caller.
  owner("UPDATE canvas_connector.oauth_http_limit SET hits=0,window_started_at=clock_timestamp()-interval '1 second';");
  setBindingAllowed(false);assert.equal((await call('create',create)).status,403);setBindingAllowed(true);
  record.resource_scope.user_id='wrong-learner';assert.equal((await call('create',create)).status,409);record.resource_scope.user_id='22';
  const created=await call('create',create);assert.equal(created.status,200);const original=JSON.parse(created.body).receipt;
  assert.equal(original.version,1);assert.equal(original.enabled,false);assert.equal(original.actorId,'actor');
  assert.equal(created.headers['cache-control'],'no-store');
  for(const privateValue of ['private-core-application','private-core-subject','access-reference','client-reference']) assert.equal(created.body.includes(privateValue),false);
  const mutation=version=>({operation_id:randomUUID(),expected_platform_version:'2',expected_route_version:String(version)});
  assert.equal((await call('activate',mutation(1))).status,409,'no connected OAuth metadata');
  await query(`INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,
    client_id,client_secret_ref,access_token_ref,capabilities,scopes,status,token_expires_at)
    VALUES($1,'managed-platform',2,$2,'synthetic-route-client','client-reference','access-reference',ARRAY['catalog'],ARRAY['read'],
      'connected',clock_timestamp()+interval '5 minutes')`,[organizationId,canvasOrigin]);
  assert.equal((await call('activate',mutation(1))).status,409,'OAuth capabilities/scopes are required');
  await query(`UPDATE canvas_connector.connections SET capabilities=ARRAY['native_activity_scores'],scopes=ARRAY[
    'url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id','url:GET|/api/v1/courses/:course_id/assignments/:id']
    WHERE organization_id=$1 AND platform_id='managed-platform'`,[organizationId]);
  const activated=await call('activate',mutation(1));assert.equal(activated.status,200);assert.equal(JSON.parse(activated.body).receipt.version,2);
  const schedule=mutation(2),scheduled=await call('schedule',schedule);assert.equal(scheduled.status,200);
  const receipt=JSON.parse(scheduled.body).receipt;assert.equal(receipt.captureId,schedule.operation_id);assert.equal(receipt.version,2);
  const inspection=await call('capture',{capture_id:receipt.captureId});assert.equal(inspection.status,200);
  assert.equal(JSON.parse(inspection.body).capture.phase,'pending');
  assert.equal((await limitedPool.query('SELECT current_user AS identity')).rows[0].identity,'canvas_oauth_http');
  for(const privateValue of ['access-reference','client-reference','private-core-subject']) assert.equal(inspection.body.includes(privateValue),false);
  for(const sql of ['SELECT access_token_ref FROM canvas_connector.rest_capture_jobs','SELECT * FROM canvas_connector.rest_capture_jobs',
    "UPDATE canvas_connector.rest_capture_jobs SET phase='completed'",'DELETE FROM canvas_connector.rest_capture_jobs',
    "UPDATE canvas_connector.rest_capture_routes SET binding_id='forged'",'UPDATE canvas_connector.rest_capture_routes SET version=99',
    'DELETE FROM canvas_connector.rest_route_operation_audit']) await assert.rejects(limitedPool.query(sql));
  // Closed/revoked Core binding stops new actions. Original history and local
  // disable stay available without a new binding read or authority refresh.
  setBindingAllowed(false);record.application_status='approved';
  const before=gateway.seen.filter(item=>item.method==='POST' && item.url.includes('/external-observation-bindings/')).length;
  const disable=await call('deactivate',{operation_id:randomUUID(),expected_route_version:'2'});assert.equal(disable.status,200);
  assert.deepEqual(JSON.parse((await call('schedule',schedule)).body).receipt,receipt);
  assert.deepEqual(JSON.parse((await call('create',create)).body).receipt,original);
  assert.deepEqual(JSON.parse((await call('receipt',{operation_id:schedule.operation_id})).body).receipt,receipt);
  assert.equal(gateway.seen.filter(item=>item.method==='POST' && item.url.includes('/external-observation-bindings/')).length,before);
  assert.equal((await call('activate',mutation(3))).status,403,'new actions still require the current Core binding permission');
  assert.equal((await query('SELECT count(*)::integer AS n FROM canvas_connector.rest_capture_jobs WHERE organization_id=$1 AND capture_id=$2',[organizationId,receipt.captureId])).rows[0].n,1);
  record.application_status='pending';setBindingAllowed(true);
  const badScope=await send(address,{path:'/platforms/foreign-platform/capture-routes/route/inspect',body:''}).response;
  assert.equal(badScope.status,200);assert.equal(JSON.parse(badScope.body).route,null);
  const rows=JSON.parse((await send(address,{path:'/platforms/managed-platform/capture-routes/catalog',body:''}).response).body);
  assert.equal(rows.routes.length,1);assert.equal(rows.routes[0].routeId,'route');
  for(const name of ['organization_id','actor_id','subject_id','verification']) assert.equal((await call('create',{...create,[name]:'forged'})).status,400);
  assert.equal((await call('schedule',{...mutation(3),requirement:'forged'})).status,400);
  // Eight actual HTTPS requests preserve one original create intent and actor.
  const rounds=Number(process.env.CANVAS_TEST_CAPTURE_STRESS_ROUNDS??'1');
  assert.ok(Number.isInteger(rounds)&&rounds>=1&&rounds<=50,'bounded local capture stress rounds');
  for(let round=0;round<rounds;round++) {
    if(round) owner("UPDATE canvas_connector.oauth_http_limit SET hits=0,window_started_at=clock_timestamp()-interval '1 second';");
    const concurrent={...create,operation_id:randomUUID(),binding_id:'managed-concurrent-binding-'+round};
    bindings.set(concurrent.binding_id,{...record,id:concurrent.binding_id});
    const requests=await Promise.all(Array.from({length:8},()=>send(address,{path:'/platforms/managed-platform/capture-routes/concurrent-'+round+'/create',body:new URLSearchParams(concurrent).toString()}).response));
    for(const [index,response] of requests.entries()) {
      assert.equal(response.status,200,`concurrent capture create round${round} index${index}; statuses=${requests.map(value=>value.status).join(',')}; types=${requests.map(value=>value.headers['content-type']??'none').join(',')}`);
      assert.deepEqual(JSON.parse(response.body),JSON.parse(requests[0].body));
    }
    assert.equal((await query('SELECT count(*)::integer AS n FROM canvas_connector.rest_route_operation_audit WHERE organization_id=$1 AND operation_id=$2',[organizationId,concurrent.operation_id])).rows[0].n,1);
  }
  assert.ok(gateway.seen.every(item=>item.headers.cookie==='session=abcdefghijklmnop' && !item.headers['x-api-key'] && !item.headers.authorization));
  for(const item of gateway.seen.filter(item=>item.method==='POST')) assert.equal(item.headers.origin,'https://localhost');
  owner('UPDATE canvas_connector.oauth_http_limit SET hits=0,window_started_at=clock_timestamp();');
  console.log('Actual restricted-role HTTPS capture configuration/current Gateway binding+Origin/activation scopes/manual scheduling/8-way replay/closed binding history/private-column denials passed; synthetic Gateway peer only');
}
