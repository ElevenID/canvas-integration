// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { request } from 'node:https';
import { randomUUID } from 'node:crypto';
import { httpsFixture,json } from './support/canvas-https-fixture.mjs';
import { createLtiRegistrationAdminStore } from '../src/lti-registration-admin-store.mjs';
import { createLtiRegistrationAdminHandler } from '../src/lti-registration-admin-http.mjs';
import { createGatewayAdminAuthenticator } from '../src/gateway-admin-auth.mjs';

const container=process.argv[2];if(!/^canvas-lti-state-[a-f0-9]{32}$/.test(container)) throw Error('owned_fixture_required');
const run=promisify(execFile),quote=value=>value===null?'NULL':typeof value==='number'?String(value):"'"+String(value).replaceAll("'","''")+"'";
async function sql(source,role=false) {
  const {stdout}=await run('docker',['exec',container,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','postgres','-v','ON_ERROR_STOP=1','-c',
    (role?'SET ROLE lti_admin_runtime; ':'')+source]);return stdout.trim();
}
const org='30000000-0000-4000-8000-000000000001',otherOrg='30000000-0000-4000-8000-000000000002';
await sql(`CREATE ROLE lti_admin_runtime;
 GRANT USAGE ON SCHEMA canvas_connector TO lti_admin_runtime;
 GRANT SELECT ON canvas_connector.platforms,canvas_connector.lti_registrations,canvas_connector.lti_registration_operation_audit TO lti_admin_runtime;
 GRANT UPDATE(updated_at) ON canvas_connector.platforms TO lti_admin_runtime;
 GRANT INSERT(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
  ON canvas_connector.lti_registrations TO lti_admin_runtime;
 GRANT UPDATE(client_id,deployment_id,trust_profile,environment,target_link_uri,enabled) ON canvas_connector.lti_registrations TO lti_admin_runtime;
 GRANT INSERT(organization_id,operation_id,platform_id,registration_id,actor_id,action,request,receipt)
  ON canvas_connector.lti_registration_operation_audit TO lti_admin_runtime;
 GRANT EXECUTE ON FUNCTION canvas_connector.lti_visible_identifier(text),
  canvas_connector.administer_lti_registration(text,text,text,uuid,uuid,text,bigint,bigint,jsonb) TO lti_admin_runtime;
 INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES
 ('${org}','admin-canvas','https://college.instructure.com',true),('${otherOrg}','admin-canvas','https://other.instructure.com',true),
 ('${org}','self-managed','https://canvas.custom.example',true);`);
let loseReply=false;
const store=createLtiRegistrationAdminStore({async query(statement,parameters){
  const bound=statement.replace(/\$(\d+)/g,(_,index)=>quote(parameters[Number(index)-1]));
  const output=await sql(`SELECT row_to_json(q) FROM (${bound}) q;`,true);
  const rows=output.split('\n').filter(Boolean).map(line=>JSON.parse(line));
  if(loseReply && statement.includes('administer_lti_registration') && rows[0]?.result!==null){loseReply=false;throw Error('synthetic_lost_reply');}
  return{rows};
}});
const gateway=await httpsFixture(),admin=await httpsFixture();
let actor='operator-one',tenant=org,revoke=false,permissionReads=0;
gateway.setHandler((req,res)=>{
  if(req.url==='/v1/auth/me')return json(res,{authenticated:true,user:{user_id:actor,organization_id:tenant}});
  if(req.url===`/v1/organizations/${tenant}/members/me/permissions`){permissionReads++;return json(res,{permissions:revoke&&permissionReads>1?[]:['integration-connector:edit']});}
  res.writeHead(404);res.end();
});
const authenticate=createGatewayAdminAuthenticator({gatewayOrigin:gateway.origin,adminOrigin:admin.origin,sessionCookieName:'session',ca:gateway.ca});
const handler=createLtiRegistrationAdminHandler({store,authenticateAndAuthorize:authenticate,rateLimiter:{consume:async()=>true},publicOrigin:admin.origin,
  selfManagedOriginAllowlist:[]});
admin.setHandler((req,res)=>{void handler(req,res).catch(()=>res.destroy());});
const registration=randomUUID(),prefix=`/platforms/admin-canvas/lti/registrations/${registration}`;
const createFields={operation_id:randomUUID(),expected_platform_version:'1',client_id:'client-admin',deployment_id:'deployment-admin',trust_profile:'hosted_global',environment:'production'};
async function send(path,fields={},extraHeaders={}) {
  const body=new URLSearchParams(fields).toString();
  return new Promise((resolve,reject)=>{
    const req=request(new URL(path,admin.origin),{method:'POST',agent:false,ca:admin.ca,headers:{Origin:admin.origin,
      Cookie:'session=synthetic-admin-session-credential; other=never-forward',
      'Content-Type':'application/x-www-form-urlencoded','Content-Length':String(Buffer.byteLength(body)),...extraHeaders}},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{const text=Buffer.concat(chunks).toString('utf8');resolve({status:res.statusCode,body:text?JSON.parse(text):null});});
    });req.on('error',reject);req.end(body);
  });
}
try {
  const created=await send(prefix+'/create',createFields,{'X-Organization-ID':otherOrg,'X-API-Key':'never-forward'});
  assert.equal(created.status,200);assert.equal(created.body.receipt.version,1);assert.equal(created.body.receipt.enabled,false);
  assert.equal(created.body.receipt.definition.targetLinkUri,`${admin.origin}/lti/registrations/${registration}/resource`);
  assert.equal(await sql(`SELECT organization_id FROM canvas_connector.lti_registrations WHERE id='${registration}';`),org);
  assert.ok(gateway.seen.every(item=>item.headers.cookie==='session=synthetic-admin-session-credential' && item.headers['x-api-key']===undefined && item.headers['x-organization-id']===undefined));
  const activateFields={operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1'};
  const activations=await Promise.all(Array.from({length:8},()=>send(prefix+'/activate',activateFields)));
  const active=activations[0];
  for(const [index,value] of activations.entries()) {
    assert.equal(value.status,200,`concurrent exact activation${index}`);assert.deepEqual(value.body,active.body);
  }
  assert.equal(active.body.receipt.version,2);assert.equal(active.body.receipt.enabled,true);
  assert.equal(await sql(`SELECT count(*) FROM canvas_connector.lti_registration_operation_audit WHERE operation_id='${activateFields.operation_id}';`),'1');
  const replay=await send(prefix+'/activate',activateFields);assert.deepEqual(replay.body,active.body);
  actor='operator-two';assert.equal((await send(prefix+'/activate',activateFields)).status,409);actor='operator-one';
  const originalArgs=[quote(org),quote('admin-canvas'),quote(actor),quote(createFields.operation_id),quote(registration),quote('create'),'1','NULL',quote(JSON.stringify(created.body.receipt.definition))+'::jsonb'];
  for(const index of [0,1,2,3,4,5,6,8]) {
    const nullable=[...originalArgs];nullable[index]='NULL';
    assert.equal(await sql('SELECT canvas_connector.administer_lti_registration('+nullable.join(',')+');',true),'');
  }
  assert.deepEqual(JSON.parse(await sql('SELECT canvas_connector.administer_lti_registration('+originalArgs.join(',')+');',true)),created.body.receipt);
  assert.equal((await send(prefix+'/replace',{...createFields,operation_id:randomUUID(),expected_registration_version:'1'})).status,409);
  const replaceFields={...createFields,operation_id:randomUUID(),expected_registration_version:'2',client_id:'replacement-client'};
  const replaced=await send(prefix+'/replace',replaceFields);assert.equal(replaced.status,200);assert.equal(replaced.body.receipt.version,3);assert.equal(replaced.body.receipt.enabled,false);
  const beforeRevoked=await sql('SELECT count(*) FROM canvas_connector.lti_registration_operation_audit;');
  revoke=true;permissionReads=0;
  assert.equal((await send(prefix+'/activate',{operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'3'})).status,403);
  revoke=false;assert.equal(await sql('SELECT count(*) FROM canvas_connector.lti_registration_operation_audit;'),beforeRevoked);
  tenant=otherOrg;assert.equal((await send(prefix+'/inspect')).body.registration,null);tenant=org;
  assert.equal((await send(prefix+'/create',{...createFields,organization_id:otherOrg})).status,400);
  assert.equal((await send(prefix+'/create',{...createFields,target_link_uri:'https://attacker.invalid'})).status,400);
  const selfPath=`/platforms/self-managed/lti/registrations/${randomUUID()}/create`;
  assert.equal((await send(selfPath,{...createFields,operation_id:randomUUID(),trust_profile:'self_managed_same_origin',environment:undefined})).status,400);
  const selfFields={...createFields,operation_id:randomUUID(),trust_profile:'self_managed_same_origin'};delete selfFields.environment;
  assert.equal((await send(selfPath,selfFields)).status,409,'no caller-selected self-managed trust without server allowlist');
  // Final postimage checks must reject trigger rewrites independently of RETURNING.
  await sql(`CREATE FUNCTION canvas_connector.test_registration_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
   BEGIN NEW.client_id:='rewritten';RETURN NEW;END;$$;
   CREATE TRIGGER zz_registration_rewrite BEFORE UPDATE ON canvas_connector.lti_registrations FOR EACH ROW
    EXECUTE FUNCTION canvas_connector.test_registration_rewrite();`);
  const rewritten=await send(prefix+'/replace',{...createFields,operation_id:randomUUID(),expected_registration_version:'3'});
  assert.equal(rewritten.status,503);assert.equal(await sql(`SELECT version FROM canvas_connector.lti_registrations WHERE id='${registration}';`),'3');
  await sql('DROP TRIGGER zz_registration_rewrite ON canvas_connector.lti_registrations;');
  // A lost commit reply is reconciled from immutable history before current state.
  const lostFields={...createFields,operation_id:randomUUID(),expected_registration_version:'3'};
  loseReply=true;const lost=await send(prefix+'/replace',lostFields);
  // Preserve the exact operation body; no owner lookup or identity regeneration.
  assert.equal(lost.status,503);
  await sql(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${org}' AND id='admin-canvas';`);
  const originalFields=lostFields;
  const recovered=await send(prefix+'/replace',originalFields);assert.equal(recovered.status,200);assert.equal(recovered.body.receipt.version,4);
  assert.equal((await send(prefix+'/replace',{...originalFields,client_id:'changed-intent'})).status,409);
  const deactivated=await send(prefix+'/deactivate',{operation_id:randomUUID(),expected_registration_version:'4'});
  assert.equal(deactivated.status,200);assert.equal(deactivated.body.receipt.version,5);
  assert.equal((await send(prefix+'/inspect')).body.registration.version,5);
  assert.equal((await send(prefix+'/receipt',{operation_id:lostFields.operation_id})).body.receipt.version,4);
  for(const statement of ["UPDATE canvas_connector.lti_registration_operation_audit SET receipt='{}';",
    'DELETE FROM canvas_connector.lti_registration_operation_audit;','DELETE FROM canvas_connector.lti_registrations;',
    'SELECT * FROM canvas_connector.secrets;','UPDATE canvas_connector.lti_launch_states SET phase=\'accepted\';']) {
    await assert.rejects(sql(statement,true));
  }
  for(let i=0;i<21;i++) {
    const seeded=randomUUID();
    await sql(`INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri)
     VALUES('${seeded}','${org}','admin-canvas','seed-client','seed-deploy','hosted_global','production','${admin.origin}/lti/registrations/${seeded}/resource');`);
  }
  const first=(await send('/platforms/admin-canvas/lti/registrations/catalog')).body;
  assert.equal(first.registrations.length,20);assert.ok(first.nextCursor);
  const second=(await send('/platforms/admin-canvas/lti/registrations/catalog',{after_id:first.nextCursor})).body;
  assert.equal(second.registrations.length,2);assert.equal(new Set([...first.registrations,...second.registrations].map(item=>item.registrationId)).size,22);
  console.log('Real Gateway-session HTTPS -> constrained-role PG LTI registration administration passed: tenant/actor/permission fences, inactive create, CAS, history, lost reply, trigger rollback, disabled deactivation and keyset catalog');
} finally {await Promise.allSettled([gateway.close(),admin.close()]);}
