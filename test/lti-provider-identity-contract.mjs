// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID,randomBytes } from 'node:crypto';
const container=process.argv[2];assert.match(container??'',/^canvas-lti-state-[a-f0-9]{32}$/);
const run=promisify(execFile),quote=value=>value===null?'NULL':"'"+String(value).replaceAll("'","''")+"'";
async function sql(statement,role=false) {
  const result=await run('docker',['exec',container,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','postgres',
    '-v','ON_ERROR_STOP=1','-c',(role?'SET ROLE lti_runtime; ':'')+statement]);return result.stdout.trim();
}
await sql(`GRANT SELECT ON canvas_connector.lti_provider_identities,canvas_connector.lti_provider_identity_claims,
  canvas_connector.lti_provider_identity_observations TO lti_runtime;
 GRANT INSERT(id,organization_id,platform_id,issuer,client_id,deployment_id,subject) ON canvas_connector.lti_provider_identities TO lti_runtime;
 GRANT UPDATE(canvas_user_id,status) ON canvas_connector.lti_provider_identities TO lti_runtime;
 GRANT INSERT(identity_id,canvas_user_id) ON canvas_connector.lti_provider_identity_claims TO lti_runtime;
 GRANT INSERT(state_hash,launch_id,identity_id,token_hash,canvas_user_id,receipt) ON canvas_connector.lti_provider_identity_observations TO lti_runtime;
 GRANT EXECUTE ON FUNCTION canvas_connector.observe_lti_provider_identity(text,text,uuid) TO lti_runtime;
 INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
  VALUES('identity-org','identity-platform','https://canvas.identity.example',true);`);
const reg=randomUUID();
await sql(`INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
 VALUES('${reg}','identity-org','identity-platform','client-identity','deployment-identity','self_managed_same_origin','https://connector.example/lti/identity',true);`);
async function launch(subject,numeric,{accepted=true,registration=reg,client='client-identity',deployment='deployment-identity',expiry=120}={}) {
 const state=randomBytes(32).toString('hex'),browser=randomBytes(32).toString('hex'),token=randomBytes(32).toString('hex'),nonce=randomBytes(32).toString('base64url');
 const now=Number(await sql('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint;'));
 const payload={issuer:'https://canvas.identity.example',clientId:client,deploymentId:deployment,subject,nonce,targetLinkUri:'https://connector.example/lti/identity',
  issuedAt:now-1,expiresAt:now+expiry,notBefore:null,messageType:'LtiResourceLinkRequest',version:'1.3.0',resourceLinkId:'identity-resource',contextId:null,
  ...(numeric===undefined?{}:{canvasUserId:numeric})};
 assert.ok(await sql(`SELECT canvas_connector.begin_lti_launch('${registration}',1,1,'${state}','${browser}','${nonce}','${randomUUID()}');`,true));
 assert.ok(await sql(`SELECT canvas_connector.stage_lti_launch('${state}','${token}',${quote(JSON.stringify(payload))}::jsonb);`,true));
 if(accepted) assert.ok(await sql(`SELECT canvas_connector.confirm_lti_launch('${state}','${browser}','${token}');`,true));
 return {state,browser,token,subject};
}
async function observe(value,browser=value.browser) {
 const result=await sql(`SELECT canvas_connector.observe_lti_provider_identity('${value.state}',${quote(browser)},'${randomUUID()}');`,true);
 return result?JSON.parse(result):null;
}
const absent=await launch('subject-a'),observed=await observe(absent);
assert.equal(observed.status,'subject_observed');assert.equal(observed.numericIdSupplied,false);
const a=await launch('subject-a','42'),receipts=await Promise.all(Array.from({length:8},()=>observe(a)));
for(const value of receipts)assert.deepEqual(value,receipts[0]);
assert.equal(receipts[0].status,'numeric_linked');assert.equal(receipts[0].identityRevision,2);
assert.equal(observed.identityId,receipts[0].identityId);assert.deepEqual(await observe(absent),observed);
const changed=await launch('subject-a','43'),quarantined=await observe(changed);
assert.equal(quarantined.status,'quarantined');assert.equal(quarantined.identityRevision,3);
assert.equal(await sql(`SELECT canvas_user_id FROM canvas_connector.lti_provider_identities WHERE id='${observed.identityId}';`),'42');
const b=await observe(await launch('subject-b','43'));assert.equal(b.status,'quarantined');
const c=await observe(await launch('subject-c','42'));assert.equal(c.status,'quarantined');
assert.equal((await observe(await launch('subject-a','42'))).status,'quarantined');
assert.deepEqual(await observe(a),receipts[0]); // History does not unquarantine current mappings.
const staged=await launch('staged-only','50',{accepted:false});assert.equal(await observe(staged),null);
assert.equal(await observe(a,'e'.repeat(64)),null);
assert.equal(await sql(`SELECT canvas_connector.observe_lti_provider_identity(NULL,'${a.browser}','${randomUUID()}');`,true),'');
assert.equal(await sql(`SELECT canvas_connector.observe_lti_provider_identity('${a.state}',NULL,'${randomUUID()}');`,true),'');
assert.equal(await sql(`SELECT canvas_connector.observe_lti_provider_identity('${a.state}','${a.browser}',NULL);`,true),'');
const numericSubject=await observe(await launch('12345'));assert.equal(numericSubject.status,'subject_observed');
const secondReg=randomUUID();
await sql(`INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
 VALUES('${secondReg}','identity-org','identity-platform','other-client','other-deployment','self_managed_same_origin','https://connector.example/lti/identity',true);`);
assert.equal((await observe(await launch('subject-a','42',{registration:secondReg,client:'other-client',deployment:'other-deployment'}))).status,'numeric_linked');
const race=await Promise.all([launch('race-a','99'),launch('race-b','99')]);
await Promise.all(race.map(value=>observe(value)));
assert.equal(await sql("SELECT count(*) FROM canvas_connector.lti_provider_identities WHERE subject IN ('race-a','race-b') AND status='quarantined';"),'2');
const rollback=await launch('trigger-rewrite','60');
await sql(`CREATE FUNCTION canvas_connector.test_identity_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.canvas_user_id:='61';RETURN NEW;END;$$;
 CREATE TRIGGER zz_identity_rewrite BEFORE UPDATE ON canvas_connector.lti_provider_identities FOR EACH ROW EXECUTE FUNCTION canvas_connector.test_identity_rewrite();`);
try {await assert.rejects(observe(rollback));}finally{await sql('DROP TRIGGER zz_identity_rewrite ON canvas_connector.lti_provider_identities; DROP FUNCTION canvas_connector.test_identity_rewrite();');}
assert.equal(await sql("SELECT count(*) FROM canvas_connector.lti_provider_identities WHERE subject='trigger-rewrite';"),'0');
assert.equal(await sql(`SELECT count(*) FROM canvas_connector.lti_provider_identity_observations WHERE state_hash='${rollback.state}';`),'0');
assert.equal((await observe(rollback)).status,'numeric_linked');
for(const query of ['DELETE FROM canvas_connector.lti_provider_identities','UPDATE canvas_connector.lti_provider_identity_claims SET canvas_user_id=\'70\'',
 'DELETE FROM canvas_connector.lti_provider_identity_observations','UPDATE canvas_connector.lti_provider_identities SET subject=\'rewritten\'']) await assert.rejects(sql(query,true));
const closed=await launch('closed','80');
await sql("UPDATE canvas_connector.platforms SET enabled=false WHERE id='identity-platform';");
assert.equal(await observe(closed),null);assert.deepEqual(await observe(a),receipts[0]);
console.log('Actual PG16 provider identity: accepted browser proof,8-way original replay,opaque/numeric collision quarantine,scope isolation,concurrent aliases,trigger rollback,history and closed-configuration fences passed; no Marty identity authority');
