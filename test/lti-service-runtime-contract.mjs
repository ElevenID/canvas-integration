// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
import { preflightLtiServices } from '../src/lti-service-preflight.mjs';
import { ltiToolKeyContract } from './lti-tool-key-contract.mjs';
import { ltiServiceStoreContract } from './lti-service-store-contract.mjs';
import { ltiServiceLifecycleContract } from './lti-service-lifecycle-contract.mjs';
import { ltiServiceRecoveryContract } from './lti-service-recovery-contract.mjs';
import { ltiCaptureContract } from './lti-capture-contract.mjs';

export async function ltiServiceRuntimeContract(configuration,{keyProvider,keyCustody,ownerQuery}) {
 const role='canvas_lti_services',password='synthetic-lti-services-password';
 await ownerQuery(`CREATE ROLE ${role} LOGIN PASSWORD '${password}';
  GRANT CONNECT ON DATABASE canvas_driver_test TO ${role};
  GRANT USAGE ON SCHEMA canvas_connector TO ${role};
  GRANT SELECT ON canvas_connector.platforms,canvas_connector.lti_registrations,
   canvas_connector.lti_tool_keys,canvas_connector.lti_tool_key_configurations,canvas_connector.lti_tool_key_operation_audit,
   canvas_connector.lti_service_attempts,canvas_connector.lti_service_tokens,canvas_connector.lti_service_recovery_audit TO ${role};
  GRANT UPDATE(enabled) ON canvas_connector.platforms,canvas_connector.lti_registrations TO ${role};
  GRANT INSERT(organization_id,platform_id,registration_id,kid,platform_version,registration_version,client_id,tool_origin,public_jwk,wrapping_key_id,ciphertext,nonce,tag)
   ON canvas_connector.lti_tool_keys TO ${role};
  GRANT INSERT(organization_id,platform_id,registration_id,current_kid),UPDATE(current_kid) ON canvas_connector.lti_tool_key_configurations TO ${role};
  GRANT INSERT(organization_id,operation_id,platform_id,registration_id,actor_id,request,receipt) ON canvas_connector.lti_tool_key_operation_audit TO ${role};
  GRANT INSERT(organization_id,operation_id,platform_id,registration_id,actor_id,platform_version,registration_version,key_version,kid,client_id,canvas_origin,tool_origin,requested_scopes),
   UPDATE(phase,dispatch_id,issued_at,assertion_expires_at,token_reference,receipt) ON canvas_connector.lti_service_attempts TO ${role};
  GRANT INSERT(organization_id,platform_id,registration_id,operation_id,reference,granted_scopes,expires_at,wrapping_key_id,input_digest,ciphertext,nonce,tag,created_at,retire_after)
   ON canvas_connector.lti_service_tokens TO ${role};
  GRANT INSERT(organization_id,operation_id,platform_id,registration_id,attempt_id,actor_id,request,receipt) ON canvas_connector.lti_service_recovery_audit TO ${role};
  GRANT EXECUTE ON FUNCTION canvas_connector.lti_visible_identifier(text),canvas_connector.lti_service_read_scopes(text[]),
   canvas_connector.lti_tool_public_keys(uuid),
   canvas_connector.administer_lti_tool_key(text,text,uuid,uuid,text,text,bigint,bigint,bigint,uuid,jsonb,text,bytea,bytea,bytea),
   canvas_connector.lti_service_attempt_view(canvas_connector.lti_service_attempts),canvas_connector.lti_service_attempt_current(canvas_connector.lti_service_attempts),
   canvas_connector.lock_lti_service_configuration(canvas_connector.lti_service_attempts),
   canvas_connector.prepare_lti_service_attempt(text,text,uuid,uuid,text,bigint,bigint,bigint,text[]),canvas_connector.begin_lti_service_exchange(text,uuid,uuid),
   canvas_connector.stage_lti_service_token(text,uuid,uuid,uuid,text[],timestamptz,text,bytea,bytea,bytea,bytea),
   canvas_connector.publish_lti_service_token(text,uuid,uuid),canvas_connector.mark_lti_service_uncertain(text,uuid,uuid),
   canvas_connector.recover_lti_service_attempt(text,text,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,uuid) TO ${role};`);
 const pool=createConnectorPostgresPool({...configuration,user:role,credentialProvider:{getPassword:async()=>password}});
 try {
  await preflightLtiServices(pool);
  for(const [grant,restore] of [
   ...['pg_read_server_files','pg_write_server_files','pg_execute_server_program'].map(name=>[
    `GRANT ${name} TO ${role} WITH INHERIT FALSE`,`REVOKE ${name} FROM ${role}`]),
   [`GRANT UPDATE(version) ON canvas_connector.lti_tool_key_configurations TO ${role}`,`REVOKE UPDATE(version) ON canvas_connector.lti_tool_key_configurations FROM ${role}`],
   [`GRANT INSERT(created_at) ON canvas_connector.lti_service_attempts TO ${role}`,`REVOKE INSERT(created_at) ON canvas_connector.lti_service_attempts FROM ${role}`],
   [`ALTER TABLE canvas_connector.lti_service_attempts DISABLE TRIGGER lti_service_attempt_transition`,`ALTER TABLE canvas_connector.lti_service_attempts ENABLE TRIGGER lti_service_attempt_transition`],
   [`ALTER FUNCTION canvas_connector.begin_lti_service_exchange(text,uuid,uuid) SECURITY DEFINER`,`ALTER FUNCTION canvas_connector.begin_lti_service_exchange(text,uuid,uuid) SECURITY INVOKER`],
   [`REVOKE INSERT(retire_after) ON canvas_connector.lti_service_tokens FROM ${role}`,`GRANT INSERT(retire_after) ON canvas_connector.lti_service_tokens TO ${role}`],
   [`CREATE ROLE canvas_lti_hidden NOINHERIT;GRANT UPDATE(version) ON canvas_connector.lti_tool_key_configurations TO canvas_lti_hidden;GRANT canvas_lti_hidden TO ${role} WITH INHERIT FALSE`,`REVOKE canvas_lti_hidden FROM ${role};DROP OWNED BY canvas_lti_hidden;DROP ROLE canvas_lti_hidden`],
  ]) {
   await ownerQuery(grant);
   if(grant.includes('canvas_lti_hidden')) {
    const reach=(await pool.query(`SELECT has_column_privilege(current_user,'canvas_connector.lti_tool_key_configurations','version','UPDATE') AS inherited,
     pg_has_role(current_user,'canvas_lti_hidden','MEMBER') AS reachable`)).rows[0];
    assert.deepEqual(reach,{inherited:false,reachable:true});
   }
   try{await assert.rejects(preflightLtiServices(pool),/lti_service_runtime_unavailable/);}
   finally{await ownerQuery(restore);}
   await preflightLtiServices(pool);
  }
  for(const sql of ['DELETE FROM canvas_connector.lti_service_tokens','UPDATE canvas_connector.lti_service_attempts SET actor_id=actor_id',
   'UPDATE canvas_connector.lti_tool_key_configurations SET version=version','SELECT * FROM unrelated_private.denied'])await assert.rejects(pool.query(sql));
  await ltiToolKeyContract(pool,{keyProvider,ownerQuery});
  await ltiServiceStoreContract(pool,{keyProvider,ownerQuery});
  await ltiServiceLifecycleContract(pool,{keyProvider,ownerQuery});
  await ltiServiceRecoveryContract(pool,{keyProvider,ownerQuery});
  await ltiCaptureContract(configuration,{servicePool:pool,keyProvider,keyCustody,ownerQuery});
  console.log('Actual restricted TLS LTI service role, read-only preflight, hidden membership/guard/privilege negatives and composed custody/lifecycle/recovery PASS');
 } finally {await pool.close();}
}
