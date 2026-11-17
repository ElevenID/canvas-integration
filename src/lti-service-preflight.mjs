// SPDX-License-Identifier: AGPL-3.0-only
// Read-only capability/guard check for the composed service role. This is not
// complete owner-schema provenance validation or a tenant/JWT SQL sandbox.
export async function preflightLtiServices(pool) {
 try {
  if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')throw Error();
  const result=await pool.query(`WITH reachable AS (
   SELECT oid FROM pg_catalog.pg_roles WHERE pg_has_role(current_user,oid,'MEMBER')
  ), required(relation,insert_columns,update_columns) AS (VALUES
   ('lti_tool_keys',ARRAY['organization_id','platform_id','registration_id','kid','platform_version','registration_version','client_id','tool_origin','public_jwk','wrapping_key_id','ciphertext','nonce','tag'],ARRAY[]::text[]),
   ('lti_tool_key_configurations',ARRAY['organization_id','platform_id','registration_id','current_kid'],ARRAY['current_kid']),
   ('lti_tool_key_operation_audit',ARRAY['organization_id','operation_id','platform_id','registration_id','actor_id','request','receipt'],ARRAY[]::text[]),
   ('lti_service_attempts',ARRAY['organization_id','operation_id','platform_id','registration_id','actor_id','platform_version','registration_version','key_version','kid','client_id','canvas_origin','tool_origin','requested_scopes'],ARRAY['phase','dispatch_id','issued_at','assertion_expires_at','token_reference','receipt']),
   ('lti_service_tokens',ARRAY['organization_id','platform_id','registration_id','operation_id','reference','granted_scopes','expires_at','wrapping_key_id','input_digest','ciphertext','nonce','tag','created_at','retire_after'],ARRAY[]::text[]),
   ('lti_service_recovery_audit',ARRAY['organization_id','operation_id','platform_id','registration_id','attempt_id','actor_id','request','receipt'],ARRAY[]::text[])
  ) SELECT
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(SELECT oid FROM reachable)
    AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolname ~ '^pg_'))
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_schema_privilege(oid,'canvas_connector','CREATE'))
   AND NOT EXISTS(SELECT 1 FROM (VALUES('platforms'),('lti_registrations')) parent(name)
    JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||parent.name)::regclass
    WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
     OR pg_has_role(current_user,c.relowner,'MEMBER') OR NOT has_table_privilege(current_user,c.oid,'SELECT')
     OR NOT has_any_column_privilege(current_user,c.oid,'UPDATE')
     OR EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER'))
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||required.relation)::regclass
    WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
     OR pg_has_role(current_user,c.relowner,'MEMBER') OR NOT has_table_privilege(current_user,c.oid,'SELECT')
     OR EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER'))
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.insert_columns) field(name)
    WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,field.name,'INSERT'))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.update_columns) field(name)
    WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,field.name,'UPDATE'))
   AND NOT EXISTS(SELECT 1 FROM (VALUES
    ('platforms',ARRAY['organization_id','id','config_version']),
    ('lti_registrations',ARRAY['id','organization_id','platform_id','version'])
   ) immutable(relation,names) CROSS JOIN LATERAL unnest(immutable.names) field(name) CROSS JOIN reachable
    WHERE has_column_privilege(reachable.oid,'canvas_connector.'||immutable.relation,field.name,'UPDATE'))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_attribute field
     ON field.attrelid=('canvas_connector.'||required.relation)::regclass AND field.attnum>0 AND NOT field.attisdropped
    CROSS JOIN reachable WHERE
     (NOT field.attname=ANY(required.update_columns) AND has_column_privilege(reachable.oid,field.attrelid,field.attname,'UPDATE'))
     OR (NOT field.attname=ANY(required.insert_columns) AND has_column_privilege(reachable.oid,field.attrelid,field.attname,'INSERT')))
   AND (SELECT count(*)=6 FROM pg_catalog.pg_trigger t JOIN (VALUES
    ('lti_tool_keys','lti_tool_key_immutable','keep_lti_tool_key_history()',27),
    ('lti_tool_key_configurations','lti_tool_key_revision','bump_lti_tool_key_configuration()',19),
    ('lti_tool_key_operation_audit','lti_tool_key_audit_immutable','keep_lti_tool_key_history()',27),
    ('lti_service_attempts','lti_service_attempt_transition','guard_lti_service_attempt()',27),
    ('lti_service_tokens','lti_service_token_immutable','keep_lti_tool_key_history()',27),
    ('lti_service_recovery_audit','lti_service_recovery_audit_immutable','keep_lti_tool_key_history()',27)
   ) expected(relation,name,signature,kind)
     ON t.tgrelid=('canvas_connector.'||expected.relation)::regclass AND t.tgname=expected.name
     AND t.tgfoid=('canvas_connector.'||expected.signature)::regprocedure
    WHERE NOT t.tgisinternal AND t.tgenabled IN('O','A') AND t.tgtype=expected.kind
     AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
   AND NOT EXISTS(SELECT 1 FROM (VALUES
    ('keep_lti_tool_key_history()'),('bump_lti_tool_key_configuration()'),('guard_lti_service_attempt()')
   ) expected(signature) JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||expected.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER'))
   AND (SELECT count(*)=2 FROM pg_catalog.pg_trigger t JOIN (VALUES
    ('platforms','platform_configuration_revision','bump_platform_configuration()'),
    ('lti_registrations','lti_registration_revision','bump_lti_registration()')
   ) expected(relation,name,signature)
     ON t.tgrelid=('canvas_connector.'||expected.relation)::regclass AND t.tgname=expected.name
     AND t.tgfoid=('canvas_connector.'||expected.signature)::regprocedure
    JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
    WHERE NOT t.tgisinternal AND t.tgenabled IN('O','A') AND t.tgtype=19
     AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
     AND NOT p.prosecdef AND NOT pg_has_role(current_user,p.proowner,'MEMBER'))
   AND NOT EXISTS(SELECT 1 FROM (VALUES
    ('lti_visible_identifier(text)'),('lti_service_read_scopes(text[])'),
    ('lti_tool_public_keys(uuid)'),
    ('administer_lti_tool_key(text,text,uuid,uuid,text,text,bigint,bigint,bigint,uuid,jsonb,text,bytea,bytea,bytea)'),
    ('lti_service_attempt_view(canvas_connector.lti_service_attempts)'),('lti_service_attempt_current(canvas_connector.lti_service_attempts)'),
    ('lock_lti_service_configuration(canvas_connector.lti_service_attempts)'),
    ('prepare_lti_service_attempt(text,text,uuid,uuid,text,bigint,bigint,bigint,text[])'),('begin_lti_service_exchange(text,uuid,uuid)'),
    ('stage_lti_service_token(text,uuid,uuid,uuid,text[],timestamptz,text,bytea,bytea,bytea,bytea)'),
    ('publish_lti_service_token(text,uuid,uuid)'),('mark_lti_service_uncertain(text,uuid,uuid)'),
    ('recover_lti_service_attempt(text,text,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,uuid)')
   ) expected(signature) JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||expected.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER')
     OR NOT has_function_privilege(current_user,p.oid,'EXECUTE')) AS ready`);
  if(result?.rows?.length!==1||result.rows[0].ready!==true)throw Error();
 }catch{throw Error('lti_service_runtime_unavailable');}
}
