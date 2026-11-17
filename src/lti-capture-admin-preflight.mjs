// SPDX-License-Identifier: AGPL-3.0-only
// Additional HTTP-admin capabilities; compose with the LTI service preflight.
// This is neither a tenant SQL sandbox nor full owner-schema provenance proof.
export async function preflightLtiCaptureAdministration(pool) {
 try {
  if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function')throw Error();
  const result=await pool.query(`WITH reachable AS(SELECT oid FROM pg_catalog.pg_roles WHERE pg_has_role(current_user,oid,'MEMBER')),
   required(relation,insert_columns,update_columns) AS(VALUES
    ('lti_capture_routes',ARRAY['organization_id','id','producer_ref','platform_id','registration_id','definition','service_operation_id','enabled'],ARRAY['definition','service_operation_id','enabled']),
    ('lti_capture_jobs',ARRAY['organization_id','capture_id','producer_ref','route_id','route_version','definition','platform_id','registration_id','service_operation_id','token_reference','canvas_origin','platform_version','registration_version','key_version','available_at','created_at'],ARRAY[]::text[]),
    ('lti_capture_operation_audit',ARRAY['organization_id','operation_id','platform_id','registration_id','route_id','actor_id','action','request','receipt'],ARRAY[]::text[])
   ) SELECT
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(SELECT oid FROM reachable) AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolname~'^pg_'))
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_schema_privilege(oid,'canvas_connector','CREATE'))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||required.relation)::regclass
    WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER')
     OR NOT has_table_privilege(current_user,c.oid,'SELECT')
     OR EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.insert_columns) f(name)
    WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,f.name,'INSERT'))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.update_columns) f(name)
    WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,f.name,'UPDATE'))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_attribute f ON f.attrelid=('canvas_connector.'||required.relation)::regclass AND f.attnum>0 AND NOT f.attisdropped
    CROSS JOIN reachable WHERE NOT f.attname=ANY(required.insert_columns) AND has_column_privilege(reachable.oid,f.attrelid,f.attname,'INSERT')
     OR NOT f.attname=ANY(required.update_columns) AND has_column_privilege(reachable.oid,f.attrelid,f.attname,'UPDATE'))
   AND has_sequence_privilege(current_user,'canvas_connector.lti_capture_jobs_ordinal_seq','USAGE')
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_sequence_privilege(oid,'canvas_connector.lti_capture_jobs_ordinal_seq','UPDATE'))
   AND (SELECT count(*)=3 FROM pg_catalog.pg_trigger t JOIN(VALUES
    ('lti_capture_routes','lti_capture_route_revision','guard_lti_capture_route()'),
    ('lti_capture_jobs','lti_capture_job_immutable','guard_lti_capture_job()'),
    ('lti_capture_operation_audit','lti_capture_audit_immutable','keep_lti_tool_key_history()')
   ) e(relation,name,signature) ON t.tgrelid=('canvas_connector.'||e.relation)::regclass AND t.tgname=e.name AND t.tgfoid=('canvas_connector.'||e.signature)::regprocedure
    WHERE NOT t.tgisinternal AND t.tgenabled IN('O','A') AND t.tgtype=27 AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
   AND NOT EXISTS(SELECT 1 FROM(VALUES('guard_lti_capture_route()'),('guard_lti_capture_job()'),('keep_lti_tool_key_history()')) e(signature)
    JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||e.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER'))
   AND NOT EXISTS(SELECT 1 FROM(VALUES('valid_lti_capture_definition(jsonb)'),('lti_visible_identifier(text)'),
    ('lti_capture_current(canvas_connector.lti_capture_jobs)'),('lock_lti_capture_context(canvas_connector.lti_capture_jobs)'),
    ('schedule_lti_capture(text,text,text,bigint,uuid)'),
    ('administer_lti_capture(text,text,uuid,text,uuid,text,text,bigint,bigint,bigint,bigint,uuid,jsonb,bigint)')) e(signature)
    JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||e.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER')
     OR NOT has_function_privilege(current_user,p.oid,'EXECUTE')) AS ready`);
  if(result?.rows?.length!==1||result.rows[0].ready!==true)throw Error();
 }catch{throw Error('lti_capture_admin_runtime_unavailable');}
}
