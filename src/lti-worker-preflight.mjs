// SPDX-License-Identifier: AGPL-3.0-only
// Keyless worker capabilities only. No owner grants or tenant SQL sandbox.
export async function preflightLtiWorker(pool,{scheduling=false}={}) {
 try {
  if(typeof globalThis.window!=='undefined'||typeof pool?.query!=='function'||typeof scheduling!=='boolean')throw Error();
  const specs=[
   ['platforms',[],['enabled']],['lti_registrations',[],['enabled']],['lti_tool_key_configurations',[],['current_kid']],
   ['lti_service_attempts',[],['phase']],['lti_service_tokens',[],[]],['lti_capture_routes',[],['enabled']],
   ['lti_capture_jobs',['organization_id','capture_id','producer_ref','route_id','route_version','definition','platform_id','registration_id','service_operation_id','token_reference','canvas_origin','platform_version','registration_version','key_version','available_at','created_at'],
    ['phase','attempts','available_at','lease_id','lease_expires_at','last_error','completed_lease_id','result']],
   ['observation_counters',['organization_id','binding_id'],['current_sequence']],
   ['observation_outbox',['organization_id','observation_id','producer_ref','binding_id','binding_revision','sequence','observed_at_ms','effective_at_ms','claims'],
    ['body','phase','attempts','available_at','lease_id','lease_expires_at','receipt_id','replayed','last_error','last_status']],
   ...scheduling?[
    ['lti_schedule_configurations',['organization_id','configuration_id','producer_ref','route_id','intent','receipt'],[]],
    ['lti_schedule_captures',['organization_id','capture_id','configuration_id','route_id','ordinal','receipt'],[]],
    ['lti_schedule_heads',['organization_id','route_id','producer_ref','configuration_id','revision','route_version','interval_ms','enabled','next_due_at','updated_at'],
     ['configuration_id','revision','route_version','interval_ms','enabled','next_ordinal','next_due_at','last_capture_id','updated_at']],
   ]:[],
  ].map(([relation,insert_columns,update_columns])=>({relation,insert_columns,update_columns}));
  const guards=[
   ['platforms','platform_configuration_revision','bump_platform_configuration()',19],['lti_registrations','lti_registration_revision','bump_lti_registration()',19],
   ['lti_tool_key_configurations','lti_tool_key_revision','bump_lti_tool_key_configuration()',19],['lti_service_attempts','lti_service_attempt_transition','guard_lti_service_attempt()',27],
   ['lti_service_tokens','lti_service_token_immutable','keep_lti_tool_key_history()',27],['lti_capture_routes','lti_capture_route_revision','guard_lti_capture_route()',27],
   ['lti_capture_jobs','lti_capture_job_immutable','guard_lti_capture_job()',27],['observation_outbox','observation_immutable','protect_outbox()',31],
   ...scheduling?[
    ['lti_schedule_heads','lti_schedule_head_revision','guard_lti_schedule_head()',19],['lti_schedule_configurations','lti_schedule_configuration_immutable','keep_lti_schedule_audit()',27],
    ['lti_schedule_captures','lti_schedule_capture_immutable','keep_lti_schedule_audit()',27],
   ]:[],
  ].map(([relation,name,signature,kind])=>({relation,name,signature,kind}));
  const functions=['lti_service_attempt_view(canvas_connector.lti_service_attempts)','lti_service_attempt_current(canvas_connector.lti_service_attempts)',
   'lock_lti_service_configuration(canvas_connector.lti_service_attempts)','lti_capture_current(canvas_connector.lti_capture_jobs)','lock_lti_capture_context(canvas_connector.lti_capture_jobs)',
   'claim_lti_capture(text,text)','complete_lti_capture(text,text,uuid,uuid,bigint,bigint,jsonb)','defer_lti_capture(text,text,uuid,uuid,text,boolean)',
   'valid_outbox_claims(jsonb)','enqueue_observation(text,text,text,bigint,text,bigint,bigint,jsonb)','seal_observation(text,text,text,text)','claim_observation(text,text)',
   'acknowledge_observation(text,text,text,uuid,text,boolean)','defer_observation(text,text,text,uuid,text,integer,boolean)',
   ...scheduling?['tick_lti_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean)']:[]];
  const r=await pool.query(`WITH reachable AS(SELECT oid FROM pg_catalog.pg_roles WHERE pg_has_role(current_user,oid,'MEMBER')),
   required AS(SELECT * FROM jsonb_to_recordset($1::jsonb) x(relation text,insert_columns text[],update_columns text[])),
   guards AS(SELECT * FROM jsonb_to_recordset($2::jsonb) x(relation text,name text,signature text,kind integer))
   SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(SELECT oid FROM reachable)
    AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolname~'^pg_'))
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_schema_privilege(oid,'canvas_connector','CREATE'))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||required.relation)::regclass
    WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER')
     OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.insert_columns) f(name) WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,f.name,'INSERT'))
   AND NOT EXISTS(SELECT 1 FROM required CROSS JOIN LATERAL unnest(required.update_columns) f(name) WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,f.name,'UPDATE'))
   AND NOT EXISTS(SELECT 1 FROM required JOIN pg_catalog.pg_attribute f ON f.attrelid=('canvas_connector.'||required.relation)::regclass AND f.attnum>0 AND NOT f.attisdropped CROSS JOIN reachable
    WHERE NOT f.attname=ANY(required.insert_columns) AND has_column_privilege(reachable.oid,f.attrelid,f.attname,'INSERT')
     OR NOT f.attname=ANY(required.update_columns) AND has_column_privilege(reachable.oid,f.attrelid,f.attname,'UPDATE'))
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute f CROSS JOIN reachable WHERE f.attrelid='canvas_connector.lti_tool_keys'::regclass AND f.attnum>0 AND NOT f.attisdropped
    AND (NOT f.attname=ANY(ARRAY['organization_id','platform_id','registration_id','kid','platform_version','registration_version','client_id','tool_origin']) AND has_column_privilege(reachable.oid,f.attrelid,f.attname,'SELECT')
     OR has_column_privilege(reachable.oid,f.attrelid,f.attname,'INSERT,UPDATE')))
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_table_privilege(oid,'canvas_connector.lti_tool_keys','DELETE,TRUNCATE,TRIGGER,REFERENCES')
    OR has_any_column_privilege(oid,'canvas_connector.secrets','SELECT,INSERT,UPDATE') OR has_table_privilege(oid,'canvas_connector.secrets','DELETE,TRUNCATE,TRIGGER,REFERENCES'))
   AND NOT EXISTS(SELECT 1 FROM reachable CROSS JOIN(VALUES('lti_tool_key_operation_audit'),('lti_service_recovery_audit'),('lti_capture_operation_audit')) a(name)
    WHERE has_any_column_privilege(oid,'canvas_connector.'||a.name,'INSERT,UPDATE') OR has_table_privilege(oid,'canvas_connector.'||a.name,'DELETE,TRUNCATE,TRIGGER,REFERENCES'))
   AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['organization_id','platform_id','registration_id','kid','platform_version','registration_version','client_id','tool_origin']) f(name)
    WHERE NOT has_column_privilege(current_user,'canvas_connector.lti_tool_keys',f.name,'SELECT'))
   AND has_sequence_privilege(current_user,'canvas_connector.lti_capture_jobs_ordinal_seq','USAGE')
   AND NOT EXISTS(SELECT 1 FROM reachable WHERE has_sequence_privilege(oid,'canvas_connector.lti_capture_jobs_ordinal_seq','UPDATE'))
   AND (SELECT count(*)=(SELECT count(*) FROM guards) FROM guards g JOIN pg_catalog.pg_trigger t
    ON t.tgrelid=('canvas_connector.'||g.relation)::regclass AND t.tgname=g.name AND t.tgfoid=('canvas_connector.'||g.signature)::regprocedure
    WHERE NOT t.tgisinternal AND t.tgenabled IN('O','A') AND t.tgtype=g.kind AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
   AND NOT EXISTS(SELECT 1 FROM guards g JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||g.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER'))
   AND NOT EXISTS(SELECT 1 FROM unnest($3::text[]) e(signature) JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||e.signature)::regprocedure
    WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog'] OR pg_has_role(current_user,p.proowner,'MEMBER') OR NOT has_function_privilege(current_user,p.oid,'EXECUTE')) AS ready`,
   [JSON.stringify(specs),JSON.stringify(guards),functions]);
  if(r?.rows?.length!==1||r.rows[0].ready!==true)throw Error();
 }catch{throw Error('lti_worker_runtime_unavailable');}
}
