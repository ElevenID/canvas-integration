// SPDX-License-Identifier: AGPL-3.0-only
// Read-only capability and guard checks. Owner provisioning is separate; this
// is not a complete schema provenance audit or a tenant/JWT SQL sandbox.
export async function preflightLtiRuntime(pool) {
  const result=await pool.query(`WITH reachable_roles AS (
    SELECT oid,rolname FROM pg_catalog.pg_roles WHERE pg_has_role(current_user,oid,'MEMBER')
  ) SELECT
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid IN(SELECT oid FROM reachable_roles) AND
      (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
    AND NOT EXISTS(SELECT 1 FROM reachable_roles WHERE has_schema_privilege(oid,'canvas_connector','CREATE'))
    AND NOT EXISTS(SELECT 1 FROM (VALUES
      ('lti_registrations'),('lti_launch_states'),('lti_launch_receipts'),('lti_registration_operation_audit'),
      ('lti_provider_identities'),('lti_provider_identity_claims'),('lti_provider_identity_observations')
    ) required(name) JOIN pg_catalog.pg_class c ON c.oid=('canvas_connector.'||required.name)::regclass
      WHERE c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
        OR pg_has_role(current_user,c.relowner,'MEMBER')
        OR NOT has_table_privilege(current_user,c.oid,'SELECT')
        OR EXISTS(SELECT 1 FROM reachable_roles WHERE has_table_privilege(oid,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid))
    AND NOT EXISTS(SELECT 1 FROM (VALUES
      ('lti_registrations','INSERT',ARRAY['id','organization_id','platform_id','client_id','deployment_id','trust_profile','environment','target_link_uri','enabled']),
      ('lti_registrations','UPDATE',ARRAY['client_id','deployment_id','trust_profile','environment','target_link_uri','enabled','updated_at']),
      ('lti_launch_states','INSERT',ARRAY['state_hash','launch_id','browser_hash','organization_id','platform_id','registration_id','platform_version','registration_version','registration_snapshot','nonce']),
      ('lti_launch_states','UPDATE',ARRAY['phase','token_hash','protocol_claims','accepted_at']),
      ('lti_launch_receipts','INSERT',ARRAY['state_hash','launch_id','token_hash','receipt']),
      ('lti_registration_operation_audit','INSERT',ARRAY['organization_id','operation_id','platform_id','registration_id','actor_id','action','request','receipt']),
      ('lti_provider_identities','INSERT',ARRAY['id','organization_id','platform_id','issuer','client_id','deployment_id','subject']),
      ('lti_provider_identities','UPDATE',ARRAY['canvas_user_id','status']),
      ('lti_provider_identity_claims','INSERT',ARRAY['identity_id','canvas_user_id']),
      ('lti_provider_identity_observations','INSERT',ARRAY['state_hash','launch_id','identity_id','token_hash','canvas_user_id','receipt'])
    ) required(relation,privilege,names) CROSS JOIN LATERAL unnest(required.names) field(name)
      WHERE NOT has_column_privilege(current_user,'canvas_connector.'||required.relation,field.name,required.privilege))
    AND NOT EXISTS(SELECT 1 FROM (VALUES
      ('lti_registrations',ARRAY['id','organization_id','platform_id','version']),
      ('lti_launch_states',ARRAY['state_hash','launch_id','browser_hash','organization_id','platform_id','registration_id','platform_version','registration_version','registration_snapshot','nonce','created_at','expires_at']),
      ('lti_launch_receipts',ARRAY['state_hash','launch_id','token_hash','receipt','created_at']),
      ('lti_registration_operation_audit',ARRAY['organization_id','operation_id','platform_id','registration_id','actor_id','action','request','receipt','created_at']),
      ('lti_provider_identities',ARRAY['id','organization_id','platform_id','issuer','client_id','deployment_id','subject','revision','created_at','updated_at']),
      ('lti_provider_identity_claims',ARRAY['identity_id','canvas_user_id','created_at']),
      ('lti_provider_identity_observations',ARRAY['state_hash','launch_id','identity_id','token_hash','canvas_user_id','receipt','created_at'])
    ) forbidden(relation,names) CROSS JOIN LATERAL unnest(forbidden.names) field(name) CROSS JOIN reachable_roles reachable
      WHERE has_column_privilege(reachable.oid,'canvas_connector.'||forbidden.relation,field.name,'UPDATE'))
    AND (SELECT count(*)=7 FROM pg_catalog.pg_trigger t JOIN (VALUES
      ('lti_registrations','lti_registration_revision','bump_lti_registration()',19),
      ('lti_launch_states','lti_launch_state_transition','guard_lti_launch_state()',19),
      ('lti_launch_receipts','lti_launch_receipt_immutable','keep_lti_launch_receipt()',27),
      ('lti_registration_operation_audit','lti_registration_audit_immutable','keep_lti_registration_audit()',27),
      ('lti_provider_identities','lti_provider_identity_revision','guard_lti_provider_identity()',19),
      ('lti_provider_identity_claims','lti_provider_identity_claim_immutable','keep_lti_provider_identity_history()',27),
      ('lti_provider_identity_observations','lti_provider_identity_observation_immutable','keep_lti_provider_identity_history()',27)
    ) expected(relation,name,signature,kind)
      ON t.tgrelid=('canvas_connector.'||expected.relation)::regclass AND t.tgname=expected.name
      AND t.tgfoid=('canvas_connector.'||expected.signature)::regprocedure
      WHERE NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND t.tgtype=expected.kind
        AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
    AND NOT EXISTS(SELECT 1 FROM (VALUES
      ('bump_lti_registration()'),('guard_lti_launch_state()'),('keep_lti_launch_receipt()'),('keep_lti_registration_audit()'),
      ('guard_lti_provider_identity()'),('keep_lti_provider_identity_history()')
    ) expected(signature) JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||expected.signature)::regprocedure
      WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
        OR pg_has_role(current_user,p.proowner,'MEMBER'))
    AND NOT EXISTS(SELECT 1 FROM (VALUES
      ('lti_visible_identifier(text)'),('lti_numeric_date(jsonb)'),('lti_canvas_user_id(text)'),
      ('lti_claims_match(jsonb,canvas_connector.lti_registrations,canvas_connector.platforms,text)'),
      ('begin_lti_launch(uuid,bigint,bigint,text,text,text,uuid)'),('stage_lti_launch(text,text,jsonb)'),
      ('confirm_lti_launch(text,text,text)'),('administer_lti_registration(text,text,text,uuid,uuid,text,bigint,bigint,jsonb)'),
      ('observe_lti_provider_identity(uuid,text,text,uuid)')
    ) required(signature) JOIN pg_catalog.pg_proc p ON p.oid=('canvas_connector.'||required.signature)::regprocedure
      WHERE p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
        OR pg_has_role(current_user,p.proowner,'MEMBER') OR NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
    AS ready`);
  if(result?.rows?.length!==1 || result.rows[0].ready!==true) throw Error('lti_runtime_unavailable');
}
