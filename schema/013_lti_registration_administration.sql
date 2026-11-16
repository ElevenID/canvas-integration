-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No canonical permissions or runtime DDL/grants.
BEGIN;
CREATE TABLE canvas_connector.lti_registration_operation_audit (
 organization_id text NOT NULL,
 operation_id uuid NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 actor_id text NOT NULL CHECK(actor_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 action text NOT NULL CHECK(action IN ('create','replace','activate','deactivate')),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,operation_id),
 FOREIGN KEY(organization_id,platform_id,registration_id)
  REFERENCES canvas_connector.lti_registrations(organization_id,platform_id,id)
);
CREATE INDEX lti_registrations_catalog ON canvas_connector.lti_registrations(organization_id,platform_id,id);
CREATE FUNCTION canvas_connector.keep_lti_registration_audit()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'LTI registration audit is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER lti_registration_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_registration_operation_audit
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_registration_audit();
CREATE FUNCTION canvas_connector.administer_lti_registration(org text, platform text, actor text, operation uuid,
 registration uuid, requested_action text, expected_platform bigint, expected_registration bigint, requested_definition jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE host canvas_connector.platforms; saved canvas_connector.lti_registrations;
 prior canvas_connector.lti_registration_operation_audit; intended_definition jsonb; intent jsonb; result jsonb;
 intended_version bigint; intended_enabled boolean; started timestamptz:=clock_timestamp();
BEGIN
 IF org IS NULL OR org COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR platform IS NULL OR platform COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR actor IS NULL OR actor COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR operation IS NULL OR registration IS NULL OR requested_action IS NULL
  OR requested_action NOT IN ('create','replace','activate','deactivate') THEN RETURN NULL; END IF;
 IF requested_action='deactivate' THEN
  IF expected_platform IS NOT NULL THEN RETURN NULL; END IF;
 ELSIF expected_platform IS NULL OR expected_platform NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 IF requested_action='create' THEN
  IF expected_registration IS NOT NULL THEN RETURN NULL; END IF;
 ELSIF expected_registration IS NULL OR expected_registration NOT BETWEEN 1 AND 9007199254740990 THEN RETURN NULL; END IF;
 IF requested_action IN ('create','replace') THEN
  IF jsonb_typeof(requested_definition) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
  IF ARRAY(SELECT key FROM jsonb_object_keys(requested_definition) key ORDER BY key COLLATE "C") IS DISTINCT FROM
   ARRAY['clientId','deploymentId','environment','targetLinkUri','trustProfile'] THEN RETURN NULL; END IF;
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['clientId','deploymentId','targetLinkUri','trustProfile']) name
   WHERE jsonb_typeof(requested_definition->name) IS DISTINCT FROM 'string') THEN RETURN NULL; END IF;
  IF NOT canvas_connector.lti_visible_identifier(requested_definition->>'clientId')
   OR NOT canvas_connector.lti_visible_identifier(requested_definition->>'deploymentId')
   OR NOT COALESCE(requested_definition->>'targetLinkUri' ~ ('^https://[^/[:space:]?#@]+/lti/registrations/'||registration::text||'/resource$'),false)
   OR octet_length(requested_definition->>'targetLinkUri')>2048 THEN RETURN NULL; END IF;
  IF NOT COALESCE((requested_definition->>'trustProfile'='hosted_global' AND jsonb_typeof(requested_definition->'environment')='string'
    AND requested_definition->>'environment' IN ('production','beta','test'))
   OR (requested_definition->>'trustProfile'='self_managed_same_origin' AND requested_definition->'environment'='null'::jsonb),false) THEN RETURN NULL; END IF;
 ELSIF requested_definition IS NOT NULL THEN RETURN NULL; END IF;
 intent:=jsonb_build_object('action',requested_action,'expectedPlatformVersion',expected_platform,
  'expectedRegistrationVersion',expected_registration,'definition',requested_definition);
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-registration-admin',org,operation)::text,0));
 SELECT * INTO prior FROM canvas_connector.lti_registration_operation_audit WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF prior.platform_id IS DISTINCT FROM platform OR prior.registration_id IS DISTINCT FROM registration
   OR prior.actor_id IS DISTINCT FROM actor OR prior.action IS DISTINCT FROM requested_action OR prior.request IS DISTINCT FROM intent THEN RETURN NULL; END IF;
  RETURN prior.receipt;
 END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF requested_action<>'deactivate' AND (host.config_version IS DISTINCT FROM expected_platform OR host.archived
  OR (requested_action='activate' AND NOT host.enabled)) THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM canvas_connector.lti_registrations WHERE id=registration FOR UPDATE;
 IF requested_action='create' THEN
  IF FOUND THEN RETURN NULL; END IF;
  intended_version:=1;intended_enabled:=false;intended_definition:=requested_definition;
  INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
   VALUES(registration,org,platform,requested_definition->>'clientId',requested_definition->>'deploymentId',
    requested_definition->>'trustProfile',requested_definition->>'environment',requested_definition->>'targetLinkUri',false);
 ELSE
  IF NOT FOUND OR saved.organization_id IS DISTINCT FROM org OR saved.platform_id IS DISTINCT FROM platform
   OR saved.version IS DISTINCT FROM expected_registration THEN RETURN NULL; END IF;
  intended_version:=expected_registration+1;intended_enabled:=requested_action='activate';
  intended_definition:=CASE WHEN requested_action='replace' THEN requested_definition ELSE
   jsonb_build_object('clientId',saved.client_id,'deploymentId',saved.deployment_id,'trustProfile',saved.trust_profile,
    'environment',saved.environment,'targetLinkUri',saved.target_link_uri) END;
  UPDATE canvas_connector.lti_registrations SET client_id=intended_definition->>'clientId',deployment_id=intended_definition->>'deploymentId',
   trust_profile=intended_definition->>'trustProfile',environment=intended_definition->>'environment',
   target_link_uri=intended_definition->>'targetLinkUri',enabled=intended_enabled WHERE id=registration;
 END IF;
 SELECT * INTO saved FROM canvas_connector.lti_registrations WHERE id=registration;
 IF NOT FOUND OR saved.organization_id IS DISTINCT FROM org OR saved.platform_id IS DISTINCT FROM platform
  OR saved.version IS DISTINCT FROM intended_version OR saved.enabled IS DISTINCT FROM intended_enabled
  OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR jsonb_build_object('clientId',saved.client_id,'deploymentId',saved.deployment_id,'trustProfile',saved.trust_profile,
    'environment',saved.environment,'targetLinkUri',saved.target_link_uri) IS DISTINCT FROM intended_definition THEN
  RAISE EXCEPTION 'LTI registration intent changed';
 END IF;
 result:=jsonb_build_object('operationId',operation,'actorId',actor,'action',requested_action,'registrationId',registration,
  'platformId',platform,'version',intended_version,'enabled',intended_enabled,'definition',intended_definition);
 INSERT INTO canvas_connector.lti_registration_operation_audit(organization_id,operation_id,platform_id,registration_id,actor_id,action,request,receipt)
  VALUES(org,operation,platform,registration,actor,requested_action,intent,result);
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(saved))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registration_operation_audit a WHERE a.organization_id=org AND a.operation_id=operation
   AND a.platform_id=platform AND a.registration_id=registration AND a.actor_id=actor AND a.action=requested_action
   AND a.request=intent AND a.receipt=result AND a.created_at>=started AND a.created_at<=clock_timestamp()) THEN
  RAISE EXCEPTION 'LTI registration operation changed';
 END IF;
 RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.lti_registration_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_lti_registration_audit(),
 canvas_connector.administer_lti_registration(text,text,text,uuid,uuid,text,bigint,bigint,jsonb) FROM PUBLIC;
COMMIT;
