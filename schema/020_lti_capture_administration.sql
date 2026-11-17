-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner migration; connector route intent/audit, never a Core authority mirror.
BEGIN;
CREATE INDEX lti_capture_catalog ON canvas_connector.lti_capture_routes(organization_id,platform_id,registration_id,id COLLATE "C");
CREATE TABLE canvas_connector.lti_capture_operation_audit (
 organization_id text NOT NULL,operation_id uuid NOT NULL,platform_id text NOT NULL,registration_id uuid NOT NULL,route_id text NOT NULL,
 actor_id text NOT NULL CHECK(actor_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 action text NOT NULL CHECK(action IN ('create','replace','activate','deactivate','schedule')),request jsonb NOT NULL,receipt jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,operation_id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.lti_capture_routes(organization_id,id)
);
CREATE TRIGGER lti_capture_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_capture_operation_audit
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_tool_key_history();
CREATE FUNCTION canvas_connector.administer_lti_capture(org text,platform text,registration uuid,route text,operation uuid,actor text,action text,
 expected_platform bigint,expected_registration bigint,expected_key bigint,expected_route bigint,service_operation uuid,definition jsonb,admission_deadline_ms bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE prior canvas_connector.lti_capture_operation_audit;a canvas_connector.lti_service_attempts;t canvas_connector.lti_service_tokens;
 old canvas_connector.lti_capture_routes;saved canvas_connector.lti_capture_routes;request jsonb;receipt jsonb;
 candidate jsonb;desired_enabled boolean;version bigint;started timestamptz:=clock_timestamp();audit canvas_connector.lti_capture_operation_audit;
 parent_platform canvas_connector.platforms;parent_registration canvas_connector.lti_registrations;parent_key canvas_connector.lti_tool_key_configurations;has_key boolean;
 scheduled canvas_connector.lti_capture_jobs;
BEGIN
 IF org IS NULL OR platform IS NULL OR registration IS NULL OR route IS NULL OR operation IS NULL OR actor IS NULL
  OR actor COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR route COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR action IS NULL OR action NOT IN ('create','replace','activate','deactivate','schedule') THEN RETURN NULL; END IF;
 IF action='create' THEN IF expected_route IS NOT NULL THEN RETURN NULL; END IF;
 ELSE IF expected_route IS NULL OR expected_route NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;END IF;
 IF action='deactivate' THEN
  IF expected_platform IS NOT NULL OR expected_registration IS NOT NULL OR expected_key IS NOT NULL OR service_operation IS NOT NULL OR definition IS NOT NULL THEN RETURN NULL; END IF;
 ELSE
  IF expected_platform IS NULL OR expected_registration IS NULL OR expected_key IS NULL OR service_operation IS NULL
   OR expected_platform NOT BETWEEN 1 AND 9007199254740991 OR expected_registration NOT BETWEEN 1 AND 9007199254740991 OR expected_key NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 END IF;
 IF action IN ('create','replace') THEN
  IF NOT COALESCE(canvas_connector.valid_lti_capture_definition(definition),false) OR definition->>'platformId' IS DISTINCT FROM platform
   OR definition->>'registrationId' IS DISTINCT FROM registration::text THEN RETURN NULL; END IF;
 ELSIF definition IS NOT NULL THEN RETURN NULL; END IF;
 request:=jsonb_build_object('expectedPlatformVersion',expected_platform,'expectedRegistrationVersion',expected_registration,'expectedKeyVersion',expected_key,
  'expectedRouteVersion',expected_route,'serviceOperationId',service_operation,'definition',definition);
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-capture-admin',org,operation)::text,0));
 SELECT * INTO prior FROM canvas_connector.lti_capture_operation_audit WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF ROW(prior.platform_id,prior.registration_id,prior.route_id,prior.actor_id,prior.action,prior.request)
   IS DISTINCT FROM ROW(platform,registration,route,actor,action,request) THEN RETURN NULL; END IF;
  RETURN prior.receipt;
 END IF;
 -- Same lock order as direct scheduling: capture identity before parent rows.
 IF action='schedule' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-capture',org,operation)::text,0));
  IF EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=operation) THEN RETURN NULL; END IF;
 END IF;
 SELECT * INTO parent_platform FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO parent_registration FROM canvas_connector.lti_registrations WHERE organization_id=org AND platform_id=platform AND id=registration FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO parent_key FROM canvas_connector.lti_tool_key_configurations WHERE organization_id=org AND platform_id=platform AND registration_id=registration FOR UPDATE;
 has_key:=FOUND;
 SELECT * INTO old FROM canvas_connector.lti_capture_routes WHERE organization_id=org AND id=route FOR UPDATE;
 IF action='create' THEN
  IF FOUND THEN RETURN NULL; END IF;candidate:=definition;version:=1;desired_enabled:=false;
 ELSE
  IF NOT FOUND OR old.platform_id<>platform OR old.registration_id<>registration OR old.version<>expected_route THEN RETURN NULL; END IF;
  candidate:=CASE WHEN action='replace' THEN definition ELSE old.definition END;
  IF candidate->>'producerRef' IS DISTINCT FROM old.producer_ref OR candidate->>'bindingId' IS DISTINCT FROM old.definition->>'bindingId' THEN RETURN NULL; END IF;
  IF action NOT IN ('replace','deactivate') AND old.service_operation_id IS DISTINCT FROM service_operation THEN RETURN NULL; END IF;
  version:=old.version+CASE WHEN action='schedule' THEN 0 ELSE 1 END;
  desired_enabled:=action IN ('activate','schedule');
 END IF;
 IF action<>'deactivate' THEN
  IF admission_deadline_ms IS NULL OR admission_deadline_ms NOT BETWEEN 1 AND 9007199254740991
   OR to_timestamp(admission_deadline_ms::float8/1000)<=clock_timestamp() THEN RETURN NULL; END IF;
  SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=service_operation FOR SHARE;
  IF NOT FOUND OR a.platform_id<>platform OR a.registration_id<>registration OR a.platform_version<>expected_platform
   OR a.registration_version<>expected_registration OR a.key_version<>expected_key OR a.phase<>'published'
   OR NOT canvas_connector.lti_service_attempt_current(a) THEN RETURN NULL; END IF;
  SELECT * INTO t FROM canvas_connector.lti_service_tokens WHERE organization_id=org AND operation_id=service_operation AND reference=a.token_reference;
  IF NOT FOUND OR t.expires_at<=clock_timestamp() OR NOT (CASE WHEN candidate->'requirement'->>'factType'='canvas.ags_result' THEN
    ARRAY['https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly','https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly']<@t.granted_scopes
   ELSE ARRAY['https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly']<@t.granted_scopes END) THEN RETURN NULL; END IF;
 END IF;
 IF action='create' THEN
  INSERT INTO canvas_connector.lti_capture_routes(organization_id,id,producer_ref,platform_id,registration_id,definition,service_operation_id,enabled)
   VALUES(org,route,candidate->>'producerRef',platform,registration,candidate,service_operation,false) RETURNING * INTO saved;
 ELSIF action='schedule' THEN
  IF NOT old.enabled OR NOT canvas_connector.schedule_lti_capture(org,old.producer_ref,route,expected_route,operation) THEN RETURN NULL; END IF;
  SELECT * INTO scheduled FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=operation;
  IF NOT FOUND THEN RAISE EXCEPTION 'LTI scheduled capture missing'; END IF;
  saved:=old;
 ELSE
  UPDATE canvas_connector.lti_capture_routes SET definition=candidate,enabled=desired_enabled,
   service_operation_id=CASE WHEN action='replace' THEN service_operation ELSE old.service_operation_id END
   WHERE organization_id=org AND id=route RETURNING * INTO saved;
 END IF;
 IF ROW(saved.organization_id,saved.id,saved.producer_ref,saved.platform_id,saved.registration_id,saved.definition,saved.service_operation_id,saved.version,saved.enabled)
  IS DISTINCT FROM ROW(org,route,candidate->>'producerRef',platform,registration,candidate,
   CASE WHEN action IN ('create','replace') THEN service_operation ELSE old.service_operation_id END,version,desired_enabled) THEN RAISE EXCEPTION 'LTI route intent changed'; END IF;
 receipt:=jsonb_build_object('operationId',operation,'actorId',actor,'action',action,'platformId',platform,'registrationId',registration,'routeId',route,
  'version',version,'enabled',desired_enabled,'serviceOperationId',saved.service_operation_id,'captureId',CASE WHEN action='schedule' THEN operation ELSE NULL END);
 INSERT INTO canvas_connector.lti_capture_operation_audit(organization_id,operation_id,platform_id,registration_id,route_id,actor_id,action,request,receipt)
  VALUES(org,operation,platform,registration,route,actor,action,request,receipt) RETURNING * INTO audit;
 IF ROW(audit.organization_id,audit.operation_id,audit.platform_id,audit.registration_id,audit.route_id,audit.actor_id,audit.action,audit.request,audit.receipt)
  IS DISTINCT FROM ROW(org,operation,platform,registration,route,actor,action,request,receipt)
  OR audit.created_at<started OR audit.created_at>clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_operation_audit s WHERE to_jsonb(s)=to_jsonb(audit))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_routes s WHERE to_jsonb(s)=to_jsonb(saved))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms s WHERE to_jsonb(s)=to_jsonb(parent_platform))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations s WHERE to_jsonb(s)=to_jsonb(parent_registration))
  OR has_key AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations s WHERE to_jsonb(s)=to_jsonb(parent_key))
  OR NOT has_key AND EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations s WHERE s.organization_id=org AND s.platform_id=platform AND s.registration_id=registration)
  OR action<>'deactivate' AND (t.expires_at<=clock_timestamp() OR NOT canvas_connector.lti_service_attempt_current(a)
   OR to_timestamp(admission_deadline_ms::float8/1000)<=clock_timestamp()
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(a))
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens s WHERE to_jsonb(s)=to_jsonb(t)))
  OR action='schedule' AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs j WHERE j.organization_id=org AND j.capture_id=operation
   AND to_jsonb(j)=to_jsonb(scheduled) AND j.route_id=route AND j.route_version=expected_route AND j.definition=candidate AND j.service_operation_id=service_operation AND j.token_reference=a.token_reference) THEN
  RAISE EXCEPTION 'LTI route audit changed'; END IF;
 RETURN receipt;
END;
$$;
REVOKE ALL ON canvas_connector.lti_capture_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.administer_lti_capture(text,text,uuid,text,uuid,text,text,bigint,bigint,bigint,bigint,uuid,jsonb,bigint) FROM PUBLIC;
COMMIT;
