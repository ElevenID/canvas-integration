-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No Core authority, runtime grants or provider I/O.
BEGIN;
CREATE INDEX rest_capture_routes_platform_catalog ON canvas_connector.rest_capture_routes(organization_id,platform_id,id COLLATE "C");
CREATE TABLE canvas_connector.rest_route_operation_audit (
 organization_id text NOT NULL,operation_id uuid NOT NULL,platform_id text NOT NULL,route_id text NOT NULL,
 actor_id text NOT NULL CHECK(actor_id~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 action text NOT NULL CHECK(action IN ('create','replace','activate','deactivate','schedule')),
 request jsonb NOT NULL,receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,operation_id),
 FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.rest_capture_routes(organization_id,id)
);
CREATE FUNCTION canvas_connector.keep_rest_route_operation_audit()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'capture route audit is immutable' USING ERRCODE='23514'; END;
$$;
CREATE TRIGGER rest_route_operation_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.rest_route_operation_audit
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_rest_route_operation_audit();

CREATE OR REPLACE FUNCTION canvas_connector.revise_rest_route()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (NEW.organization_id,NEW.id,NEW.platform_id,NEW.producer_ref,NEW.binding_id)
  IS DISTINCT FROM (OLD.organization_id,OLD.id,OLD.platform_id,OLD.producer_ref,OLD.binding_id)
  THEN RAISE EXCEPTION 'immutable route identity'; END IF;
 NEW.version:=OLD.version+1;RETURN NEW;
END;
$$;

CREATE FUNCTION canvas_connector.administer_rest_route(org text,platform text,route text,operation uuid,actor text,
 requested_action text,expected_platform bigint,expected_route bigint,definition jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE prior canvas_connector.rest_route_operation_audit; audit canvas_connector.rest_route_operation_audit;
 host canvas_connector.platforms; configuration canvas_connector.rest_capture_routes;
 connection canvas_connector.connections; scheduled jsonb;
 names text[]; intent jsonb; current_definition jsonb; result jsonb; needs_connection boolean;
 required_capabilities text[]; required_scopes text[];
 intended_definition jsonb; intended_version bigint; intended_enabled boolean; expected_job jsonb; started_at timestamptz:=clock_timestamp();
BEGIN
 IF org IS NULL OR org!~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR platform IS NULL OR platform!~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR route IS NULL OR route!~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR operation IS NULL OR actor IS NULL OR actor!~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR requested_action IS NULL OR requested_action NOT IN ('create','replace','activate','deactivate','schedule') THEN RETURN NULL; END IF;
 IF requested_action='deactivate' THEN
  IF expected_platform IS NOT NULL OR definition IS NOT NULL THEN RETURN NULL; END IF;
 ELSE
  IF expected_platform IS NULL OR expected_platform NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 END IF;
 IF requested_action='create' THEN
  IF expected_route IS NOT NULL THEN RETURN NULL; END IF;
 ELSE
  IF expected_route IS NULL OR expected_route NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 END IF;
 intent:=jsonb_build_object('expectedPlatformVersion',expected_platform,'expectedRouteVersion',expected_route,
   'definition',CASE WHEN requested_action IN ('create','replace') THEN definition ELSE NULL END);
 -- Reserve an absent route before locking platform -> route -> connection -> job,
 -- the same row order used by capture workers. Hash collisions only serialize.
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('rest-route-admin',org,platform,route)::text,0));
 SELECT * INTO prior FROM canvas_connector.rest_route_operation_audit WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF prior.platform_id<>platform OR prior.route_id<>route OR prior.actor_id<>actor
   OR prior.action<>requested_action OR prior.request<>intent THEN RETURN NULL; END IF;
  RETURN prior.receipt;
 END IF;
 IF requested_action<>'deactivate' THEN
  IF definition IS NULL OR jsonb_typeof(definition)<>'object'
   OR definition-'producerRef'-'platformId'-'bindingId'-'bindingRevision'-'requirement'-'claimNames'-'effectiveTimePolicy'<>'{}'::jsonb
   OR jsonb_typeof(definition->'producerRef') IS DISTINCT FROM 'string'
   OR COALESCE(definition->>'producerRef'!~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$',true)
   OR definition->>'platformId' IS DISTINCT FROM platform
   OR jsonb_typeof(definition->'bindingId') IS DISTINCT FROM 'string'
   OR COALESCE(definition->>'bindingId'!~'^[A-Za-z0-9_-]{1,128}$',true)
   OR jsonb_typeof(definition->'bindingRevision') IS DISTINCT FROM 'number'
   OR COALESCE(definition->>'bindingRevision'!~'^[1-9][0-9]{0,15}$',true)
   OR (definition->>'bindingRevision')::numeric>9007199254740991
   OR jsonb_typeof(definition->'claimNames') IS DISTINCT FROM 'array'
   OR COALESCE(definition->>'effectiveTimePolicy' NOT IN ('require_provider_time','as_of_read'),true) THEN RETURN NULL; END IF;
  SELECT array_agg(value ORDER BY value COLLATE "C") INTO names FROM jsonb_array_elements_text(definition->'claimNames');
  IF canvas_connector.valid_rest_route(definition->'requirement',names) IS DISTINCT FROM true
   OR to_jsonb(names)<>definition->'claimNames' THEN RETURN NULL; END IF;
 END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR SHARE;
 IF NOT FOUND OR (requested_action<>'deactivate' AND (host.config_version<>expected_platform OR host.archived)) THEN RETURN NULL; END IF;
 SELECT * INTO configuration FROM canvas_connector.rest_capture_routes WHERE organization_id=org AND id=route FOR UPDATE;
 IF requested_action='create' THEN
  intended_definition:=definition;intended_version:=1;intended_enabled:=false;
  IF FOUND THEN RETURN NULL; END IF;
  INSERT INTO canvas_connector.rest_capture_routes(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,
   requirement,claim_names,effective_time_policy,enabled)
  VALUES(org,route,definition->>'producerRef',platform,definition->>'bindingId',(definition->>'bindingRevision')::bigint,
   definition->'requirement',names,definition->>'effectiveTimePolicy',false) RETURNING * INTO configuration;
 ELSE
  IF NOT FOUND OR configuration.platform_id<>platform OR configuration.version<>expected_route
   OR (requested_action<>'schedule' AND configuration.version=9007199254740991) THEN RETURN NULL; END IF;
  current_definition:=jsonb_build_object('producerRef',configuration.producer_ref,'platformId',configuration.platform_id,
   'bindingId',configuration.binding_id,'bindingRevision',configuration.binding_revision,'requirement',configuration.requirement,
   'claimNames',to_jsonb(ARRAY(SELECT value FROM unnest(configuration.claim_names) value ORDER BY value COLLATE "C")),
   'effectiveTimePolicy',configuration.effective_time_policy);
  intended_definition:=CASE WHEN requested_action='replace' THEN definition ELSE current_definition END;
  intended_version:=configuration.version+CASE WHEN requested_action='schedule' THEN 0 ELSE 1 END;
  intended_enabled:=requested_action IN ('activate','schedule');
  IF requested_action='replace' THEN
   IF definition->>'producerRef'<>configuration.producer_ref OR definition->>'bindingId'<>configuration.binding_id
    OR (definition=current_definition AND NOT configuration.enabled) THEN RETURN NULL; END IF;
  ELSIF requested_action IN ('activate','schedule') THEN
   IF definition<>current_definition OR configuration.enabled IS DISTINCT FROM (requested_action='schedule') THEN RETURN NULL; END IF;
  ELSIF NOT configuration.enabled THEN RETURN NULL;
  END IF;
 END IF;
 needs_connection:=requested_action IN ('activate','schedule');
 IF needs_connection THEN
  SELECT * INTO connection FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform FOR SHARE;
  IF NOT FOUND OR NOT host.enabled OR host.archived OR connection.status<>'connected'
   OR connection.platform_config_version<>host.config_version OR connection.canvas_origin<>host.canvas_origin
   OR (connection.token_expires_at IS NOT NULL AND connection.token_expires_at<=clock_timestamp()) THEN RETURN NULL; END IF;
  CASE configuration.requirement->>'factType'
   WHEN 'canvas.assignment_score','canvas.quiz_score' THEN
    required_capabilities:=ARRAY['native_activity_scores'];
    required_scopes:=ARRAY['url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id','url:GET|/api/v1/courses/:course_id/assignments/:id'];
   WHEN 'canvas.module_completion' THEN
    required_capabilities:=ARRAY['module_completion'];required_scopes:=ARRAY['url:GET|/api/v1/courses/:course_id/modules/:id'];
   WHEN 'canvas.course_completion' THEN
    required_capabilities:=ARRAY['course_completion'];required_scopes:=ARRAY['url:GET|/api/v1/courses/:course_id/users/:user_id/progress'];
   ELSE RETURN NULL;
  END CASE;
  IF NOT COALESCE(connection.capabilities@>required_capabilities AND connection.scopes@>required_scopes,false) THEN RETURN NULL; END IF;
 END IF;
 IF requested_action='replace' THEN
  UPDATE canvas_connector.rest_capture_routes SET binding_revision=(definition->>'bindingRevision')::bigint,
   requirement=definition->'requirement',claim_names=names,effective_time_policy=definition->>'effectiveTimePolicy',enabled=false
   WHERE organization_id=org AND id=route RETURNING * INTO configuration;
 ELSIF requested_action IN ('activate','deactivate') THEN
  UPDATE canvas_connector.rest_capture_routes SET enabled=(requested_action='activate')
   WHERE organization_id=org AND id=route RETURNING * INTO configuration;
 ELSIF requested_action='schedule' THEN
  -- Capture identity is the operator's durable operation UUID. Never adopt an
  -- older manually-created job with no matching actor/intent audit receipt.
  IF EXISTS(SELECT 1 FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND capture_id=operation::text) THEN RETURN NULL; END IF;
  INSERT INTO canvas_connector.rest_capture_jobs(organization_id,capture_id,producer_ref,route_id,route_version,platform_id,
   binding_id,binding_revision,requirement,claim_names,effective_time_policy)
  VALUES(org,operation::text,configuration.producer_ref,route,configuration.version,platform,configuration.binding_id,
   configuration.binding_revision,configuration.requirement,configuration.claim_names,configuration.effective_time_policy)
  RETURNING jsonb_build_object('organizationId',organization_id,'captureId',capture_id,'producerRef',producer_ref,'routeId',route_id,'routeVersion',route_version,'platformId',platform_id,'bindingId',binding_id,'bindingRevision',binding_revision,'requirement',requirement,'claimNames',claim_names,'effectiveTimePolicy',effective_time_policy,'phase',phase,'attempts',attempts,'availableAt',available_at,'leaseId',lease_id,'leaseExpiresAt',lease_expires_at) INTO scheduled;
 END IF;
 -- RETURNING alone is not an intent fence: a BEFORE trigger can rewrite
 -- NEW and therefore the returned row. Compare the postimage to the explicit
 -- normalized intent (or locked definition), independently of RETURNING.
 IF configuration.organization_id IS DISTINCT FROM org OR configuration.id IS DISTINCT FROM route
  OR configuration.platform_id IS DISTINCT FROM platform OR configuration.version IS DISTINCT FROM intended_version
  OR configuration.enabled IS DISTINCT FROM intended_enabled
  OR jsonb_build_object('producerRef',configuration.producer_ref,'platformId',configuration.platform_id,
    'bindingId',configuration.binding_id,'bindingRevision',configuration.binding_revision,'requirement',configuration.requirement,
    'claimNames',to_jsonb(ARRAY(SELECT value FROM unnest(configuration.claim_names) value ORDER BY value COLLATE "C")),
    'effectiveTimePolicy',configuration.effective_time_policy) IS DISTINCT FROM intended_definition THEN
  RAISE EXCEPTION 'capture route intent changed';
 END IF;
 IF requested_action='schedule' THEN
  expected_job:=jsonb_build_object('organizationId',org,'captureId',operation::text,'producerRef',configuration.producer_ref,
    'routeId',route,'routeVersion',configuration.version,'platformId',platform,'bindingId',configuration.binding_id,
    'bindingRevision',configuration.binding_revision,'requirement',configuration.requirement,'claimNames',configuration.claim_names,
    'effectiveTimePolicy',configuration.effective_time_policy,'phase','pending','attempts',0,'leaseId',NULL,'leaseExpiresAt',NULL);
  IF scheduled-'availableAt' IS DISTINCT FROM expected_job THEN RAISE EXCEPTION 'capture schedule intent changed'; END IF;
 END IF;
 result:=jsonb_build_object('operationId',operation,'actorId',actor,'action',requested_action,'routeId',route,
  'platformId',platform,'version',configuration.version,'enabled',configuration.enabled,
  'captureId',CASE WHEN requested_action='schedule' THEN operation::text ELSE NULL END);
 INSERT INTO canvas_connector.rest_route_operation_audit(organization_id,operation_id,platform_id,route_id,actor_id,action,request,receipt)
 VALUES(org,operation,platform,route,actor,requested_action,intent,result) RETURNING * INTO audit;
 -- Late expiry or same-transaction trigger changes must roll back the whole
 -- job/configuration/audit effect, never return an optimistic acknowledgment.
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE p.organization_id=org AND p.id=platform AND to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.rest_capture_routes r WHERE r.organization_id=org AND r.id=route AND to_jsonb(r)=to_jsonb(configuration))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.rest_route_operation_audit a WHERE a.organization_id=org AND a.operation_id=operation AND a.platform_id=platform AND a.route_id=route AND a.actor_id=actor AND a.action=requested_action AND a.request=intent AND a.receipt=result AND a.created_at>=started_at AND a.created_at<=clock_timestamp())
  OR (requested_action='schedule' AND NOT EXISTS(SELECT 1 FROM canvas_connector.rest_capture_jobs j WHERE j.organization_id=org AND j.capture_id=operation::text AND j.available_at>=started_at AND j.available_at<=clock_timestamp() AND jsonb_build_object('organizationId',j.organization_id,'captureId',j.capture_id,'producerRef',j.producer_ref,'routeId',j.route_id,'routeVersion',j.route_version,'platformId',j.platform_id,'bindingId',j.binding_id,'bindingRevision',j.binding_revision,'requirement',j.requirement,'claimNames',j.claim_names,'effectiveTimePolicy',j.effective_time_policy,'phase',j.phase,'attempts',j.attempts,'availableAt',j.available_at,'leaseId',j.lease_id,'leaseExpiresAt',j.lease_expires_at)=scheduled))
  OR (needs_connection AND NOT EXISTS(SELECT 1 FROM canvas_connector.connections c WHERE c.organization_id=org AND c.platform_id=platform
    AND to_jsonb(c)=to_jsonb(connection) AND (c.token_expires_at IS NULL OR c.token_expires_at>clock_timestamp()))) THEN
  RAISE EXCEPTION 'capture route operation changed';
 END IF;
 RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.rest_route_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_rest_route_operation_audit(),
 canvas_connector.administer_rest_route(text,text,text,uuid,text,text,bigint,bigint,jsonb) FROM PUBLIC;
COMMIT;
