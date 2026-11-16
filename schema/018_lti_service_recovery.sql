-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner only. Resolution preserves custody/history and does not claim remote revocation.
BEGIN;
CREATE TABLE canvas_connector.lti_service_recovery_audit (
 organization_id text NOT NULL,
 operation_id uuid NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 attempt_id uuid NOT NULL,
 actor_id text NOT NULL,
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,operation_id),
 FOREIGN KEY(organization_id,platform_id,registration_id,attempt_id)
  REFERENCES canvas_connector.lti_service_attempts(organization_id,platform_id,registration_id,operation_id)
);
CREATE TRIGGER lti_service_recovery_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_service_recovery_audit
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_tool_key_history();
CREATE FUNCTION canvas_connector.recover_lti_service_attempt(org text,platform text,registration uuid,attempt uuid,
 operation uuid,actor text,requested_action text,expected_phase text,expected_platform bigint,expected_registration bigint,
 expected_key bigint,confirmation uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; saved canvas_connector.lti_service_attempts;
 host canvas_connector.platforms; reg canvas_connector.lti_registrations; configuration canvas_connector.lti_tool_key_configurations;
 token canvas_connector.lti_service_tokens; prior canvas_connector.lti_service_recovery_audit;
 intent jsonb; result jsonb; disposition text; started timestamptz:=clock_timestamp();
BEGIN
 IF org IS NULL OR platform IS NULL OR registration IS NULL OR attempt IS NULL OR operation IS NULL OR actor IS NULL
  OR actor COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR requested_action IS NULL
  OR requested_action NOT IN ('abandon_prepared','retire_known','resolve_unknown') OR expected_phase IS NULL THEN RETURN NULL; END IF;
 IF requested_action='resolve_unknown' THEN
  IF confirmation IS NULL OR expected_platform IS NULL OR expected_registration IS NULL OR expected_key IS NULL
   OR expected_phase NOT IN ('exchanging','uncertain') THEN RETURN NULL; END IF;
 ELSE
  IF confirmation IS NOT NULL OR expected_platform IS NOT NULL OR expected_registration IS NOT NULL OR expected_key IS NOT NULL
   OR (requested_action='abandon_prepared' AND expected_phase<>'prepared')
   OR (requested_action='retire_known' AND expected_phase NOT IN ('staged','published')) THEN RETURN NULL; END IF;
 END IF;
 intent:=jsonb_build_object('action',requested_action,'expectedPhase',expected_phase,'expectedPlatformVersion',expected_platform,
  'expectedRegistrationVersion',expected_registration,'expectedKeyVersion',expected_key,'confirmationReference',confirmation);
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-service-recovery',org,operation)::text,0));
 SELECT * INTO prior FROM canvas_connector.lti_service_recovery_audit WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF prior.platform_id IS DISTINCT FROM platform OR prior.registration_id IS DISTINCT FROM registration OR prior.attempt_id IS DISTINCT FROM attempt
   OR prior.actor_id IS DISTINCT FROM actor OR prior.request IS DISTINCT FROM intent THEN RETURN NULL; END IF;
  RETURN prior.receipt;
 END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO reg FROM canvas_connector.lti_registrations WHERE organization_id=org AND platform_id=platform AND id=registration FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO configuration FROM canvas_connector.lti_tool_key_configurations
  WHERE organization_id=org AND platform_id=platform AND registration_id=registration FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND platform_id=platform
  AND registration_id=registration AND operation_id=attempt FOR UPDATE;
 IF NOT FOUND OR a.phase IS DISTINCT FROM expected_phase THEN RETURN NULL; END IF;
 IF requested_action='abandon_prepared' THEN
  IF a.dispatch_id IS NOT NULL OR a.token_reference IS NOT NULL
   OR EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens WHERE organization_id=org AND operation_id=attempt) THEN RETURN NULL; END IF;
  disposition:='not_dispatched';
 ELSIF requested_action='resolve_unknown' THEN
  IF a.token_reference IS NOT NULL OR a.dispatch_id IS NULL OR host.enabled OR reg.enabled OR configuration.current_kid IS NOT NULL
   OR host.config_version IS DISTINCT FROM expected_platform OR reg.version IS DISTINCT FROM expected_registration
   OR configuration.version IS DISTINCT FROM expected_key
   OR EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens WHERE organization_id=org AND operation_id=attempt) THEN RETURN NULL; END IF;
  disposition:='operator_attested_external_disposition';
 ELSE
  SELECT * INTO token FROM canvas_connector.lti_service_tokens WHERE organization_id=org AND operation_id=attempt AND reference=a.token_reference;
  IF NOT FOUND OR token.retire_after>clock_timestamp() THEN RETURN NULL; END IF;
  disposition:='elapsed_provider_ttl_after_custody';
 END IF;
 UPDATE canvas_connector.lti_service_attempts SET phase='resolved' WHERE organization_id=org AND operation_id=attempt RETURNING * INTO saved;
 IF saved.phase<>'resolved' OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR (to_jsonb(saved)-ARRAY['phase','updated_at']) IS DISTINCT FROM (to_jsonb(a)-ARRAY['phase','updated_at']) THEN
  RAISE EXCEPTION 'LTI recovery attempt intent changed'; END IF;
 result:=jsonb_build_object('operationId',operation,'attemptId',attempt,'actorId',actor,'platformId',platform,'registrationId',registration,
  'action',requested_action,'priorPhase',expected_phase,'phase','resolved','tokenReference',a.token_reference,
  'confirmationReference',confirmation,'providerDisposition',disposition);
 INSERT INTO canvas_connector.lti_service_recovery_audit(organization_id,operation_id,platform_id,registration_id,attempt_id,actor_id,request,receipt)
  VALUES(org,operation,platform,registration,attempt,actor,intent,result);
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(saved))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(reg))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations c WHERE to_jsonb(c)=to_jsonb(configuration))
  OR (requested_action='retire_known' AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens t WHERE to_jsonb(t)=to_jsonb(token)))
  OR (requested_action='retire_known' AND token.retire_after>clock_timestamp())
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_recovery_audit audit WHERE audit.organization_id=org AND audit.operation_id=operation
   AND audit.platform_id=platform AND audit.registration_id=registration AND audit.attempt_id=attempt AND audit.actor_id=actor
   AND audit.request=intent AND audit.receipt=result AND audit.created_at>=started AND audit.created_at<=clock_timestamp()) THEN
  RAISE EXCEPTION 'LTI recovery operation changed'; END IF;
 RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.lti_service_recovery_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.recover_lti_service_attempt(text,text,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,uuid) FROM PUBLIC;
COMMIT;
