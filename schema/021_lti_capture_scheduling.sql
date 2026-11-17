-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector-owned cadence and queue state. Owner installs; runtime grants none.
BEGIN;
-- Pin the retained platform revision guard for the stricter keyless worker.
ALTER FUNCTION canvas_connector.bump_platform_configuration() SET search_path=pg_catalog;
CREATE TABLE canvas_connector.lti_schedule_configurations (
 organization_id text NOT NULL,configuration_id uuid NOT NULL,producer_ref text NOT NULL,route_id text NOT NULL,
 intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object'),receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,configuration_id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.lti_capture_routes(organization_id,id)
);
CREATE TABLE canvas_connector.lti_schedule_heads (
 organization_id text NOT NULL,route_id text NOT NULL,producer_ref text NOT NULL,configuration_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 route_version bigint NOT NULL CHECK(route_version BETWEEN 1 AND 9007199254740991),
 interval_ms integer NOT NULL CHECK(interval_ms BETWEEN 1000 AND 86400000),enabled boolean NOT NULL,
 next_ordinal bigint NOT NULL DEFAULT 1 CHECK(next_ordinal BETWEEN 1 AND 9007199254740991),
 next_due_at timestamptz NOT NULL,last_capture_id uuid,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,route_id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.lti_capture_routes(organization_id,id),
 FOREIGN KEY(organization_id,configuration_id) REFERENCES canvas_connector.lti_schedule_configurations(organization_id,configuration_id)
);
CREATE TABLE canvas_connector.lti_schedule_captures (
 organization_id text NOT NULL,capture_id uuid NOT NULL,configuration_id uuid NOT NULL,route_id text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 1 AND 9007199254740990),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,capture_id),UNIQUE(organization_id,configuration_id,ordinal),
 FOREIGN KEY(organization_id,capture_id) REFERENCES canvas_connector.lti_capture_jobs(organization_id,capture_id),
 FOREIGN KEY(organization_id,configuration_id) REFERENCES canvas_connector.lti_schedule_configurations(organization_id,configuration_id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.lti_capture_routes(organization_id,id)
);
ALTER TABLE canvas_connector.lti_schedule_heads ADD FOREIGN KEY(organization_id,last_capture_id)
 REFERENCES canvas_connector.lti_schedule_captures(organization_id,capture_id);
CREATE FUNCTION canvas_connector.keep_lti_schedule_audit() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'capture schedule history is immutable' USING ERRCODE='23514';END;
$$;
CREATE TRIGGER lti_schedule_configuration_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_schedule_configurations
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_schedule_audit();
CREATE TRIGGER lti_schedule_capture_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_schedule_captures
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_schedule_audit();
CREATE FUNCTION canvas_connector.guard_lti_schedule_head() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.organization_id,NEW.route_id,NEW.producer_ref) IS DISTINCT FROM ROW(OLD.organization_id,OLD.route_id,OLD.producer_ref) THEN
  RAISE EXCEPTION 'capture schedule scope is immutable' USING ERRCODE='23514'; END IF;
 IF NEW.configuration_id=OLD.configuration_id THEN
  IF ROW(NEW.revision,NEW.route_version,NEW.interval_ms,NEW.enabled) IS DISTINCT FROM ROW(OLD.revision,OLD.route_version,OLD.interval_ms,OLD.enabled)
   OR NEW.next_ordinal<>OLD.next_ordinal+1 OR NEW.next_due_at<=OLD.next_due_at OR NEW.last_capture_id IS NULL THEN
   RAISE EXCEPTION 'capture schedule cursor is immutable' USING ERRCODE='23514'; END IF;
 ELSIF NEW.revision<>OLD.revision+1 OR NEW.next_ordinal<>1 OR NEW.last_capture_id IS NOT NULL THEN
  RAISE EXCEPTION 'capture schedule revision is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER lti_schedule_head_revision BEFORE UPDATE ON canvas_connector.lti_schedule_heads
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_schedule_head();

CREATE FUNCTION canvas_connector.tick_lti_capture_schedule(org text,producer text,route text,configuration uuid,
 expected_revision bigint,expected_route bigint,cadence integer,requested_enabled boolean)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source canvas_connector.lti_capture_routes; host canvas_connector.platforms;
 registration canvas_connector.lti_registrations;key_config canvas_connector.lti_tool_key_configurations;has_key boolean;
 credential canvas_connector.lti_service_attempts;candidate canvas_connector.lti_capture_jobs;
 head canvas_connector.lti_schedule_heads; previous canvas_connector.lti_schedule_heads;
 prior canvas_connector.lti_schedule_configurations; config_receipt jsonb; capture_receipt jsonb; requested_intent jsonb;
 queued canvas_connector.lti_capture_jobs; capture uuid; checked_at timestamptz; started timestamptz:=clock_timestamp();
 reason text;expected_job jsonb;expected_head jsonb;created boolean:=false;
BEGIN
 IF org IS NULL OR org COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR producer IS NULL OR producer COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR route IS NULL OR route COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR configuration IS NULL
  OR expected_revision IS NULL OR expected_revision NOT BETWEEN 0 AND 9007199254740990
  OR expected_route IS NULL OR expected_route NOT BETWEEN 1 AND 9007199254740991
  OR cadence IS NULL OR cadence NOT BETWEEN 1000 AND 86400000 OR requested_enabled IS NULL THEN RETURN NULL; END IF;
 requested_intent:=jsonb_build_object('producerRef',producer,'routeId',route,'expectedRevision',expected_revision,
  'routeVersion',expected_route,'intervalMs',cadence,'enabled',requested_enabled);
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-schedule',org,configuration)::text,0));
 SELECT * INTO prior FROM canvas_connector.lti_schedule_configurations WHERE organization_id=org AND configuration_id=configuration;
 IF FOUND AND (prior.producer_ref IS DISTINCT FROM producer OR prior.route_id IS DISTINCT FROM route OR prior.intent IS DISTINCT FROM requested_intent) THEN RETURN NULL; END IF;
 SELECT * INTO source FROM canvas_connector.lti_capture_routes WHERE organization_id=org AND id=route AND producer_ref=producer;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=org AND id=source.platform_id FOR UPDATE;
 SELECT * INTO registration FROM canvas_connector.lti_registrations WHERE organization_id=org AND platform_id=source.platform_id AND id=source.registration_id FOR UPDATE;
 SELECT * INTO key_config FROM canvas_connector.lti_tool_key_configurations WHERE organization_id=org AND platform_id=source.platform_id AND registration_id=source.registration_id FOR UPDATE;
 has_key:=FOUND;
 SELECT * INTO source FROM canvas_connector.lti_capture_routes WHERE organization_id=org AND id=route FOR UPDATE;
 IF source.producer_ref IS DISTINCT FROM producer OR source.platform_id IS DISTINCT FROM host.id THEN RETURN NULL; END IF;
 SELECT * INTO credential FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=source.service_operation_id FOR SHARE;
 candidate.organization_id:=org;candidate.producer_ref:=producer;candidate.route_id:=route;candidate.route_version:=source.version;
 candidate.definition:=source.definition;candidate.platform_id:=source.platform_id;candidate.registration_id:=source.registration_id;
 candidate.service_operation_id:=source.service_operation_id;candidate.token_reference:=credential.token_reference;
 candidate.canvas_origin:=credential.canvas_origin;candidate.platform_version:=credential.platform_version;
 candidate.registration_version:=credential.registration_version;candidate.key_version:=credential.key_version;
 SELECT * INTO head FROM canvas_connector.lti_schedule_heads WHERE organization_id=org AND route_id=route FOR UPDATE;
 IF prior.configuration_id IS NOT NULL THEN
  config_receipt:=prior.receipt;
  IF head.configuration_id IS DISTINCT FROM configuration THEN
   RETURN jsonb_build_object('configuration',config_receipt,'current',false,'capture',NULL,'enqueued',false,'reason','superseded'); END IF;
 ELSE
  IF coalesce(head.revision,0) IS DISTINCT FROM expected_revision OR (requested_enabled AND source.version IS DISTINCT FROM expected_route) THEN RETURN NULL; END IF;
  checked_at:=clock_timestamp();
  config_receipt:=jsonb_build_object('configurationId',configuration,'routeId',route,'producerRef',producer,
    'revision',expected_revision+1,'routeVersion',expected_route,'intervalMs',cadence,'enabled',requested_enabled,
    'configuredAtMs',floor(extract(epoch FROM checked_at)*1000)::bigint);
  INSERT INTO canvas_connector.lti_schedule_configurations(organization_id,configuration_id,producer_ref,route_id,intent,receipt)
   VALUES(org,configuration,producer,route,requested_intent,config_receipt);
  IF head.organization_id IS NULL THEN
   INSERT INTO canvas_connector.lti_schedule_heads(organization_id,route_id,producer_ref,configuration_id,revision,route_version,interval_ms,enabled,next_due_at,updated_at)
    VALUES(org,route,producer,configuration,expected_revision+1,expected_route,cadence,requested_enabled,checked_at,checked_at) RETURNING * INTO head;
  ELSE
   UPDATE canvas_connector.lti_schedule_heads SET configuration_id=configuration,revision=expected_revision+1,route_version=expected_route,
    interval_ms=cadence,enabled=requested_enabled,next_ordinal=1,next_due_at=checked_at,last_capture_id=NULL,updated_at=checked_at
    WHERE organization_id=org AND route_id=route RETURNING * INTO head;
  END IF;
  IF to_jsonb(head) IS DISTINCT FROM jsonb_build_object('organization_id',org,'route_id',route,'producer_ref',producer,
    'configuration_id',configuration,'revision',expected_revision+1,'route_version',expected_route,'interval_ms',cadence,
    'enabled',requested_enabled,'next_ordinal',1,'next_due_at',checked_at,'last_capture_id',NULL,'updated_at',checked_at) THEN
   RAISE EXCEPTION 'capture schedule configuration changed'; END IF;
 END IF;
 IF head.last_capture_id IS NOT NULL THEN
  SELECT receipt INTO capture_receipt FROM canvas_connector.lti_schedule_captures WHERE organization_id=org AND capture_id=head.last_capture_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'capture schedule receipt unavailable'; END IF;
 END IF;
 checked_at:=clock_timestamp();
 IF NOT head.enabled THEN reason:='disabled';
 ELSIF source.version<>head.route_version OR NOT source.enabled OR NOT host.enabled OR host.archived THEN reason:='route_changed';
 ELSIF checked_at<head.next_due_at THEN reason:='not_due';
 ELSIF NOT canvas_connector.lti_capture_current(candidate) THEN reason:='source_unavailable';
 ELSIF EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs j WHERE j.organization_id=org AND j.route_id=route
    AND j.route_version=source.version AND j.phase<>'completed') THEN reason:='capture_pending';
 ELSIF EXISTS(SELECT 1 FROM canvas_connector.observation_outbox o WHERE o.organization_id=org AND o.producer_ref=producer
    AND o.binding_id=source.definition->>'bindingId' AND o.binding_revision=(source.definition->>'bindingRevision')::bigint AND o.phase<>'acknowledged') THEN reason:='delivery_pending';
 END IF;
 IF reason IS NULL THEN
  IF head.next_ordinal=9007199254740991 THEN RAISE EXCEPTION 'capture schedule ordinal exhausted'; END IF;
  previous:=head;
  capture:=substr(encode(sha256(convert_to('canvas-lti-capture-v1'||E'\n'||org||E'\n'||producer||E'\n'||route||E'\n'||configuration::text||E'\n'||head.next_ordinal::text,'UTF8')),'hex'),1,32)::uuid;
  -- Parent and route locks precede the deterministic insert. Do not acquire a
  -- direct-schedule capture advisory lock after taking these parent locks.
  INSERT INTO canvas_connector.lti_capture_jobs(organization_id,capture_id,producer_ref,route_id,route_version,definition,platform_id,registration_id,
   service_operation_id,token_reference,canvas_origin,platform_version,registration_version,key_version,available_at,created_at)
  VALUES(org,capture,producer,route,source.version,source.definition,source.platform_id,source.registration_id,source.service_operation_id,
   credential.token_reference,credential.canvas_origin,credential.platform_version,credential.registration_version,credential.key_version,checked_at,checked_at)
   RETURNING * INTO queued;
  expected_job:=to_jsonb(candidate)||jsonb_build_object('capture_id',capture,'ordinal',queued.ordinal,'phase','pending','attempts',0,
   'available_at',checked_at,'created_at',checked_at,'lease_id',NULL,'lease_expires_at',NULL,'last_error',NULL,'completed_lease_id',NULL,'result',NULL);
  IF to_jsonb(queued) IS DISTINCT FROM expected_job OR NOT canvas_connector.lti_capture_current(queued) THEN RAISE EXCEPTION 'automatic LTI capture intent changed'; END IF;
  capture_receipt:=jsonb_build_object('captureId',capture,'configurationId',configuration,'routeId',route,
   'routeVersion',source.version,'revision',head.revision,'ordinal',head.next_ordinal,'enqueuedAtMs',floor(extract(epoch FROM checked_at)*1000)::bigint);
  INSERT INTO canvas_connector.lti_schedule_captures(organization_id,capture_id,configuration_id,route_id,ordinal,receipt)
   VALUES(org,capture,configuration,route,head.next_ordinal,capture_receipt);
  UPDATE canvas_connector.lti_schedule_heads SET next_ordinal=head.next_ordinal+1,next_due_at=checked_at+cadence*interval '1 millisecond',
   last_capture_id=capture,updated_at=checked_at WHERE organization_id=org AND route_id=route RETURNING * INTO head;
  expected_head:=to_jsonb(previous)||jsonb_build_object('next_ordinal',previous.next_ordinal+1,'next_due_at',checked_at+cadence*interval '1 millisecond',
   'last_capture_id',capture,'updated_at',checked_at);
  IF to_jsonb(head) IS DISTINCT FROM expected_head THEN RAISE EXCEPTION 'capture schedule cursor changed'; END IF;
  created:=true;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_schedule_configurations a WHERE a.organization_id=org AND a.configuration_id=configuration
    AND a.producer_ref=producer AND a.route_id=route AND a.intent=requested_intent AND a.receipt=config_receipt
    AND (prior.configuration_id IS NOT NULL OR (a.created_at>=started AND a.created_at<=clock_timestamp())))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_schedule_heads h WHERE to_jsonb(h)=to_jsonb(head))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_routes r WHERE to_jsonb(r)=to_jsonb(source))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(registration))
  OR has_key AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations c WHERE to_jsonb(c)=to_jsonb(key_config))
  OR NOT has_key AND EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations c WHERE c.organization_id=org AND c.platform_id=source.platform_id AND c.registration_id=source.registration_id)
  OR (created AND (NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs j WHERE to_jsonb(j)=to_jsonb(queued))
    OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_schedule_captures a WHERE a.organization_id=org AND a.capture_id=capture
     AND a.configuration_id=configuration AND a.route_id=route AND a.ordinal=previous.next_ordinal AND a.receipt=capture_receipt
     AND a.created_at>=checked_at AND a.created_at<=clock_timestamp())
    OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts a WHERE to_jsonb(a)=to_jsonb(credential))
    OR NOT canvas_connector.lti_capture_current(queued))) THEN
  RAISE EXCEPTION 'automatic capture transaction changed'; END IF;
 RETURN jsonb_build_object('configuration',config_receipt,'current',true,'capture',capture_receipt,'enqueued',created,'reason',reason);
END;
$$;
REVOKE ALL ON canvas_connector.lti_schedule_heads,canvas_connector.lti_schedule_configurations,canvas_connector.lti_schedule_captures FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.guard_lti_schedule_head(),canvas_connector.keep_lti_schedule_audit(),
 canvas_connector.tick_lti_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean) FROM PUBLIC;
COMMIT;
