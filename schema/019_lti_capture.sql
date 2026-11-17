-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector provider queries and delivery state, never canonical authority.
BEGIN;
CREATE FUNCTION canvas_connector.valid_lti_capture_definition(d jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE q jsonb; name text; claims text[]; allowed text[];
BEGIN
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR d-ARRAY['producerRef','platformId','registrationId','bindingId','bindingRevision','requirement','claimNames','effectiveTimePolicy']<>'{}'
  OR (SELECT count(*) FROM jsonb_object_keys(d))<>8 THEN RETURN false; END IF;
 FOREACH name IN ARRAY ARRAY['producerRef','platformId','bindingId','registrationId','effectiveTimePolicy'] LOOP
  IF jsonb_typeof(d->name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 END LOOP;
 IF d->>'producerRef' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR d->>'platformId' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR d->>'bindingId' COLLATE "C" !~ '^[A-Za-z0-9_-]{1,128}$'
  OR d->>'registrationId' COLLATE "C" !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
  OR d->>'effectiveTimePolicy'<>'as_of_read' OR jsonb_typeof(d->'bindingRevision') IS DISTINCT FROM 'number'
  OR (d->>'bindingRevision') !~ '^[1-9][0-9]{0,15}$' OR (d->>'bindingRevision')::numeric>9007199254740991 THEN RETURN false; END IF;
 q:=d->'requirement';
 IF jsonb_typeof(q) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(q))<>5
  OR q-ARRAY['factType','courseId','userId','resourceLinkId','lineItemId','contextId']<>'{}' THEN RETURN false; END IF;
 FOREACH name IN ARRAY ARRAY['factType','courseId','userId','resourceLinkId'] LOOP
  IF jsonb_typeof(q->name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 END LOOP;
 IF NOT canvas_connector.lti_visible_identifier(q->>'userId') OR NOT canvas_connector.lti_visible_identifier(q->>'resourceLinkId') THEN RETURN false; END IF;
 IF q->>'factType'='canvas.ags_result' THEN
  IF q?'contextId' THEN RETURN false; END IF;name:='lineItemId';allowed:=ARRAY['score','score_maximum','score_percent'];
 ELSIF q->>'factType'='canvas.nrps_membership' THEN
  IF q?'lineItemId' OR jsonb_typeof(q->'contextId') IS DISTINCT FROM 'string' OR NOT canvas_connector.lti_visible_identifier(q->>'contextId') THEN RETURN false; END IF;
  name:='courseId';allowed:=ARRAY['provider_state'];
 ELSE RETURN false; END IF;
 IF jsonb_typeof(q->name) IS DISTINCT FROM 'string' OR q->>name !~ '^[1-9][0-9]{0,19}$'
  OR (q->>name)::numeric>18446744073709551615 OR q->>'courseId' !~ '^[1-9][0-9]{0,19}$'
  OR (q->>'courseId')::numeric>18446744073709551615 OR jsonb_typeof(d->'claimNames') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(d->'claimNames') v WHERE jsonb_typeof(v)<>'string') THEN RETURN false; END IF;
 SELECT array_agg(v ORDER BY ordinal) INTO claims FROM jsonb_array_elements_text(d->'claimNames') WITH ORDINALITY x(v,ordinal);
 RETURN COALESCE(cardinality(claims) BETWEEN 1 AND 3 AND claims<@allowed
  AND claims=ARRAY(SELECT v FROM (SELECT DISTINCT v FROM unnest(claims) v) unique_names ORDER BY v COLLATE "C"),false);
END;
$$;
CREATE TABLE canvas_connector.lti_capture_routes (
 organization_id text NOT NULL,id text NOT NULL CHECK(id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 producer_ref text NOT NULL,platform_id text NOT NULL,registration_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(canvas_connector.valid_lti_capture_definition(definition)),
 service_operation_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT false,
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,platform_id,registration_id,service_operation_id)
  REFERENCES canvas_connector.lti_service_attempts(organization_id,platform_id,registration_id,operation_id),
 CHECK(definition->>'producerRef'=producer_ref AND definition->>'platformId'=platform_id AND definition->>'registrationId'=registration_id::text)
);
CREATE UNIQUE INDEX lti_capture_binding ON canvas_connector.lti_capture_routes(organization_id,(definition->>'bindingId'));
CREATE FUNCTION canvas_connector.guard_lti_capture_route()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'LTI capture route retention required'; END IF;
 IF ROW(NEW.organization_id,NEW.id,NEW.producer_ref,NEW.platform_id,NEW.registration_id,NEW.definition->>'bindingId')
  IS DISTINCT FROM ROW(OLD.organization_id,OLD.id,OLD.producer_ref,OLD.platform_id,OLD.registration_id,OLD.definition->>'bindingId') THEN
  RAISE EXCEPTION 'immutable LTI capture route identity'; END IF;
 NEW.version:=OLD.version+1;RETURN NEW;
END;
$$;
CREATE TRIGGER lti_capture_route_revision BEFORE UPDATE OR DELETE ON canvas_connector.lti_capture_routes
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_capture_route();
CREATE TABLE canvas_connector.lti_capture_jobs (
 organization_id text NOT NULL,capture_id uuid NOT NULL,ordinal bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 producer_ref text NOT NULL,route_id text NOT NULL,route_version bigint NOT NULL,definition jsonb NOT NULL,
 platform_id text NOT NULL,registration_id uuid NOT NULL,service_operation_id uuid NOT NULL,token_reference uuid NOT NULL,
 canvas_origin text NOT NULL,platform_version bigint NOT NULL,registration_version bigint NOT NULL,key_version bigint NOT NULL,
 phase text NOT NULL DEFAULT 'pending' CHECK(phase IN ('pending','leased','retry','completed','parked')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000000),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_id uuid,lease_expires_at timestamptz,
 last_error text CHECK(last_error IN ('provider_unavailable','configuration_changed','observation_missing','attempt_limit')),
 completed_lease_id uuid,result jsonb,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,capture_id),
 FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.lti_capture_routes(organization_id,id),
 FOREIGN KEY(organization_id,service_operation_id,token_reference) REFERENCES canvas_connector.lti_service_tokens(organization_id,operation_id,reference),
 CHECK((phase='leased')=(lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK(phase='leased' OR lease_id IS NULL AND lease_expires_at IS NULL),
 CHECK((phase='completed')=(completed_lease_id IS NOT NULL AND result IS NOT NULL)),
 CHECK(phase='completed' OR completed_lease_id IS NULL AND result IS NULL)
);
CREATE INDEX lti_capture_ready ON canvas_connector.lti_capture_jobs(organization_id,producer_ref,ordinal) WHERE phase NOT IN ('completed','parked');
CREATE FUNCTION canvas_connector.guard_lti_capture_job()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'LTI capture retention required'; END IF;
 IF (to_jsonb(NEW)-ARRAY['phase','attempts','available_at','lease_id','lease_expires_at','last_error','completed_lease_id','result'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['phase','attempts','available_at','lease_id','lease_expires_at','last_error','completed_lease_id','result'])
  OR OLD.phase IN ('completed','parked') OR NOT (
   OLD.phase IN ('pending','retry') AND NEW.phase IN ('leased','parked')
   OR OLD.phase='leased' AND NEW.phase IN ('leased','completed','retry','parked')) THEN RAISE EXCEPTION 'immutable LTI capture'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER lti_capture_job_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_capture_jobs
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_capture_job();
CREATE FUNCTION canvas_connector.lti_capture_current(j canvas_connector.lti_capture_jobs)
RETURNS boolean LANGUAGE sql SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_routes r
  JOIN canvas_connector.lti_service_attempts a ON a.organization_id=r.organization_id AND a.operation_id=r.service_operation_id
  JOIN canvas_connector.lti_service_tokens t ON t.organization_id=a.organization_id AND t.operation_id=a.operation_id AND t.reference=a.token_reference
  WHERE r.organization_id=j.organization_id AND r.id=j.route_id AND r.producer_ref=j.producer_ref AND r.enabled AND r.version=j.route_version
   AND r.definition=j.definition AND r.platform_id=j.platform_id AND r.registration_id=j.registration_id AND r.service_operation_id=j.service_operation_id
   AND a.phase='published' AND a.platform_id=j.platform_id AND a.registration_id=j.registration_id AND a.token_reference=j.token_reference
   AND a.canvas_origin=j.canvas_origin AND a.platform_version=j.platform_version AND a.registration_version=j.registration_version AND a.key_version=j.key_version
   AND t.expires_at>clock_timestamp() AND canvas_connector.lti_service_attempt_current(a)
   AND CASE WHEN j.definition->'requirement'->>'factType'='canvas.ags_result' THEN
    ARRAY['https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly','https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly']<@t.granted_scopes
    ELSE ARRAY['https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly']<@t.granted_scopes END);
$$;
CREATE FUNCTION canvas_connector.lock_lti_capture_context(j canvas_connector.lti_capture_jobs)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts;
BEGIN
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=j.organization_id AND operation_id=j.service_operation_id;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM canvas_connector.lock_lti_service_configuration(a);
 PERFORM 1 FROM canvas_connector.lti_capture_routes WHERE organization_id=j.organization_id AND id=j.route_id FOR SHARE;
 PERFORM 1 FROM canvas_connector.lti_service_attempts WHERE organization_id=j.organization_id AND operation_id=j.service_operation_id FOR SHARE;
 RETURN canvas_connector.lti_capture_current(j);
END;
$$;
CREATE FUNCTION canvas_connector.schedule_lti_capture(org text,producer text,route text,expected bigint,capture uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE r canvas_connector.lti_capture_routes;a canvas_connector.lti_service_attempts;j canvas_connector.lti_capture_jobs;saved canvas_connector.lti_capture_jobs;stamp timestamptz;
BEGIN
 IF capture IS NULL OR expected IS NULL THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-capture',org,capture)::text,0));
 SELECT * INTO j FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=capture;
 IF FOUND THEN RETURN j.producer_ref=producer AND j.route_id=route AND j.route_version=expected; END IF;
 SELECT * INTO r FROM canvas_connector.lti_capture_routes WHERE organization_id=org AND id=route AND producer_ref=producer;
 IF NOT FOUND OR NOT r.enabled OR r.version<>expected THEN RETURN false; END IF;
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=r.service_operation_id;
 IF NOT FOUND OR a.token_reference IS NULL THEN RETURN false; END IF;
 j.organization_id:=org;j.capture_id:=capture;j.producer_ref:=producer;j.route_id:=route;j.route_version:=expected;
 j.definition:=r.definition;j.platform_id:=r.platform_id;j.registration_id:=r.registration_id;j.service_operation_id:=r.service_operation_id;
 j.token_reference:=a.token_reference;j.canvas_origin:=a.canvas_origin;j.platform_version:=a.platform_version;j.registration_version:=a.registration_version;j.key_version:=a.key_version;
 IF NOT canvas_connector.lock_lti_capture_context(j) THEN RETURN false; END IF;
 stamp:=clock_timestamp();
 INSERT INTO canvas_connector.lti_capture_jobs(organization_id,capture_id,producer_ref,route_id,route_version,definition,platform_id,registration_id,
  service_operation_id,token_reference,canvas_origin,platform_version,registration_version,key_version,available_at,created_at)
 VALUES(org,capture,producer,route,expected,j.definition,j.platform_id,j.registration_id,j.service_operation_id,j.token_reference,j.canvas_origin,j.platform_version,j.registration_version,j.key_version,stamp,stamp)
 RETURNING * INTO saved;
 IF (to_jsonb(saved)-ARRAY['ordinal','phase','attempts','available_at','lease_id','lease_expires_at','last_error','completed_lease_id','result','created_at'])
  IS DISTINCT FROM (to_jsonb(j)-ARRAY['ordinal','phase','attempts','available_at','lease_id','lease_expires_at','last_error','completed_lease_id','result','created_at'])
  OR saved.phase<>'pending' OR saved.attempts<>0 OR saved.available_at IS DISTINCT FROM stamp OR saved.created_at IS DISTINCT FROM stamp
  OR saved.lease_id IS NOT NULL OR saved.lease_expires_at IS NOT NULL OR saved.last_error IS NOT NULL OR saved.result IS NOT NULL OR saved.completed_lease_id IS NOT NULL
  OR NOT canvas_connector.lti_capture_current(saved)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs s WHERE to_jsonb(s)=to_jsonb(saved)) THEN RAISE EXCEPTION 'LTI capture schedule changed'; END IF;
 RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.claim_lti_capture(org text,producer text)
RETURNS SETOF canvas_connector.lti_capture_jobs LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE candidate canvas_connector.lti_capture_jobs;j canvas_connector.lti_capture_jobs;saved canvas_connector.lti_capture_jobs;ready boolean;lease uuid;expiry timestamptz;
BEGIN
 SELECT * INTO candidate FROM canvas_connector.lti_capture_jobs q WHERE organization_id=org AND producer_ref=producer AND available_at<=clock_timestamp()
  AND (phase IN ('pending','retry') OR phase='leased' AND lease_expires_at<=clock_timestamp())
  AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs earlier WHERE earlier.organization_id=org AND earlier.route_id=q.route_id
   AND earlier.ordinal<q.ordinal AND earlier.phase NOT IN ('completed','parked')) ORDER BY ordinal LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 ready:=canvas_connector.lock_lti_capture_context(candidate);
 SELECT * INTO j FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=candidate.capture_id FOR UPDATE SKIP LOCKED;
 IF NOT FOUND OR j.available_at>clock_timestamp() OR NOT(j.phase IN ('pending','retry') OR j.phase='leased' AND j.lease_expires_at<=clock_timestamp()) THEN RETURN; END IF;
 IF NOT ready OR NOT canvas_connector.lti_capture_current(j) OR j.attempts>=1000000 THEN
  UPDATE canvas_connector.lti_capture_jobs SET phase='parked',lease_id=NULL,lease_expires_at=NULL,last_error='configuration_changed'
   WHERE organization_id=org AND capture_id=j.capture_id RETURNING * INTO saved;
  IF (to_jsonb(saved)-ARRAY['phase','lease_id','lease_expires_at','last_error']) IS DISTINCT FROM (to_jsonb(j)-ARRAY['phase','lease_id','lease_expires_at','last_error'])
   OR saved.phase<>'parked' OR saved.lease_id IS NOT NULL OR saved.lease_expires_at IS NOT NULL OR saved.last_error IS DISTINCT FROM 'configuration_changed'
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs s WHERE to_jsonb(s)=to_jsonb(saved)) THEN RAISE EXCEPTION 'LTI capture parking changed'; END IF;
  RETURN;
 END IF;
 lease:=gen_random_uuid();expiry:=clock_timestamp()+interval '3 minutes';
 UPDATE canvas_connector.lti_capture_jobs SET phase='leased',lease_id=lease,lease_expires_at=expiry,attempts=j.attempts+1
  WHERE organization_id=org AND capture_id=j.capture_id RETURNING * INTO saved;
 IF (to_jsonb(saved)-ARRAY['phase','lease_id','lease_expires_at','attempts']) IS DISTINCT FROM (to_jsonb(j)-ARRAY['phase','lease_id','lease_expires_at','attempts'])
  OR saved.phase<>'leased' OR saved.lease_id IS DISTINCT FROM lease OR saved.lease_expires_at IS DISTINCT FROM expiry OR saved.attempts<>j.attempts+1
  OR expiry<=clock_timestamp() OR NOT canvas_connector.lti_capture_current(saved)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs s WHERE to_jsonb(s)=to_jsonb(saved)) THEN RAISE EXCEPTION 'LTI capture claim changed'; END IF;
 RETURN NEXT saved;
END;
$$;
CREATE FUNCTION canvas_connector.complete_lti_capture(org text,producer text,capture uuid,lease uuid,observed bigint,effective bigint,assertions jsonb)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE j canvas_connector.lti_capture_jobs;saved canvas_connector.lti_capture_jobs;payload jsonb;names text[];name text;o canvas_connector.observation_outbox;
BEGIN
 payload:=jsonb_build_object('observedAtMs',observed,'effectiveAtMs',effective,'claims',assertions);
 SELECT * INTO j FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=capture AND producer_ref=producer;
 IF NOT FOUND OR lease IS NULL THEN RETURN false; END IF;
 IF j.phase='completed' THEN RETURN j.completed_lease_id=lease AND j.result=payload; END IF;
 IF NOT canvas_connector.lock_lti_capture_context(j) THEN RETURN false; END IF;
 SELECT * INTO j FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND capture_id=capture AND producer_ref=producer FOR UPDATE;
 IF j.phase='completed' THEN RETURN j.completed_lease_id=lease AND j.result=payload; END IF;
 IF j.phase<>'leased' OR j.lease_id IS DISTINCT FROM lease OR j.lease_expires_at<=clock_timestamp() OR NOT canvas_connector.lti_capture_current(j) THEN RETURN false; END IF;
 SELECT array_agg(v) INTO names FROM jsonb_array_elements_text(j.definition->'claimNames') v;
 IF observed IS NULL OR effective IS DISTINCT FROM observed OR observed NOT BETWEEN 1 AND 9007199254740991
  OR NOT COALESCE(canvas_connector.valid_outbox_claims(assertions),false) OR assertions->>'effective_time_source' IS DISTINCT FROM 'observation_read'
  OR (SELECT count(*) FROM jsonb_object_keys(assertions))<>cardinality(names)+1
  OR EXISTS(SELECT 1 FROM jsonb_object_keys(assertions) n WHERE n<>'effective_time_source' AND NOT n=ANY(names)) THEN RAISE EXCEPTION 'LTI capture projection mismatch'; END IF;
 FOREACH name IN ARRAY names LOOP
  IF name='provider_state' THEN
   IF jsonb_typeof(assertions->name) IS DISTINCT FROM 'string' OR assertions->>name NOT IN ('Active','Inactive','Deleted') THEN RAISE EXCEPTION 'LTI membership projection mismatch'; END IF;
  ELSIF jsonb_typeof(assertions->name) NOT IN ('number','null') OR name='score_maximum' AND (assertions->>name)::numeric<0 THEN
   RAISE EXCEPTION 'LTI score projection mismatch';
  END IF;
 END LOOP;
 -- Serialize against every producer of this binding's existing outbox. A
 -- matching row from a different capture pipeline is an identity collision,
 -- never proof that this leased LTI capture already committed.
 INSERT INTO canvas_connector.observation_counters(organization_id,binding_id) VALUES(org,j.definition->>'bindingId') ON CONFLICT DO NOTHING;
 PERFORM 1 FROM canvas_connector.observation_counters WHERE organization_id=org AND binding_id=j.definition->>'bindingId' FOR UPDATE;
 IF EXISTS(SELECT 1 FROM canvas_connector.observation_outbox WHERE organization_id=org AND observation_id=capture::text) THEN
  RAISE EXCEPTION 'LTI observation identity collision'; END IF;
 SELECT * INTO o FROM canvas_connector.enqueue_observation(org,producer,j.definition->>'bindingId',(j.definition->>'bindingRevision')::bigint,capture::text,observed,effective,assertions);
 IF NOT FOUND OR ROW(o.organization_id,o.producer_ref,o.observation_id,o.binding_id,o.binding_revision,o.observed_at_ms,o.effective_at_ms,o.claims)
  IS DISTINCT FROM ROW(org,producer,capture::text,j.definition->>'bindingId',(j.definition->>'bindingRevision')::bigint,observed,effective,assertions)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.observation_outbox x WHERE to_jsonb(x)=to_jsonb(o))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.observation_counters c WHERE c.organization_id=org AND c.binding_id=o.binding_id AND c.current_sequence=o.sequence) THEN
  RAISE EXCEPTION 'LTI capture outbox changed'; END IF;
 UPDATE canvas_connector.lti_capture_jobs SET phase='completed',completed_lease_id=lease,result=payload,lease_id=NULL,lease_expires_at=NULL,last_error=NULL
  WHERE organization_id=org AND capture_id=capture RETURNING * INTO saved;
 IF (to_jsonb(saved)-ARRAY['phase','completed_lease_id','result','lease_id','lease_expires_at','last_error']) IS DISTINCT FROM
   (to_jsonb(j)-ARRAY['phase','completed_lease_id','result','lease_id','lease_expires_at','last_error'])
  OR saved.phase<>'completed' OR saved.completed_lease_id IS DISTINCT FROM lease OR saved.result IS DISTINCT FROM payload
  OR saved.lease_id IS NOT NULL OR saved.lease_expires_at IS NOT NULL OR saved.last_error IS NOT NULL
  OR j.lease_expires_at<=clock_timestamp() OR NOT canvas_connector.lti_capture_current(saved)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.observation_outbox x WHERE to_jsonb(x)=to_jsonb(o))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.observation_counters c WHERE c.organization_id=org AND c.binding_id=o.binding_id AND c.current_sequence=o.sequence)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs s WHERE to_jsonb(s)=to_jsonb(saved)) THEN RAISE EXCEPTION 'LTI capture completion changed'; END IF;
 RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.defer_lti_capture(org text,producer text,capture uuid,lease uuid,code text,park boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE j canvas_connector.lti_capture_jobs;saved canvas_connector.lti_capture_jobs;due timestamptz;target text;
BEGIN
 IF lease IS NULL OR park IS NULL OR code IS NULL OR code NOT IN ('provider_unavailable','configuration_changed','observation_missing','attempt_limit') THEN RETURN false; END IF;
 SELECT * INTO j FROM canvas_connector.lti_capture_jobs WHERE organization_id=org AND producer_ref=producer AND capture_id=capture FOR UPDATE;
 IF NOT FOUND OR j.phase<>'leased' OR j.lease_id IS DISTINCT FROM lease OR j.lease_expires_at<=clock_timestamp() THEN RETURN false; END IF;
 due:=clock_timestamp()+make_interval(secs=>least(300,power(2,least(j.attempts,10)))::integer);target:=CASE WHEN park THEN 'parked' ELSE 'retry' END;
 UPDATE canvas_connector.lti_capture_jobs SET phase=target,lease_id=NULL,lease_expires_at=NULL,available_at=due,last_error=code
  WHERE organization_id=org AND capture_id=capture RETURNING * INTO saved;
 IF (to_jsonb(saved)-ARRAY['phase','lease_id','lease_expires_at','available_at','last_error']) IS DISTINCT FROM
   (to_jsonb(j)-ARRAY['phase','lease_id','lease_expires_at','available_at','last_error'])
  OR saved.phase IS DISTINCT FROM target OR saved.available_at IS DISTINCT FROM due OR saved.last_error IS DISTINCT FROM code
  OR saved.lease_id IS NOT NULL OR saved.lease_expires_at IS NOT NULL OR j.lease_expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_capture_jobs s WHERE to_jsonb(s)=to_jsonb(saved)) THEN RAISE EXCEPTION 'LTI capture defer changed'; END IF;
 RETURN true;
END;
$$;
REVOKE ALL ON canvas_connector.lti_capture_routes,canvas_connector.lti_capture_jobs FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.valid_lti_capture_definition(jsonb),canvas_connector.guard_lti_capture_route(),canvas_connector.guard_lti_capture_job(),
 canvas_connector.lti_capture_current(canvas_connector.lti_capture_jobs),canvas_connector.lock_lti_capture_context(canvas_connector.lti_capture_jobs),
 canvas_connector.schedule_lti_capture(text,text,text,bigint,uuid),canvas_connector.claim_lti_capture(text,text),
 canvas_connector.complete_lti_capture(text,text,uuid,uuid,bigint,bigint,jsonb),canvas_connector.defer_lti_capture(text,text,uuid,uuid,text,boolean) FROM PUBLIC;
COMMIT;
