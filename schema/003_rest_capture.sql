-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector query routing/capture state, never core permissions or authority.
BEGIN;
CREATE FUNCTION canvas_connector.valid_rest_route(requirement jsonb,names text[])
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE fact text; field text;
BEGIN
 IF jsonb_typeof(requirement)<>'object' OR requirement-'factType'-'courseId'-'userId'-'activityId'-'moduleId'<>'{}'::jsonb
  OR array_ndims(names) IS DISTINCT FROM 1 OR cardinality(names) NOT BETWEEN 1 AND 7
  OR cardinality(names)<>(SELECT count(DISTINCT name) FROM unnest(names) name)
  OR NOT(names<@ARRAY['completed','score','score_maximum','score_percent','provider_state','requirement_count','requirement_completed_count']) THEN RETURN false; END IF;
 fact:=requirement->>'factType';
 IF fact NOT IN ('canvas.assignment_score','canvas.quiz_score','canvas.module_completion','canvas.course_completion') OR fact IS NULL THEN RETURN false; END IF;
 FOREACH field IN ARRAY ARRAY['courseId','userId'] LOOP
  IF jsonb_typeof(requirement->field) IS DISTINCT FROM 'string' OR requirement->>field !~ '^[1-9][0-9]{0,19}$'
    OR (requirement->>field)::numeric>18446744073709551615 THEN RETURN false; END IF;
 END LOOP;
 IF fact IN ('canvas.assignment_score','canvas.quiz_score') THEN
  IF requirement?'moduleId' THEN RETURN false; END IF;field:='activityId';
 ELSIF fact='canvas.module_completion' THEN
  IF requirement?'activityId' THEN RETURN false; END IF;field:='moduleId';
 ELSE RETURN NOT(requirement?'activityId' OR requirement?'moduleId'); END IF;
 RETURN COALESCE(jsonb_typeof(requirement->field)='string' AND requirement->>field~'^[1-9][0-9]{0,19}$'
   AND (requirement->>field)::numeric<=18446744073709551615,false);
END;
$$;
CREATE TABLE canvas_connector.rest_capture_routes (
 organization_id text NOT NULL,id text NOT NULL CHECK(id~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 producer_ref text NOT NULL CHECK(producer_ref~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),platform_id text NOT NULL,
 binding_id text NOT NULL CHECK(binding_id~'^[A-Za-z0-9_-]{1,128}$'),
 binding_revision bigint NOT NULL CHECK(binding_revision BETWEEN 1 AND 9007199254740991),
 requirement jsonb NOT NULL,claim_names text[] NOT NULL,
 effective_time_policy text NOT NULL DEFAULT 'require_provider_time' CHECK(effective_time_policy IN ('require_provider_time','as_of_read')),
 enabled boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(organization_id,id),UNIQUE(organization_id,binding_id),
 FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
 CHECK(canvas_connector.valid_rest_route(requirement,claim_names))
);
CREATE FUNCTION canvas_connector.revise_rest_route() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (NEW.organization_id,NEW.id) IS DISTINCT FROM (OLD.organization_id,OLD.id) THEN RAISE EXCEPTION 'immutable route identity'; END IF;
 NEW.version:=OLD.version+1;RETURN NEW;
END;
$$;
CREATE TRIGGER rest_route_revision BEFORE UPDATE ON canvas_connector.rest_capture_routes FOR EACH ROW EXECUTE FUNCTION canvas_connector.revise_rest_route();
CREATE TABLE canvas_connector.rest_capture_jobs (
 organization_id text NOT NULL,capture_id text NOT NULL CHECK(capture_id~'^[A-Za-z0-9_-]{1,128}$'),
 ordinal bigint GENERATED ALWAYS AS IDENTITY UNIQUE,producer_ref text NOT NULL,route_id text NOT NULL,route_version bigint NOT NULL,
 platform_id text NOT NULL,binding_id text NOT NULL,binding_revision bigint NOT NULL,
 requirement jsonb NOT NULL,claim_names text[] NOT NULL,effective_time_policy text NOT NULL,
 phase text NOT NULL DEFAULT 'pending' CHECK(phase IN ('pending','leased','retry','completed','parked')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000000),available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_id uuid,lease_expires_at timestamptz,canvas_origin text,platform_config_version bigint,connection_revision bigint,access_token_ref text,
 capabilities text[],scopes text[],last_error text CHECK(last_error IN ('provider_unavailable','configuration_changed','invalid_observation','attempt_limit')),
 PRIMARY KEY(organization_id,capture_id),FOREIGN KEY(organization_id,route_id) REFERENCES canvas_connector.rest_capture_routes(organization_id,id),
 CHECK((phase='leased' AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL AND access_token_ref IS NOT NULL)
   OR (phase<>'leased' AND lease_id IS NULL AND lease_expires_at IS NULL))
);
CREATE FUNCTION canvas_connector.protect_rest_capture() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture retention required'; END IF;
 IF (NEW.organization_id,NEW.capture_id,NEW.ordinal,NEW.producer_ref,NEW.route_id,NEW.route_version,NEW.platform_id,
  NEW.binding_id,NEW.binding_revision,NEW.requirement,NEW.claim_names,NEW.effective_time_policy)
  IS DISTINCT FROM (OLD.organization_id,OLD.capture_id,OLD.ordinal,OLD.producer_ref,OLD.route_id,OLD.route_version,OLD.platform_id,
  OLD.binding_id,OLD.binding_revision,OLD.requirement,OLD.claim_names,OLD.effective_time_policy)
  OR (OLD.phase IN ('completed','parked') AND NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'immutable capture'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER rest_capture_immutable BEFORE UPDATE OR DELETE ON canvas_connector.rest_capture_jobs FOR EACH ROW EXECUTE FUNCTION canvas_connector.protect_rest_capture();
CREATE FUNCTION canvas_connector.schedule_rest_capture(org text,producer text,route text,capture text)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE configured canvas_connector.rest_capture_routes; old canvas_connector.rest_capture_jobs;
BEGIN
 SELECT * INTO configured FROM canvas_connector.rest_capture_routes WHERE organization_id=org AND id=route AND producer_ref=producer FOR UPDATE;
 IF NOT FOUND OR NOT configured.enabled THEN RETURN false; END IF;
 SELECT * INTO old FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND capture_id=capture;
 IF FOUND THEN
  IF old.route_id<>route OR old.producer_ref<>producer THEN RAISE EXCEPTION 'capture identity conflict'; END IF;
  RETURN true;
 END IF;
 INSERT INTO canvas_connector.rest_capture_jobs(organization_id,capture_id,producer_ref,route_id,route_version,platform_id,
  binding_id,binding_revision,requirement,claim_names,effective_time_policy)
 VALUES(org,capture,producer,route,configured.version,configured.platform_id,configured.binding_id,configured.binding_revision,
  configured.requirement,configured.claim_names,configured.effective_time_policy);
 RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.claim_rest_capture(org text,producer text)
RETURNS SETOF canvas_connector.rest_capture_jobs LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE candidate canvas_connector.rest_capture_jobs; item canvas_connector.rest_capture_jobs;
 configured canvas_connector.rest_capture_routes; platform canvas_connector.platforms; connection canvas_connector.connections;
BEGIN
 SELECT * INTO candidate FROM canvas_connector.rest_capture_jobs job WHERE organization_id=org AND producer_ref=producer
  AND available_at<=clock_timestamp() AND (phase IN ('pending','retry') OR (phase='leased' AND lease_expires_at<=clock_timestamp()))
  AND NOT EXISTS(SELECT 1 FROM canvas_connector.rest_capture_jobs earlier WHERE earlier.organization_id=org
   AND earlier.route_id=job.route_id AND earlier.ordinal<job.ordinal AND earlier.phase NOT IN ('completed','parked'))
  ORDER BY ordinal LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO platform FROM canvas_connector.platforms WHERE organization_id=org AND id=candidate.platform_id FOR SHARE;
 SELECT * INTO configured FROM canvas_connector.rest_capture_routes WHERE organization_id=org AND id=candidate.route_id FOR SHARE;
 SELECT * INTO connection FROM canvas_connector.connections WHERE organization_id=org AND platform_id=candidate.platform_id FOR SHARE;
 SELECT * INTO item FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND capture_id=candidate.capture_id FOR UPDATE SKIP LOCKED;
 IF NOT FOUND OR item.available_at>clock_timestamp()
  OR NOT(item.phase IN ('pending','retry') OR (item.phase='leased' AND item.lease_expires_at<=clock_timestamp())) THEN RETURN; END IF;
 IF NOT COALESCE(configured.enabled AND configured.version=item.route_version AND platform.enabled AND NOT platform.archived
  AND connection.status='connected' AND connection.platform_config_version=platform.config_version AND connection.canvas_origin=platform.canvas_origin
  AND (connection.token_expires_at IS NULL OR connection.token_expires_at>clock_timestamp()),false) THEN
  UPDATE canvas_connector.rest_capture_jobs SET phase='parked',lease_id=NULL,lease_expires_at=NULL,last_error='configuration_changed'
   WHERE organization_id=org AND capture_id=item.capture_id;RETURN;
 END IF;
 RETURN QUERY UPDATE canvas_connector.rest_capture_jobs SET phase='leased',lease_id=gen_random_uuid(),
  lease_expires_at=clock_timestamp()+interval '3 minutes',attempts=attempts+1,canvas_origin=platform.canvas_origin,
  platform_config_version=platform.config_version,connection_revision=connection.revision,access_token_ref=connection.access_token_ref,
  capabilities=connection.capabilities,scopes=connection.scopes WHERE organization_id=org AND capture_id=item.capture_id RETURNING *;
END;
$$;
CREATE FUNCTION canvas_connector.complete_rest_capture(org text,producer text,capture text,lease uuid,observed bigint,effective bigint,assertions jsonb)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item canvas_connector.rest_capture_jobs; candidate canvas_connector.rest_capture_jobs;
 configured canvas_connector.rest_capture_routes; platform canvas_connector.platforms; connection canvas_connector.connections;
BEGIN
 SELECT * INTO candidate FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND capture_id=capture AND producer_ref=producer;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO platform FROM canvas_connector.platforms WHERE organization_id=org AND id=candidate.platform_id FOR SHARE;
 SELECT * INTO configured FROM canvas_connector.rest_capture_routes WHERE organization_id=org AND id=candidate.route_id FOR SHARE;
 SELECT * INTO connection FROM canvas_connector.connections WHERE organization_id=org AND platform_id=candidate.platform_id FOR SHARE;
 SELECT * INTO item FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND capture_id=capture FOR UPDATE;
 IF item.phase<>'leased' OR item.lease_id IS DISTINCT FROM lease OR item.lease_expires_at<=clock_timestamp()
  OR NOT COALESCE(configured.enabled AND configured.version=item.route_version AND platform.enabled AND NOT platform.archived
   AND platform.config_version=item.platform_config_version AND connection.status='connected' AND connection.revision=item.connection_revision
   AND connection.access_token_ref=item.access_token_ref AND connection.canvas_origin=item.canvas_origin
   AND connection.platform_config_version=platform.config_version AND (connection.token_expires_at IS NULL OR connection.token_expires_at>clock_timestamp()),false) THEN RETURN false; END IF;
 IF NOT canvas_connector.valid_outbox_claims(assertions) OR (SELECT count(*) FROM jsonb_object_keys(assertions))<>cardinality(item.claim_names)+1
  OR EXISTS(SELECT 1 FROM jsonb_object_keys(assertions) name WHERE name<>'effective_time_source' AND NOT(name=ANY(item.claim_names)))
  OR COALESCE(assertions->>'effective_time_source' NOT IN ('provider_event','observation_read'),true) OR NOT(assertions?'effective_time_source')
  OR (assertions->>'effective_time_source'='observation_read' AND (item.effective_time_policy<>'as_of_read' OR effective<>observed)) THEN
  RAISE EXCEPTION 'capture projection mismatch';END IF;
 PERFORM * FROM canvas_connector.enqueue_observation(org,producer,item.binding_id,item.binding_revision,capture,observed,effective,assertions);
 UPDATE canvas_connector.rest_capture_jobs SET phase='completed',lease_id=NULL,lease_expires_at=NULL,last_error=NULL WHERE organization_id=org AND capture_id=capture;
 IF item.lease_expires_at<=clock_timestamp() OR (connection.token_expires_at IS NOT NULL AND connection.token_expires_at<=clock_timestamp()) THEN
  RAISE EXCEPTION 'capture authority expired';END IF;
 RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.defer_rest_capture(org text,producer text,capture text,lease uuid,code text,park boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item canvas_connector.rest_capture_jobs;
BEGIN
 SELECT * INTO item FROM canvas_connector.rest_capture_jobs WHERE organization_id=org AND producer_ref=producer AND capture_id=capture FOR UPDATE;
 IF NOT FOUND OR item.phase<>'leased' OR item.lease_id IS DISTINCT FROM lease OR item.lease_expires_at<=clock_timestamp() THEN RETURN false; END IF;
 UPDATE canvas_connector.rest_capture_jobs SET phase=CASE WHEN park THEN 'parked' ELSE 'retry' END,lease_id=NULL,lease_expires_at=NULL,
  available_at=clock_timestamp()+make_interval(secs=>least(300,power(2,least(attempts,10)))::integer),last_error=code
  WHERE organization_id=org AND capture_id=capture;
 IF item.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'capture lease expired'; END IF;RETURN true;
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA canvas_connector FROM PUBLIC;
COMMIT;
