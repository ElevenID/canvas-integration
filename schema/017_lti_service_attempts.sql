-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector owner migration. No runtime DDL/grants or canonical authority.
BEGIN;
CREATE FUNCTION canvas_connector.lti_service_read_scopes(value text[])
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT COALESCE(cardinality(value) BETWEEN 1 AND 3 AND array_ndims(value)=1 AND array_lower(value,1)=1
  AND NOT EXISTS(SELECT 1 FROM unnest(value) s WHERE s IS NULL OR s NOT IN (
   'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
   'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',
   'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly'))
  AND value=ARRAY(SELECT s FROM (SELECT DISTINCT s FROM unnest(value) s) unique_scopes ORDER BY s COLLATE "C"),false);
$$;
CREATE TABLE canvas_connector.lti_service_attempts (
 organization_id text NOT NULL,
 operation_id uuid NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 actor_id text NOT NULL CHECK(actor_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 platform_version bigint NOT NULL CHECK(platform_version BETWEEN 1 AND 9007199254740991),
 registration_version bigint NOT NULL CHECK(registration_version BETWEEN 1 AND 9007199254740991),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 9007199254740991),
 kid uuid NOT NULL,
 client_id text NOT NULL,
 canvas_origin text NOT NULL,
 tool_origin text NOT NULL,
 requested_scopes text[] NOT NULL CHECK(canvas_connector.lti_service_read_scopes(requested_scopes)),
 phase text NOT NULL DEFAULT 'prepared' CHECK(phase IN ('prepared','exchanging','uncertain','staged','published','resolved')),
 dispatch_id uuid UNIQUE,
 issued_at bigint,
 assertion_expires_at bigint,
 token_reference uuid,
 receipt jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 prepare_expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '5 minutes'),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,operation_id),
 UNIQUE(organization_id,platform_id,registration_id,operation_id),
 FOREIGN KEY(organization_id,platform_id,registration_id,kid)
  REFERENCES canvas_connector.lti_tool_keys(organization_id,platform_id,registration_id,kid),
 CHECK(prepare_expires_at>created_at AND prepare_expires_at<=created_at+interval '5 minutes 1 second'),
 CHECK((dispatch_id IS NULL AND issued_at IS NULL AND assertion_expires_at IS NULL)
  OR (dispatch_id IS NOT NULL AND issued_at IS NOT NULL AND assertion_expires_at=issued_at+120)),
 CHECK(phase<>'prepared' OR dispatch_id IS NULL),
 CHECK(phase IN ('prepared','resolved') OR dispatch_id IS NOT NULL),
 CHECK(phase='resolved' OR (phase IN ('staged','published'))=(token_reference IS NOT NULL)),
 CHECK(phase='resolved' OR (phase='published')=(receipt IS NOT NULL)),
 CHECK(receipt IS NULL OR jsonb_typeof(receipt)='object')
);
CREATE UNIQUE INDEX lti_service_unresolved ON canvas_connector.lti_service_attempts(organization_id,platform_id,registration_id)
 WHERE phase IN ('prepared','exchanging','uncertain','staged');
CREATE TABLE canvas_connector.lti_service_tokens (
 organization_id text NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 reference uuid NOT NULL UNIQUE,
 granted_scopes text[] NOT NULL CHECK(canvas_connector.lti_service_read_scopes(granted_scopes)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 wrapping_key_id text NOT NULL CHECK(wrapping_key_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 16 AND 16386),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 tag bytea NOT NULL CHECK(octet_length(tag)=16),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retire_after timestamptz NOT NULL CHECK(isfinite(retire_after) AND retire_after>created_at),
 PRIMARY KEY(organization_id,operation_id),
 UNIQUE(organization_id,operation_id,reference),
 FOREIGN KEY(organization_id,platform_id,registration_id,operation_id)
  REFERENCES canvas_connector.lti_service_attempts(organization_id,platform_id,registration_id,operation_id)
);
ALTER TABLE canvas_connector.lti_service_attempts ADD CONSTRAINT lti_service_staged_token
 FOREIGN KEY(organization_id,operation_id,token_reference) REFERENCES canvas_connector.lti_service_tokens(organization_id,operation_id,reference);
CREATE TRIGGER lti_service_token_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_service_tokens
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_tool_key_history();
CREATE FUNCTION canvas_connector.guard_lti_service_attempt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'LTI service attempt history is immutable'; END IF;
 IF (to_jsonb(NEW)-ARRAY['phase','dispatch_id','issued_at','assertion_expires_at','token_reference','receipt','updated_at'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['phase','dispatch_id','issued_at','assertion_expires_at','token_reference','receipt','updated_at'])
  OR NOT ((OLD.phase='prepared' AND NEW.phase IN ('exchanging','resolved'))
   OR (OLD.phase='exchanging' AND NEW.phase IN ('uncertain','staged','resolved'))
   OR (OLD.phase='uncertain' AND NEW.phase IN ('staged','resolved'))
   OR (OLD.phase='staged' AND NEW.phase IN ('published','resolved'))
   OR (OLD.phase='published' AND NEW.phase='resolved')
   OR (OLD.phase='resolved' AND NEW.phase='resolved' AND OLD.dispatch_id IS NOT NULL
    AND OLD.token_reference IS NULL AND NEW.token_reference IS NOT NULL))
  OR (OLD.phase<>'prepared' AND ROW(NEW.dispatch_id,NEW.issued_at,NEW.assertion_expires_at)
    IS DISTINCT FROM ROW(OLD.dispatch_id,OLD.issued_at,OLD.assertion_expires_at))
  OR (OLD.phase='prepared' AND NEW.phase='resolved' AND NEW.dispatch_id IS NOT NULL)
  OR (NEW.phase NOT IN ('staged','published','resolved') AND (NEW.token_reference IS NOT NULL OR NEW.receipt IS NOT NULL))
  OR (OLD.phase IN ('staged','published') AND NEW.token_reference IS DISTINCT FROM OLD.token_reference)
  OR (NEW.phase='resolved' AND OLD.phase<>'resolved' AND ROW(NEW.token_reference,NEW.receipt) IS DISTINCT FROM ROW(OLD.token_reference,OLD.receipt))
  OR (OLD.phase='resolved' AND NEW.receipt IS DISTINCT FROM OLD.receipt) THEN
  RAISE EXCEPTION 'Invalid LTI service attempt transition' USING ERRCODE='23514';
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END;
$$;
CREATE TRIGGER lti_service_attempt_transition BEFORE UPDATE OR DELETE ON canvas_connector.lti_service_attempts
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_service_attempt();
CREATE FUNCTION canvas_connector.lti_service_attempt_view(a canvas_connector.lti_service_attempts)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('organizationId',a.organization_id,'operationId',a.operation_id,'platformId',a.platform_id,
  'registrationId',a.registration_id,'actorId',a.actor_id,'platformVersion',a.platform_version,
  'registrationVersion',a.registration_version,'keyVersion',a.key_version,'kid',a.kid,'clientId',a.client_id,
  'canvasOrigin',a.canvas_origin,'toolOrigin',a.tool_origin,'scopes',a.requested_scopes,'phase',a.phase,
  'dispatchId',a.dispatch_id,'issuedAt',a.issued_at,'expiresAt',a.assertion_expires_at,
  'tokenReference',a.token_reference,'receipt',a.receipt);
$$;
CREATE FUNCTION canvas_connector.lti_service_attempt_current(a canvas_connector.lti_service_attempts)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM canvas_connector.platforms p
  JOIN canvas_connector.lti_registrations r ON r.organization_id=p.organization_id AND r.platform_id=p.id
  JOIN canvas_connector.lti_tool_key_configurations c ON c.organization_id=r.organization_id AND c.platform_id=r.platform_id AND c.registration_id=r.id
  JOIN canvas_connector.lti_tool_keys k ON k.organization_id=c.organization_id AND k.platform_id=c.platform_id AND k.registration_id=c.registration_id AND k.kid=c.current_kid
  WHERE p.organization_id=a.organization_id AND p.id=a.platform_id AND r.id=a.registration_id
   AND p.enabled AND NOT p.archived AND r.enabled AND p.config_version=a.platform_version AND r.version=a.registration_version
   AND c.version=a.key_version AND c.current_kid=a.kid AND k.platform_version=a.platform_version
   AND k.registration_version=a.registration_version AND k.client_id=a.client_id AND r.client_id=a.client_id
   AND p.canvas_origin=a.canvas_origin AND k.tool_origin=a.tool_origin
   AND r.target_link_uri=a.tool_origin||'/lti/registrations/'||r.id::text||'/resource');
$$;
CREATE FUNCTION canvas_connector.lock_lti_service_configuration(a canvas_connector.lti_service_attempts)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=a.organization_id AND id=a.platform_id FOR UPDATE;
 PERFORM 1 FROM canvas_connector.lti_registrations WHERE organization_id=a.organization_id AND platform_id=a.platform_id AND id=a.registration_id FOR UPDATE;
 PERFORM 1 FROM canvas_connector.lti_tool_key_configurations WHERE organization_id=a.organization_id AND platform_id=a.platform_id AND registration_id=a.registration_id FOR UPDATE;
 RETURN canvas_connector.lti_service_attempt_current(a);
END;
$$;
CREATE FUNCTION canvas_connector.prepare_lti_service_attempt(org text,platform text,registration uuid,operation uuid,actor text,
 expected_platform bigint,expected_registration bigint,expected_key bigint,scopes text[])
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; k canvas_connector.lti_tool_keys;
 started timestamptz:=clock_timestamp();
BEGIN
 IF org IS NULL OR platform IS NULL OR registration IS NULL OR operation IS NULL OR actor IS NULL
  OR actor COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR NOT canvas_connector.lti_service_read_scopes(scopes)
  OR expected_platform IS NULL OR expected_registration IS NULL OR expected_key IS NULL THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-service-attempt',org,operation)::text,0));
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF a.platform_id IS DISTINCT FROM platform OR a.registration_id IS DISTINCT FROM registration OR a.actor_id IS DISTINCT FROM actor
   OR a.platform_version IS DISTINCT FROM expected_platform OR a.registration_version IS DISTINCT FROM expected_registration
   OR a.key_version IS DISTINCT FROM expected_key OR a.requested_scopes IS DISTINCT FROM scopes THEN RETURN NULL; END IF;
  RETURN canvas_connector.lti_service_attempt_view(a);
 END IF;
 a.organization_id:=org;a.platform_id:=platform;a.registration_id:=registration;
 a.platform_version:=expected_platform;a.registration_version:=expected_registration;a.key_version:=expected_key;
 PERFORM canvas_connector.lock_lti_service_configuration(a);
 SELECT material.* INTO k FROM canvas_connector.lti_tool_keys material JOIN canvas_connector.lti_tool_key_configurations c
  ON c.organization_id=material.organization_id AND c.platform_id=material.platform_id AND c.registration_id=material.registration_id AND c.current_kid=material.kid
  WHERE c.organization_id=org AND c.platform_id=platform AND c.registration_id=registration AND c.version=expected_key;
 IF NOT FOUND THEN RETURN NULL; END IF;
 a.kid:=k.kid;a.client_id:=k.client_id;a.tool_origin:=k.tool_origin;
 SELECT canvas_origin INTO a.canvas_origin FROM canvas_connector.platforms WHERE organization_id=org AND id=platform;
 IF NOT canvas_connector.lti_service_attempt_current(a)
  OR EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND platform_id=platform AND registration_id=registration
    AND phase IN ('prepared','exchanging','uncertain','staged')) THEN RETURN NULL; END IF;
 INSERT INTO canvas_connector.lti_service_attempts(organization_id,operation_id,platform_id,registration_id,actor_id,
  platform_version,registration_version,key_version,kid,client_id,canvas_origin,tool_origin,requested_scopes)
 VALUES(org,operation,platform,registration,actor,expected_platform,expected_registration,expected_key,k.kid,k.client_id,a.canvas_origin,k.tool_origin,scopes)
 RETURNING * INTO a;
 IF a.organization_id IS DISTINCT FROM org OR a.operation_id IS DISTINCT FROM operation OR a.platform_id IS DISTINCT FROM platform
  OR a.registration_id IS DISTINCT FROM registration OR a.actor_id IS DISTINCT FROM actor OR a.platform_version IS DISTINCT FROM expected_platform
  OR a.registration_version IS DISTINCT FROM expected_registration OR a.key_version IS DISTINCT FROM expected_key OR a.kid IS DISTINCT FROM k.kid
  OR a.client_id IS DISTINCT FROM k.client_id OR a.tool_origin IS DISTINCT FROM k.tool_origin OR a.requested_scopes IS DISTINCT FROM scopes
  OR a.phase<>'prepared' OR a.dispatch_id IS NOT NULL OR a.created_at<started OR a.created_at>clock_timestamp()
  OR a.updated_at<started OR a.updated_at>clock_timestamp() OR a.prepare_expires_at<=clock_timestamp()
  OR NOT canvas_connector.lti_service_attempt_current(a)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts saved WHERE to_jsonb(saved)=to_jsonb(a)) THEN
  RAISE EXCEPTION 'LTI service attempt intent changed'; END IF;
 RETURN canvas_connector.lti_service_attempt_view(a);
END;
$$;
CREATE FUNCTION canvas_connector.begin_lti_service_exchange(org text,operation uuid,dispatch uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; saved canvas_connector.lti_service_attempts; stamp bigint; started timestamptz:=clock_timestamp();
BEGIN
 IF dispatch IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation;
 IF NOT FOUND OR NOT canvas_connector.lock_lti_service_configuration(a) THEN RETURN NULL; END IF;
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation FOR UPDATE;
 IF a.phase<>'prepared' OR a.prepare_expires_at<=clock_timestamp() THEN RETURN NULL; END IF;
 stamp:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 UPDATE canvas_connector.lti_service_attempts SET phase='exchanging',dispatch_id=dispatch,issued_at=stamp,assertion_expires_at=stamp+120
  WHERE organization_id=org AND operation_id=operation RETURNING * INTO saved;
 IF saved.phase<>'exchanging' OR saved.dispatch_id IS DISTINCT FROM dispatch OR saved.issued_at IS DISTINCT FROM stamp
  OR saved.assertion_expires_at IS DISTINCT FROM stamp+120
  OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR saved.prepare_expires_at<=clock_timestamp() OR to_timestamp(saved.assertion_expires_at)<=clock_timestamp()
  OR (to_jsonb(saved)-ARRAY['phase','dispatch_id','issued_at','assertion_expires_at','updated_at']) IS DISTINCT FROM
     (to_jsonb(a)-ARRAY['phase','dispatch_id','issued_at','assertion_expires_at','updated_at'])
  OR NOT canvas_connector.lti_service_attempt_current(saved)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(saved)) THEN
  RAISE EXCEPTION 'LTI service exchange intent changed'; END IF;
 RETURN canvas_connector.lti_service_attempt_view(saved);
END;
$$;
CREATE FUNCTION canvas_connector.stage_lti_service_token(org text,operation uuid,dispatch uuid,reference uuid,scopes text[],expiry timestamptz,
 wrapping_key text,digest bytea,encrypted bytea,iv bytea,authentication_tag bytea)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; saved canvas_connector.lti_service_attempts;
 token canvas_connector.lti_service_tokens; started timestamptz:=clock_timestamp(); staged_clock timestamptz;
BEGIN
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation FOR UPDATE;
 IF NOT FOUND OR a.dispatch_id IS DISTINCT FROM dispatch OR dispatch IS NULL THEN RETURN NULL; END IF;
 IF a.phase IN ('staged','published') OR (a.phase='resolved' AND a.token_reference IS NOT NULL) THEN
  IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens t WHERE t.organization_id=org AND t.operation_id=operation
   AND t.granted_scopes=scopes AND t.expires_at=expiry AND t.wrapping_key_id=wrapping_key AND t.input_digest=digest) THEN RETURN NULL; END IF;
  RETURN canvas_connector.lti_service_attempt_view(a);
 END IF;
 -- A response already in flight when an operator resolves uncertainty still
 -- enters encrypted custody, while the terminal resolution stays in force.
 IF a.phase NOT IN ('exchanging','uncertain','resolved') OR reference IS NULL OR NOT canvas_connector.lti_service_read_scopes(scopes)
  OR NOT scopes<@a.requested_scopes OR expiry IS NULL OR NOT isfinite(expiry)
  OR expiry<=to_timestamp(a.issued_at) OR expiry>to_timestamp(a.issued_at)+interval '24 hours'
  OR wrapping_key IS NULL OR wrapping_key COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR digest IS NULL OR octet_length(digest)<>32
  OR encrypted IS NULL OR octet_length(encrypted) NOT BETWEEN 16 AND 16386
  OR iv IS NULL OR octet_length(iv)<>12 OR authentication_tag IS NULL OR octet_length(authentication_tag)<>16 THEN RETURN NULL; END IF;
 staged_clock:=clock_timestamp();
 INSERT INTO canvas_connector.lti_service_tokens(organization_id,platform_id,registration_id,operation_id,reference,granted_scopes,expires_at,
  wrapping_key_id,input_digest,ciphertext,nonce,tag,created_at,retire_after)
  VALUES(org,a.platform_id,a.registration_id,operation,reference,scopes,expiry,wrapping_key,digest,encrypted,iv,authentication_tag,
   staged_clock,staged_clock+(expiry-to_timestamp(a.issued_at)))
  RETURNING * INTO token;
 IF ROW(token.organization_id,token.platform_id,token.registration_id,token.operation_id,token.reference,token.granted_scopes,token.expires_at,
  token.wrapping_key_id,token.input_digest,token.ciphertext,token.nonce,token.tag) IS DISTINCT FROM
  ROW(org,a.platform_id,a.registration_id,operation,reference,scopes,expiry,wrapping_key,digest,encrypted,iv,authentication_tag)
  OR token.created_at IS DISTINCT FROM staged_clock OR token.created_at<started OR token.created_at>clock_timestamp()
  OR token.retire_after IS DISTINCT FROM staged_clock+(expiry-to_timestamp(a.issued_at)) THEN RAISE EXCEPTION 'LTI service token intent changed'; END IF;
 UPDATE canvas_connector.lti_service_attempts SET phase=CASE WHEN a.phase='resolved' THEN 'resolved' ELSE 'staged' END,token_reference=reference
  WHERE organization_id=org AND operation_id=operation RETURNING * INTO saved;
 IF saved.phase IS DISTINCT FROM (CASE WHEN a.phase='resolved' THEN 'resolved' ELSE 'staged' END) OR saved.token_reference IS DISTINCT FROM reference
  OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR (to_jsonb(saved)-ARRAY['phase','token_reference','updated_at']) IS DISTINCT FROM (to_jsonb(a)-ARRAY['phase','token_reference','updated_at'])
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens t WHERE to_jsonb(t)=to_jsonb(token))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(saved)) THEN
  RAISE EXCEPTION 'LTI service token staging changed'; END IF;
 RETURN canvas_connector.lti_service_attempt_view(saved);
END;
$$;
CREATE FUNCTION canvas_connector.publish_lti_service_token(org text,operation uuid,dispatch uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; saved canvas_connector.lti_service_attempts; token canvas_connector.lti_service_tokens; result jsonb;
 started timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation;
 IF NOT FOUND OR dispatch IS NULL OR a.dispatch_id IS DISTINCT FROM dispatch THEN RETURN NULL; END IF;
 IF a.phase IN ('published','resolved') AND a.receipt IS NOT NULL THEN RETURN a.receipt; END IF;
 IF NOT canvas_connector.lock_lti_service_configuration(a) THEN RETURN NULL; END IF;
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation FOR UPDATE;
 IF a.phase IN ('published','resolved') AND a.receipt IS NOT NULL THEN RETURN a.receipt; END IF;
 IF a.phase<>'staged' THEN RETURN NULL; END IF;
 SELECT * INTO token FROM canvas_connector.lti_service_tokens WHERE organization_id=org AND operation_id=operation AND reference=a.token_reference;
 IF NOT FOUND OR token.expires_at<=clock_timestamp() THEN RETURN NULL; END IF;
 result:=jsonb_build_object('operationId',operation,'actorId',a.actor_id,'platformId',a.platform_id,'registrationId',a.registration_id,
  'kid',a.kid,'keyVersion',a.key_version,'tokenReference',token.reference,'scopes',token.granted_scopes,
  'expiresAtMs',floor(extract(epoch FROM token.expires_at)*1000)::bigint);
 UPDATE canvas_connector.lti_service_attempts SET phase='published',receipt=result WHERE organization_id=org AND operation_id=operation RETURNING * INTO saved;
 IF saved.phase<>'published' OR saved.receipt IS DISTINCT FROM result
  OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR (to_jsonb(saved)-ARRAY['phase','receipt','updated_at']) IS DISTINCT FROM (to_jsonb(a)-ARRAY['phase','receipt','updated_at'])
  OR NOT canvas_connector.lti_service_attempt_current(saved) OR token.expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_tokens t WHERE to_jsonb(t)=to_jsonb(token))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(saved)) THEN
  RAISE EXCEPTION 'LTI service publication changed'; END IF;
 RETURN result;
END;
$$;
CREATE FUNCTION canvas_connector.mark_lti_service_uncertain(org text,operation uuid,dispatch uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a canvas_connector.lti_service_attempts; saved canvas_connector.lti_service_attempts; started timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO a FROM canvas_connector.lti_service_attempts WHERE organization_id=org AND operation_id=operation FOR UPDATE;
 IF NOT FOUND OR dispatch IS NULL OR a.dispatch_id IS DISTINCT FROM dispatch THEN RETURN false; END IF;
 IF a.phase='uncertain' THEN RETURN true; END IF;
 IF a.phase<>'exchanging' THEN RETURN false; END IF;
 UPDATE canvas_connector.lti_service_attempts SET phase='uncertain' WHERE organization_id=org AND operation_id=operation RETURNING * INTO saved;
 IF saved.phase<>'uncertain' OR saved.updated_at<started OR saved.updated_at>clock_timestamp()
  OR (to_jsonb(saved)-ARRAY['phase','updated_at']) IS DISTINCT FROM (to_jsonb(a)-ARRAY['phase','updated_at'])
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_service_attempts s WHERE to_jsonb(s)=to_jsonb(saved)) THEN
  RAISE EXCEPTION 'LTI uncertain exchange intent changed'; END IF;
 RETURN true;
END;
$$;
REVOKE ALL ON canvas_connector.lti_service_attempts,canvas_connector.lti_service_tokens FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.lti_service_read_scopes(text[]),canvas_connector.guard_lti_service_attempt(),
 canvas_connector.lti_service_attempt_view(canvas_connector.lti_service_attempts),
 canvas_connector.lti_service_attempt_current(canvas_connector.lti_service_attempts),
 canvas_connector.lock_lti_service_configuration(canvas_connector.lti_service_attempts),
 canvas_connector.prepare_lti_service_attempt(text,text,uuid,uuid,text,bigint,bigint,bigint,text[]),
 canvas_connector.begin_lti_service_exchange(text,uuid,uuid),
 canvas_connector.stage_lti_service_token(text,uuid,uuid,uuid,text[],timestamptz,text,bytea,bytea,bytea,bytea),
 canvas_connector.publish_lti_service_token(text,uuid,uuid),canvas_connector.mark_lti_service_uncertain(text,uuid,uuid) FROM PUBLIC;
COMMIT;
