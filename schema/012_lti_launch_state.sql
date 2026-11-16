-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No Core authority, runtime DDL or automatic grants.
BEGIN;
CREATE FUNCTION canvas_connector.lti_visible_identifier(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT COALESCE(value COLLATE "C" ~ '^[!-~]{1,255}$',false);
$$;
CREATE FUNCTION canvas_connector.lti_numeric_date(value jsonb)
RETURNS bigint LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN jsonb_typeof(value)='number' AND value::text ~ '^(0|[1-9][0-9]{0,15})$'
   THEN CASE WHEN value::numeric<=9007199254740991 THEN (value::text)::bigint END END;
$$;
CREATE TABLE canvas_connector.lti_registrations (
 id uuid PRIMARY KEY,
 organization_id text NOT NULL,
 platform_id text NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991),
 client_id text NOT NULL CHECK(canvas_connector.lti_visible_identifier(client_id)),
 deployment_id text NOT NULL CHECK(canvas_connector.lti_visible_identifier(deployment_id)),
 trust_profile text NOT NULL CHECK(trust_profile IN ('hosted_global','self_managed_same_origin')),
 environment text,
 target_link_uri text NOT NULL CHECK(octet_length(target_link_uri)<=2048 AND target_link_uri ~ '^https://[^[:space:]]+$'),
 enabled boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((trust_profile='hosted_global' AND environment IS NOT NULL AND environment IN ('production','beta','test'))
   OR (trust_profile='self_managed_same_origin' AND environment IS NULL)),
 FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
 UNIQUE(organization_id,platform_id,id)
);
CREATE FUNCTION canvas_connector.bump_lti_registration()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.id,NEW.organization_id,NEW.platform_id) IS DISTINCT FROM ROW(OLD.id,OLD.organization_id,OLD.platform_id) THEN
  RAISE EXCEPTION 'LTI registration identity is immutable' USING ERRCODE='23514';
 END IF;
 NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END;
$$;
CREATE TRIGGER lti_registration_revision BEFORE UPDATE ON canvas_connector.lti_registrations
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.bump_lti_registration();

CREATE TABLE canvas_connector.lti_launch_states (
 state_hash text PRIMARY KEY CHECK(state_hash ~ '^[a-f0-9]{64}$'),
 launch_id uuid NOT NULL UNIQUE,
 browser_hash text NOT NULL CHECK(browser_hash ~ '^[a-f0-9]{64}$'),
 organization_id text NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 platform_version bigint NOT NULL CHECK(platform_version BETWEEN 1 AND 9007199254740991),
 registration_version bigint NOT NULL CHECK(registration_version BETWEEN 1 AND 9007199254740991),
 registration_snapshot jsonb NOT NULL CHECK(jsonb_typeof(registration_snapshot)='object'),
 nonce text NOT NULL UNIQUE CHECK(nonce ~ '^[A-Za-z0-9_-]{43}$'),
 phase text NOT NULL DEFAULT 'pending' CHECK(phase IN ('pending','staged','accepted')),
 token_hash text CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 protocol_claims jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '5 minutes'),
 accepted_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 CHECK((phase='pending' AND token_hash IS NULL AND protocol_claims IS NULL AND accepted_at IS NULL)
   OR (phase='staged' AND token_hash IS NOT NULL AND protocol_claims IS NOT NULL AND jsonb_typeof(protocol_claims)='object' AND accepted_at IS NULL)
   OR (phase='accepted' AND token_hash IS NOT NULL AND protocol_claims IS NOT NULL AND jsonb_typeof(protocol_claims)='object' AND accepted_at IS NOT NULL)),
 FOREIGN KEY(organization_id,platform_id,registration_id)
   REFERENCES canvas_connector.lti_registrations(organization_id,platform_id,id)
);
CREATE INDEX lti_launch_states_expiry ON canvas_connector.lti_launch_states(expires_at);
CREATE FUNCTION canvas_connector.guard_lti_launch_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.state_hash,NEW.launch_id,NEW.browser_hash,NEW.organization_id,NEW.platform_id,NEW.registration_id,
   NEW.platform_version,NEW.registration_version,NEW.registration_snapshot,NEW.nonce,NEW.created_at,NEW.expires_at)
  IS DISTINCT FROM ROW(OLD.state_hash,OLD.launch_id,OLD.browser_hash,OLD.organization_id,OLD.platform_id,OLD.registration_id,
   OLD.platform_version,OLD.registration_version,OLD.registration_snapshot,OLD.nonce,OLD.created_at,OLD.expires_at)
  OR NOT ((OLD.phase='pending' AND NEW.phase='staged' AND NEW.accepted_at IS NULL)
   OR (OLD.phase='staged' AND NEW.phase='accepted' AND NEW.token_hash=OLD.token_hash AND NEW.protocol_claims=OLD.protocol_claims)) THEN
  RAISE EXCEPTION 'LTI launch transition is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER lti_launch_state_transition BEFORE UPDATE ON canvas_connector.lti_launch_states
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_launch_state();
CREATE TABLE canvas_connector.lti_launch_receipts (
 state_hash text PRIMARY KEY REFERENCES canvas_connector.lti_launch_states(state_hash),
 launch_id uuid NOT NULL UNIQUE,
 token_hash text NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION canvas_connector.keep_lti_launch_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'LTI launch receipt is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER lti_launch_receipt_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_launch_receipts
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_launch_receipt();

CREATE FUNCTION canvas_connector.lti_claims_match(payload jsonb, registration canvas_connector.lti_registrations,
 host canvas_connector.platforms, challenge text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE issued bigint; expires bigint; starts bigint; now_seconds bigint; expected_issuer text;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF ARRAY(SELECT key FROM jsonb_object_keys(payload) key ORDER BY key COLLATE "C") IS DISTINCT FROM
  ARRAY['clientId','contextId','deploymentId','expiresAt','issuedAt','issuer','messageType','nonce','notBefore','resourceLinkId','subject','targetLinkUri','version'] THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['issuer','clientId','deploymentId','targetLinkUri','nonce','messageType','version']) name
  WHERE jsonb_typeof(payload->name) IS DISTINCT FROM 'string') THEN RETURN false; END IF;
 expected_issuer:=CASE WHEN registration.trust_profile='self_managed_same_origin' THEN host.canvas_origin
  WHEN registration.environment='production' THEN 'https://canvas.instructure.com'
  WHEN registration.environment='beta' THEN 'https://canvas.beta.instructure.com'
  WHEN registration.environment='test' THEN 'https://canvas.test.instructure.com' END;
 IF NOT COALESCE(payload->>'issuer'=expected_issuer AND payload->>'clientId'=registration.client_id
  AND payload->>'deploymentId'=registration.deployment_id AND payload->>'targetLinkUri'=registration.target_link_uri
  AND payload->>'nonce'=challenge AND payload->>'messageType'='LtiResourceLinkRequest' AND payload->>'version'='1.3.0'
  AND canvas_connector.lti_visible_identifier(payload->>'subject') AND jsonb_typeof(payload->'subject')='string'
  AND canvas_connector.lti_visible_identifier(payload->>'resourceLinkId') AND jsonb_typeof(payload->'resourceLinkId')='string'
  AND (payload->'contextId'='null'::jsonb OR (jsonb_typeof(payload->'contextId')='string'
   AND canvas_connector.lti_visible_identifier(payload->>'contextId'))),false) THEN RETURN false; END IF;
 issued:=canvas_connector.lti_numeric_date(payload->'issuedAt');expires:=canvas_connector.lti_numeric_date(payload->'expiresAt');
 starts:=canvas_connector.lti_numeric_date(payload->'notBefore');now_seconds:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 RETURN COALESCE(issued IS NOT NULL AND expires IS NOT NULL AND expires>now_seconds AND issued<expires
  AND issued<=now_seconds+30 AND now_seconds-issued<=300
  AND (payload->'notBefore'='null'::jsonb OR (starts IS NOT NULL AND starts<=now_seconds)),false);
END;
$$;

CREATE FUNCTION canvas_connector.begin_lti_launch(registration uuid, expected_platform bigint, expected_registration bigint,
 requested_state text, requested_browser text, requested_nonce text, requested_launch uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE definition canvas_connector.lti_registrations; host canvas_connector.platforms;
 saved canvas_connector.lti_launch_states; started timestamptz:=clock_timestamp();expected_snapshot jsonb;
BEGIN
 IF registration IS NULL OR expected_platform IS NULL OR expected_registration IS NULL
  OR expected_platform NOT BETWEEN 1 AND 9007199254740991 OR expected_registration NOT BETWEEN 1 AND 9007199254740991
  OR requested_state IS NULL OR requested_state !~ '^[a-f0-9]{64}$'
  OR requested_browser IS NULL OR requested_browser !~ '^[a-f0-9]{64}$'
  OR requested_nonce IS NULL OR requested_nonce !~ '^[A-Za-z0-9_-]{43}$' OR requested_launch IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO definition FROM canvas_connector.lti_registrations WHERE id=registration;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=definition.organization_id AND id=definition.platform_id FOR UPDATE;
 SELECT * INTO definition FROM canvas_connector.lti_registrations WHERE id=registration FOR UPDATE;
 IF host.enabled IS DISTINCT FROM true OR host.archived IS DISTINCT FROM false OR definition.enabled IS DISTINCT FROM true
  OR host.config_version IS DISTINCT FROM expected_platform OR definition.version IS DISTINCT FROM expected_registration THEN RETURN NULL; END IF;
 expected_snapshot:=jsonb_build_object('canvasOrigin',host.canvas_origin,'trustProfile',definition.trust_profile,
  'environment',definition.environment,'clientId',definition.client_id,'deploymentId',definition.deployment_id,'targetLinkUri',definition.target_link_uri);
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state;
 IF FOUND THEN
  IF saved.registration_id IS DISTINCT FROM registration OR saved.platform_version IS DISTINCT FROM expected_platform
   OR saved.registration_version IS DISTINCT FROM expected_registration OR saved.browser_hash IS DISTINCT FROM requested_browser
   OR saved.nonce IS DISTINCT FROM requested_nonce OR saved.launch_id IS DISTINCT FROM requested_launch
   OR saved.registration_snapshot IS DISTINCT FROM expected_snapshot OR saved.phase IS DISTINCT FROM 'pending'
   OR saved.expires_at<=clock_timestamp() THEN RETURN NULL; END IF;
  RETURN to_jsonb(saved);
 END IF;
 INSERT INTO canvas_connector.lti_launch_states(state_hash,launch_id,browser_hash,organization_id,platform_id,registration_id,
  platform_version,registration_version,registration_snapshot,nonce)
 VALUES(requested_state,requested_launch,requested_browser,definition.organization_id,definition.platform_id,registration,
  expected_platform,expected_registration,expected_snapshot,requested_nonce) RETURNING * INTO saved;
 IF saved.state_hash IS DISTINCT FROM requested_state OR saved.launch_id IS DISTINCT FROM requested_launch
  OR saved.browser_hash IS DISTINCT FROM requested_browser OR saved.registration_id IS DISTINCT FROM registration
  OR saved.organization_id IS DISTINCT FROM definition.organization_id OR saved.platform_id IS DISTINCT FROM definition.platform_id
  OR saved.platform_version IS DISTINCT FROM expected_platform OR saved.registration_version IS DISTINCT FROM expected_registration
  OR saved.registration_snapshot IS DISTINCT FROM expected_snapshot
  OR saved.nonce IS DISTINCT FROM requested_nonce OR saved.phase IS DISTINCT FROM 'pending'
  OR saved.created_at<started OR saved.expires_at<=clock_timestamp() OR saved.expires_at>started+interval '5 minutes'
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(definition))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_states s WHERE s.state_hash=requested_state AND to_jsonb(s)=to_jsonb(saved)) THEN
  RAISE EXCEPTION 'LTI launch intent changed';
 END IF;
 RETURN to_jsonb(saved);
END;
$$;

CREATE FUNCTION canvas_connector.stage_lti_launch(requested_state text, requested_token text, payload jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE saved canvas_connector.lti_launch_states; definition canvas_connector.lti_registrations; host canvas_connector.platforms;
BEGIN
 IF requested_state IS NULL OR requested_state !~ '^[a-f0-9]{64}$'
  OR requested_token IS NULL OR requested_token !~ '^[a-f0-9]{64}$'
  OR jsonb_typeof(payload) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=saved.organization_id AND id=saved.platform_id FOR UPDATE;
 SELECT * INTO definition FROM canvas_connector.lti_registrations WHERE id=saved.registration_id FOR UPDATE;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state FOR UPDATE;
 IF saved.phase IN ('staged','accepted') THEN
  IF saved.token_hash=requested_token AND saved.protocol_claims=payload THEN RETURN to_jsonb(saved); END IF;
  RETURN NULL;
 END IF;
 IF host.enabled IS DISTINCT FROM true OR host.archived IS DISTINCT FROM false OR definition.enabled IS DISTINCT FROM true
  OR host.config_version IS DISTINCT FROM saved.platform_version OR definition.version IS DISTINCT FROM saved.registration_version OR saved.expires_at<=clock_timestamp()
  OR NOT canvas_connector.lti_claims_match(payload,definition,host,saved.nonce) THEN RETURN NULL; END IF;
 UPDATE canvas_connector.lti_launch_states SET phase='staged',token_hash=requested_token,protocol_claims=payload
  WHERE state_hash=requested_state;
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_states s WHERE s.state_hash=requested_state AND s.launch_id=saved.launch_id
   AND s.organization_id=saved.organization_id AND s.platform_id=saved.platform_id AND s.registration_id=saved.registration_id
   AND s.platform_version=saved.platform_version AND s.registration_version=saved.registration_version
   AND s.registration_snapshot=saved.registration_snapshot
   AND s.nonce=saved.nonce AND s.browser_hash=saved.browser_hash AND s.created_at=saved.created_at AND s.expires_at=saved.expires_at
   AND s.phase='staged' AND s.token_hash=requested_token AND s.protocol_claims=payload AND s.accepted_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(definition))
  OR saved.expires_at<=clock_timestamp() OR NOT canvas_connector.lti_claims_match(payload,definition,host,saved.nonce) THEN
  RAISE EXCEPTION 'LTI launch stage changed';
 END IF;
 RETURN (SELECT to_jsonb(s) FROM canvas_connector.lti_launch_states s WHERE s.state_hash=requested_state);
END;
$$;

CREATE FUNCTION canvas_connector.confirm_lti_launch(requested_state text, requested_browser text, requested_token text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE saved canvas_connector.lti_launch_states; definition canvas_connector.lti_registrations; host canvas_connector.platforms;
 expected_receipt jsonb; accepted timestamptz; audit canvas_connector.lti_launch_receipts;
BEGIN
 IF requested_state IS NULL OR requested_state !~ '^[a-f0-9]{64}$'
  OR requested_browser IS NULL OR requested_browser !~ '^[a-f0-9]{64}$'
  OR requested_token IS NULL OR requested_token !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=saved.organization_id AND id=saved.platform_id FOR UPDATE;
 SELECT * INTO definition FROM canvas_connector.lti_registrations WHERE id=saved.registration_id FOR UPDATE;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state FOR UPDATE;
 IF saved.browser_hash IS DISTINCT FROM requested_browser OR saved.token_hash IS DISTINCT FROM requested_token
   OR saved.phase='pending' THEN RETURN NULL; END IF;
 IF saved.phase='accepted' THEN
  SELECT * INTO audit FROM canvas_connector.lti_launch_receipts WHERE state_hash=requested_state;
  IF audit.launch_id=saved.launch_id AND audit.token_hash=requested_token THEN RETURN audit.receipt; END IF;
  RAISE EXCEPTION 'LTI launch receipt is unavailable';
 END IF;
 IF host.enabled IS DISTINCT FROM true OR host.archived IS DISTINCT FROM false OR definition.enabled IS DISTINCT FROM true
  OR host.config_version IS DISTINCT FROM saved.platform_version OR definition.version IS DISTINCT FROM saved.registration_version OR saved.expires_at<=clock_timestamp()
  OR NOT canvas_connector.lti_claims_match(saved.protocol_claims,definition,host,saved.nonce) THEN RETURN NULL; END IF;
 accepted:=clock_timestamp();
 expected_receipt:=jsonb_build_object('launchId',saved.launch_id,'registrationId',saved.registration_id,
  'organizationId',saved.organization_id,'platformId',saved.platform_id,'platformVersion',saved.platform_version,
  'registrationVersion',saved.registration_version,'acceptedAtMs',floor(extract(epoch FROM accepted)*1000)::bigint);
 UPDATE canvas_connector.lti_launch_states SET phase='accepted',accepted_at=accepted WHERE state_hash=requested_state;
 INSERT INTO canvas_connector.lti_launch_receipts(state_hash,launch_id,token_hash,receipt)
 VALUES(requested_state,saved.launch_id,requested_token,expected_receipt);
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_states s WHERE s.state_hash=requested_state AND s.launch_id=saved.launch_id
   AND s.browser_hash=requested_browser AND s.organization_id=saved.organization_id AND s.platform_id=saved.platform_id
   AND s.registration_id=saved.registration_id AND s.platform_version=saved.platform_version AND s.registration_version=saved.registration_version
   AND s.registration_snapshot=saved.registration_snapshot
   AND s.created_at=saved.created_at AND s.expires_at=saved.expires_at AND s.nonce=saved.nonce
   AND s.phase='accepted' AND s.accepted_at=accepted AND s.token_hash=requested_token AND s.protocol_claims=saved.protocol_claims)
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_receipts a WHERE a.state_hash=requested_state AND a.launch_id=saved.launch_id
   AND a.token_hash=requested_token AND a.receipt=expected_receipt AND a.created_at>=accepted AND a.created_at<=clock_timestamp())
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(definition))
  OR saved.expires_at<=clock_timestamp() OR NOT canvas_connector.lti_claims_match(saved.protocol_claims,definition,host,saved.nonce) THEN
  RAISE EXCEPTION 'LTI launch acceptance changed';
 END IF;
 RETURN expected_receipt;
END;
$$;
REVOKE ALL ON canvas_connector.lti_registrations,canvas_connector.lti_launch_states,canvas_connector.lti_launch_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.lti_visible_identifier(text),canvas_connector.lti_numeric_date(jsonb),
 canvas_connector.bump_lti_registration(),canvas_connector.guard_lti_launch_state(),canvas_connector.keep_lti_launch_receipt(),
 canvas_connector.lti_claims_match(jsonb,canvas_connector.lti_registrations,canvas_connector.platforms,text),
 canvas_connector.begin_lti_launch(uuid,bigint,bigint,text,text,text,uuid),canvas_connector.stage_lti_launch(text,text,jsonb),
 canvas_connector.confirm_lti_launch(text,text,text) FROM PUBLIC;
COMMIT;
