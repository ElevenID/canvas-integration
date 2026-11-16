-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector provider identifiers only. No Marty user/application authority.
BEGIN;
CREATE FUNCTION canvas_connector.lti_canvas_user_id(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN value COLLATE "C" ~ '^[1-9][0-9]{0,19}$'
   THEN value::numeric<=18446744073709551615 ELSE false END;
$$;
CREATE OR REPLACE FUNCTION canvas_connector.lti_claims_match(payload jsonb, registration canvas_connector.lti_registrations,
 host canvas_connector.platforms, challenge text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE issued bigint; expires bigint; starts bigint; now_seconds bigint; expected_issuer text;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF payload ? 'canvasUserId' AND (jsonb_typeof(payload->'canvasUserId') IS DISTINCT FROM 'string'
   OR NOT canvas_connector.lti_canvas_user_id(payload->>'canvasUserId')) THEN RETURN false; END IF;
 IF ARRAY(SELECT key FROM jsonb_object_keys(payload-'canvasUserId') key ORDER BY key COLLATE "C") IS DISTINCT FROM
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
CREATE TABLE canvas_connector.lti_provider_identities (
 id uuid PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
 issuer text COLLATE "C" NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 client_id text COLLATE "C" NOT NULL CHECK(canvas_connector.lti_visible_identifier(client_id)),
 deployment_id text COLLATE "C" NOT NULL CHECK(canvas_connector.lti_visible_identifier(deployment_id)),
 subject text COLLATE "C" NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 1024),
 canvas_user_id text COLLATE "C" CHECK(canvas_user_id IS NULL OR canvas_connector.lti_canvas_user_id(canvas_user_id)),
 status text NOT NULL DEFAULT 'subject_observed' CHECK(status IN ('subject_observed','numeric_linked','quarantined')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
 UNIQUE(organization_id,platform_id,issuer,client_id,deployment_id,subject),
 CHECK(status<>'numeric_linked' OR canvas_user_id IS NOT NULL)
);
CREATE FUNCTION canvas_connector.guard_lti_provider_identity()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['canvas_user_id','status','revision','updated_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['canvas_user_id','status','revision','updated_at'])
   OR (OLD.canvas_user_id IS NOT NULL AND NEW.canvas_user_id IS DISTINCT FROM OLD.canvas_user_id)
   OR (OLD.status='quarantined' AND NEW.status<>'quarantined') THEN
  RAISE EXCEPTION 'LTI provider identity is immutable' USING ERRCODE='23514'; END IF;
 NEW.revision:=OLD.revision+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END;
$$;
CREATE TRIGGER lti_provider_identity_revision BEFORE UPDATE ON canvas_connector.lti_provider_identities
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.guard_lti_provider_identity();
CREATE TABLE canvas_connector.lti_provider_identity_claims (
 identity_id uuid NOT NULL REFERENCES canvas_connector.lti_provider_identities(id),
 canvas_user_id text COLLATE "C" NOT NULL CHECK(canvas_connector.lti_canvas_user_id(canvas_user_id)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(identity_id,canvas_user_id)
);
CREATE INDEX lti_provider_identity_numeric ON canvas_connector.lti_provider_identity_claims(canvas_user_id,identity_id);
CREATE TABLE canvas_connector.lti_provider_identity_observations (
 state_hash text PRIMARY KEY REFERENCES canvas_connector.lti_launch_states(state_hash),
 launch_id uuid NOT NULL UNIQUE REFERENCES canvas_connector.lti_launch_receipts(launch_id),
 identity_id uuid NOT NULL REFERENCES canvas_connector.lti_provider_identities(id),
 token_hash text NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 canvas_user_id text CHECK(canvas_user_id IS NULL OR canvas_connector.lti_canvas_user_id(canvas_user_id)),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION canvas_connector.keep_lti_provider_identity_history()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'LTI provider identity history is immutable' USING ERRCODE='23514';END;
$$;
CREATE TRIGGER lti_provider_identity_claim_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_provider_identity_claims
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_provider_identity_history();
CREATE TRIGGER lti_provider_identity_observation_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_provider_identity_observations
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_provider_identity_history();

CREATE FUNCTION canvas_connector.observe_lti_provider_identity(requested_state text, requested_browser text, new_identity uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE saved canvas_connector.lti_launch_states; definition canvas_connector.lti_registrations; host canvas_connector.platforms;
 prior canvas_connector.lti_provider_identity_observations; identity_row canvas_connector.lti_provider_identities;
 previous canvas_connector.lti_provider_identities; changed canvas_connector.lti_provider_identities;
 numeric_id text; conflict_ids uuid[]; target_id uuid; expected_rows jsonb:='[]'; observed_at timestamptz;
 expected_receipt jsonb; expected_status text; expected_numeric text; started timestamptz:=clock_timestamp();
BEGIN
 IF requested_state IS NULL OR requested_state !~ '^[a-f0-9]{64}$' OR requested_browser IS NULL
  OR requested_browser !~ '^[a-f0-9]{64}$' OR new_identity IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=saved.organization_id AND id=saved.platform_id FOR UPDATE;
 SELECT * INTO definition FROM canvas_connector.lti_registrations WHERE id=saved.registration_id FOR UPDATE;
 SELECT * INTO saved FROM canvas_connector.lti_launch_states WHERE state_hash=requested_state FOR UPDATE;
 IF saved.browser_hash IS DISTINCT FROM requested_browser OR saved.phase IS DISTINCT FROM 'accepted'
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_receipts a WHERE a.state_hash=saved.state_hash
      AND a.launch_id=saved.launch_id AND a.token_hash=saved.token_hash) THEN RETURN NULL; END IF;
 SELECT * INTO prior FROM canvas_connector.lti_provider_identity_observations WHERE state_hash=requested_state;
 IF FOUND THEN
  IF prior.launch_id=saved.launch_id AND prior.token_hash=saved.token_hash THEN RETURN prior.receipt; END IF;
  RAISE EXCEPTION 'LTI provider identity history unavailable'; END IF;
 IF host.enabled IS DISTINCT FROM true OR host.archived IS DISTINCT FROM false OR definition.enabled IS DISTINCT FROM true
   OR host.config_version IS DISTINCT FROM saved.platform_version OR definition.version IS DISTINCT FROM saved.registration_version
   OR saved.expires_at<=clock_timestamp() OR NOT canvas_connector.lti_claims_match(saved.protocol_claims,definition,host,saved.nonce) THEN RETURN NULL; END IF;
 numeric_id:=saved.protocol_claims->>'canvasUserId';
 IF numeric_id IS NOT NULL AND NOT canvas_connector.lti_canvas_user_id(numeric_id) THEN RETURN NULL; END IF;
 SELECT * INTO identity_row FROM canvas_connector.lti_provider_identities i WHERE i.organization_id=saved.organization_id
  AND i.platform_id=saved.platform_id AND i.issuer=saved.protocol_claims->>'issuer' AND i.client_id=saved.protocol_claims->>'clientId'
  AND i.deployment_id=saved.protocol_claims->>'deploymentId' AND i.subject=saved.protocol_claims->>'subject' FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO canvas_connector.lti_provider_identities(id,organization_id,platform_id,issuer,client_id,deployment_id,subject)
  VALUES(new_identity,saved.organization_id,saved.platform_id,saved.protocol_claims->>'issuer',saved.protocol_claims->>'clientId',
    saved.protocol_claims->>'deploymentId',saved.protocol_claims->>'subject') RETURNING * INTO identity_row;
  IF (to_jsonb(identity_row)-ARRAY['created_at','updated_at']) IS DISTINCT FROM jsonb_build_object('id',new_identity,
    'organization_id',saved.organization_id,'platform_id',saved.platform_id,'issuer',saved.protocol_claims->>'issuer',
    'client_id',saved.protocol_claims->>'clientId','deployment_id',saved.protocol_claims->>'deploymentId',
    'subject',saved.protocol_claims->>'subject','canvas_user_id',NULL,'status','subject_observed','revision',1)
   OR identity_row.created_at<started OR identity_row.updated_at<started
   OR identity_row.created_at>clock_timestamp() OR identity_row.updated_at>clock_timestamp() THEN
   RAISE EXCEPTION 'LTI provider identity insert changed'; END IF;
 END IF;
 conflict_ids:=ARRAY[]::uuid[];
 IF numeric_id IS NOT NULL THEN
  SELECT coalesce(array_agg(i.id ORDER BY i.id),ARRAY[]::uuid[]) INTO conflict_ids
   FROM canvas_connector.lti_provider_identities i JOIN canvas_connector.lti_provider_identity_claims c ON c.identity_id=i.id
   WHERE i.organization_id=saved.organization_id AND i.platform_id=saved.platform_id AND i.issuer=identity_row.issuer
    AND i.client_id=identity_row.client_id AND i.deployment_id=identity_row.deployment_id AND i.id<>identity_row.id AND c.canvas_user_id=numeric_id;
  INSERT INTO canvas_connector.lti_provider_identity_claims(identity_id,canvas_user_id) VALUES(identity_row.id,numeric_id)
    ON CONFLICT(identity_id,canvas_user_id) DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM canvas_connector.lti_provider_identity_claims WHERE identity_id=identity_row.id AND canvas_user_id=numeric_id) THEN
   RAISE EXCEPTION 'LTI provider identity claim changed'; END IF;
 END IF;
 expected_status:=CASE WHEN identity_row.status='quarantined' OR cardinality(conflict_ids)>0
   OR (numeric_id IS NOT NULL AND identity_row.canvas_user_id IS NOT NULL AND identity_row.canvas_user_id<>numeric_id) THEN 'quarantined'
   WHEN numeric_id IS NOT NULL OR identity_row.canvas_user_id IS NOT NULL THEN 'numeric_linked' ELSE 'subject_observed' END;
 FOREACH target_id IN ARRAY array_append(conflict_ids,identity_row.id) LOOP
  SELECT * INTO previous FROM canvas_connector.lti_provider_identities WHERE id=target_id FOR UPDATE;
  expected_numeric:=CASE WHEN target_id=identity_row.id THEN coalesce(previous.canvas_user_id,numeric_id) ELSE previous.canvas_user_id END;
  IF previous.status IS DISTINCT FROM (CASE WHEN target_id=identity_row.id THEN expected_status ELSE 'quarantined' END)
    OR previous.canvas_user_id IS DISTINCT FROM expected_numeric THEN
   UPDATE canvas_connector.lti_provider_identities SET status=CASE WHEN target_id=identity_row.id THEN expected_status ELSE 'quarantined' END,
    canvas_user_id=expected_numeric WHERE id=target_id RETURNING * INTO changed;
   IF (to_jsonb(changed)-ARRAY['canvas_user_id','status','revision','updated_at']) IS DISTINCT FROM
      (to_jsonb(previous)-ARRAY['canvas_user_id','status','revision','updated_at'])
    OR changed.status IS DISTINCT FROM (CASE WHEN target_id=identity_row.id THEN expected_status ELSE 'quarantined' END)
    OR changed.canvas_user_id IS DISTINCT FROM expected_numeric OR changed.revision IS DISTINCT FROM previous.revision+1
    OR changed.updated_at<started OR changed.updated_at>clock_timestamp() THEN RAISE EXCEPTION 'LTI provider identity postimage changed'; END IF;
  ELSE changed:=previous; END IF;
  expected_rows:=expected_rows||jsonb_build_array(to_jsonb(changed));
  IF target_id=identity_row.id THEN identity_row:=changed; END IF;
 END LOOP;
 observed_at:=clock_timestamp();
 expected_receipt:=jsonb_build_object('launchId',saved.launch_id,'registrationId',saved.registration_id,'identityId',identity_row.id,
   'status',identity_row.status,'identityRevision',identity_row.revision,'numericIdSupplied',numeric_id IS NOT NULL,
   'recordedAtMs',floor(extract(epoch FROM observed_at)*1000)::bigint);
 INSERT INTO canvas_connector.lti_provider_identity_observations(state_hash,launch_id,identity_id,token_hash,canvas_user_id,receipt)
  VALUES(saved.state_hash,saved.launch_id,identity_row.id,saved.token_hash,numeric_id,expected_receipt);
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(expected_rows) desired WHERE NOT EXISTS(
     SELECT 1 FROM canvas_connector.lti_provider_identities i WHERE to_jsonb(i)=desired))
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_provider_identity_observations a WHERE a.state_hash=saved.state_hash
     AND a.launch_id=saved.launch_id AND a.identity_id=identity_row.id AND a.token_hash=saved.token_hash
     AND a.canvas_user_id IS NOT DISTINCT FROM numeric_id AND a.receipt=expected_receipt AND a.created_at>=observed_at AND a.created_at<=clock_timestamp())
   OR (numeric_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_provider_identity_claims c
     WHERE c.identity_id=identity_row.id AND c.canvas_user_id=numeric_id))
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(definition))
   OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_launch_states s WHERE to_jsonb(s)=to_jsonb(saved))
   OR saved.expires_at<=clock_timestamp() OR NOT canvas_connector.lti_claims_match(saved.protocol_claims,definition,host,saved.nonce) THEN
  RAISE EXCEPTION 'LTI provider identity observation changed'; END IF;
 RETURN expected_receipt;
END;
$$;
REVOKE ALL ON canvas_connector.lti_provider_identities,canvas_connector.lti_provider_identity_claims,
 canvas_connector.lti_provider_identity_observations FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.lti_canvas_user_id(text),canvas_connector.guard_lti_provider_identity(),
 canvas_connector.keep_lti_provider_identity_history(),canvas_connector.observe_lti_provider_identity(text,text,uuid) FROM PUBLIC;
COMMIT;
