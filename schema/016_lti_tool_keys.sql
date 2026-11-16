-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No Core access, automatic grants or runtime DDL.
BEGIN;
CREATE TABLE canvas_connector.lti_tool_keys (
 organization_id text NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 kid uuid NOT NULL UNIQUE,
 platform_version bigint NOT NULL CHECK(platform_version BETWEEN 1 AND 9007199254740991),
 registration_version bigint NOT NULL CHECK(registration_version BETWEEN 1 AND 9007199254740991),
 client_id text NOT NULL CHECK(canvas_connector.lti_visible_identifier(client_id)),
 tool_origin text NOT NULL CHECK(tool_origin ~ '^https://[^/[:space:]?#@]+$'),
 public_jwk jsonb NOT NULL CHECK(jsonb_typeof(public_jwk)='object'),
 wrapping_key_id text NOT NULL CHECK(wrapping_key_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 8192),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 tag bytea NOT NULL CHECK(octet_length(tag)=16),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,platform_id,registration_id,kid),
 FOREIGN KEY(organization_id,platform_id,registration_id)
  REFERENCES canvas_connector.lti_registrations(organization_id,platform_id,id)
);
CREATE TABLE canvas_connector.lti_tool_key_configurations (
 organization_id text NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991),
 current_kid uuid,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,platform_id,registration_id),
 FOREIGN KEY(organization_id,platform_id,registration_id)
  REFERENCES canvas_connector.lti_registrations(organization_id,platform_id,id),
 FOREIGN KEY(organization_id,platform_id,registration_id,current_kid)
  REFERENCES canvas_connector.lti_tool_keys(organization_id,platform_id,registration_id,kid)
);
CREATE TABLE canvas_connector.lti_tool_key_operation_audit (
 organization_id text NOT NULL,
 operation_id uuid NOT NULL,
 platform_id text NOT NULL,
 registration_id uuid NOT NULL,
 actor_id text NOT NULL,
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,operation_id),
 FOREIGN KEY(organization_id,platform_id,registration_id)
  REFERENCES canvas_connector.lti_registrations(organization_id,platform_id,id)
);
CREATE FUNCTION canvas_connector.keep_lti_tool_key_history()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'LTI tool key history is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER lti_tool_key_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_tool_keys
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_tool_key_history();
CREATE TRIGGER lti_tool_key_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.lti_tool_key_operation_audit
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_lti_tool_key_history();
CREATE FUNCTION canvas_connector.bump_lti_tool_key_configuration()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.organization_id,NEW.platform_id,NEW.registration_id) IS DISTINCT FROM
  ROW(OLD.organization_id,OLD.platform_id,OLD.registration_id) THEN
  RAISE EXCEPTION 'LTI tool key configuration identity is immutable' USING ERRCODE='23514';
 END IF;
 NEW.version:=OLD.version+1;NEW.updated_at:=clock_timestamp();RETURN NEW;
END;
$$;
CREATE TRIGGER lti_tool_key_revision BEFORE UPDATE ON canvas_connector.lti_tool_key_configurations
 FOR EACH ROW EXECUTE FUNCTION canvas_connector.bump_lti_tool_key_configuration();

CREATE FUNCTION canvas_connector.administer_lti_tool_key(org text,platform text,registration uuid,operation uuid,actor text,
 requested_action text,expected_platform bigint,expected_registration bigint,expected_key bigint,
 requested_kid uuid,jwk jsonb,wrapping_key text,encrypted bytea,iv bytea,authentication_tag bytea)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE host canvas_connector.platforms; reg canvas_connector.lti_registrations;
 saved canvas_connector.lti_tool_key_configurations; material canvas_connector.lti_tool_keys;
 prior canvas_connector.lti_tool_key_operation_audit; intent jsonb; result jsonb;
 intended_version bigint; origin text; started timestamptz:=clock_timestamp();
BEGIN
 IF org IS NULL OR org COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR platform IS NULL OR platform COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR actor IS NULL OR actor COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR registration IS NULL OR operation IS NULL OR requested_action IS NULL
  OR requested_action NOT IN ('provision','rotate','deactivate') THEN RETURN NULL; END IF;
 IF requested_action='deactivate' THEN
  IF expected_platform IS NOT NULL OR expected_registration IS NOT NULL THEN RETURN NULL; END IF;
 ELSIF expected_platform IS NULL OR expected_platform NOT BETWEEN 1 AND 9007199254740991
  OR expected_registration IS NULL OR expected_registration NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 IF requested_action='provision' THEN
  IF expected_key IS NOT NULL THEN RETURN NULL; END IF;
 ELSIF expected_key IS NULL OR expected_key NOT BETWEEN 1 AND 9007199254740990 THEN RETURN NULL; END IF;
 intent:=jsonb_build_object('action',requested_action,'expectedPlatformVersion',expected_platform,
  'expectedRegistrationVersion',expected_registration,'expectedKeyVersion',expected_key);
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-lti-tool-key',org,operation)::text,0));
 SELECT * INTO prior FROM canvas_connector.lti_tool_key_operation_audit WHERE organization_id=org AND operation_id=operation;
 IF FOUND THEN
  IF prior.platform_id IS DISTINCT FROM platform OR prior.registration_id IS DISTINCT FROM registration
   OR prior.actor_id IS DISTINCT FROM actor OR prior.request IS DISTINCT FROM intent THEN RETURN NULL; END IF;
  RETURN prior.receipt;
 END IF;
 IF requested_action='deactivate' THEN
  IF requested_kid IS NOT NULL OR jwk IS NOT NULL OR wrapping_key IS NOT NULL OR encrypted IS NOT NULL
   OR iv IS NOT NULL OR authentication_tag IS NOT NULL THEN RETURN NULL; END IF;
 ELSE
  IF requested_kid IS NULL OR jsonb_typeof(jwk) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
  IF ARRAY(SELECT key FROM jsonb_object_keys(jwk) key ORDER BY key COLLATE "C") IS DISTINCT FROM
   ARRAY['alg','e','kid','kty','n','use'] OR EXISTS(SELECT 1 FROM jsonb_each(jwk) WHERE jsonb_typeof(value)<>'string') THEN RETURN NULL; END IF;
  IF jwk->>'alg'<>'RS256' OR jwk->>'kty'<>'RSA' OR jwk->>'use'<>'sig' OR jwk->>'e'<>'AQAB'
   OR jwk->>'kid'<>requested_kid::text OR octet_length(jwk->>'n') NOT BETWEEN 342 AND 683
   OR NOT COALESCE(jwk->>'n' COLLATE "C" ~ '^[A-Za-z0-9_-]+$',false)
   OR wrapping_key IS NULL OR wrapping_key COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
   OR encrypted IS NULL OR octet_length(encrypted) NOT BETWEEN 1 AND 8192
   OR iv IS NULL OR octet_length(iv)<>12 OR authentication_tag IS NULL OR octet_length(authentication_tag)<>16 THEN RETURN NULL; END IF;
 END IF;
 SELECT * INTO host FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO reg FROM canvas_connector.lti_registrations WHERE organization_id=org AND platform_id=platform AND id=registration FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF requested_action<>'deactivate' AND (NOT host.enabled OR host.archived OR host.config_version IS DISTINCT FROM expected_platform
  OR reg.version IS DISTINCT FROM expected_registration) THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM canvas_connector.lti_tool_key_configurations
  WHERE organization_id=org AND platform_id=platform AND registration_id=registration FOR UPDATE;
 IF requested_action='provision' THEN
  IF FOUND THEN RETURN NULL; END IF;
  intended_version:=1;
 ELSE
  IF NOT FOUND OR saved.version IS DISTINCT FROM expected_key THEN RETURN NULL; END IF;
  intended_version:=expected_key+1;
 END IF;
 IF requested_action<>'deactivate' THEN
  origin:=substring(reg.target_link_uri FROM '^(https://[^/[:space:]?#@]+)/lti/registrations/');
  IF origin IS NULL THEN RETURN NULL; END IF;
  INSERT INTO canvas_connector.lti_tool_keys(organization_id,platform_id,registration_id,kid,platform_version,
   registration_version,client_id,tool_origin,public_jwk,wrapping_key_id,ciphertext,nonce,tag)
  VALUES(org,platform,registration,requested_kid,host.config_version,reg.version,reg.client_id,origin,jwk,wrapping_key,encrypted,iv,authentication_tag)
   RETURNING * INTO material;
  IF ROW(material.organization_id,material.platform_id,material.registration_id,material.kid,material.platform_version,
    material.registration_version,material.client_id,material.tool_origin,material.public_jwk,material.wrapping_key_id,
    material.ciphertext,material.nonce,material.tag) IS DISTINCT FROM
   ROW(org,platform,registration,requested_kid,host.config_version,reg.version,reg.client_id,origin,jwk,wrapping_key,encrypted,iv,authentication_tag)
   OR material.created_at<started OR material.created_at>clock_timestamp() THEN RAISE EXCEPTION 'LTI key intent changed'; END IF;
 END IF;
 IF requested_action='provision' THEN
  INSERT INTO canvas_connector.lti_tool_key_configurations(organization_id,platform_id,registration_id,current_kid)
   VALUES(org,platform,registration,requested_kid) RETURNING * INTO saved;
 ELSE
  UPDATE canvas_connector.lti_tool_key_configurations SET current_kid=requested_kid
   WHERE organization_id=org AND platform_id=platform AND registration_id=registration RETURNING * INTO saved;
 END IF;
 IF ROW(saved.organization_id,saved.platform_id,saved.registration_id) IS DISTINCT FROM ROW(org,platform,registration)
  OR saved.version IS DISTINCT FROM intended_version OR saved.current_kid IS DISTINCT FROM requested_kid
  OR saved.updated_at<started OR saved.updated_at>clock_timestamp() THEN RAISE EXCEPTION 'LTI key configuration intent changed'; END IF;
 result:=jsonb_build_object('operationId',operation,'actorId',actor,'action',requested_action,'platformId',platform,
  'registrationId',registration,'version',intended_version,'kid',requested_kid,'publicJwk',jwk);
 INSERT INTO canvas_connector.lti_tool_key_operation_audit(organization_id,operation_id,platform_id,registration_id,actor_id,request,receipt)
  VALUES(org,operation,platform,registration,actor,intent,result);
 IF NOT EXISTS(SELECT 1 FROM canvas_connector.platforms p WHERE to_jsonb(p)=to_jsonb(host))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_registrations r WHERE to_jsonb(r)=to_jsonb(reg))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_configurations c WHERE to_jsonb(c)=to_jsonb(saved))
  OR (requested_action<>'deactivate' AND NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_keys k WHERE to_jsonb(k)=to_jsonb(material)))
  OR NOT EXISTS(SELECT 1 FROM canvas_connector.lti_tool_key_operation_audit a WHERE a.organization_id=org AND a.operation_id=operation
   AND a.platform_id=platform AND a.registration_id=registration AND a.actor_id=actor AND a.request=intent AND a.receipt=result
   AND a.created_at>=started AND a.created_at<=clock_timestamp()) THEN RAISE EXCEPTION 'LTI key operation changed'; END IF;
 RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.lti_tool_keys,canvas_connector.lti_tool_key_configurations,canvas_connector.lti_tool_key_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_lti_tool_key_history(),canvas_connector.bump_lti_tool_key_configuration(),
 canvas_connector.administer_lti_tool_key(text,text,uuid,uuid,text,text,bigint,bigint,bigint,uuid,jsonb,text,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;
