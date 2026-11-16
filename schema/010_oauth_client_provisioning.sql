-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No grants, plaintext or provider calls.
BEGIN;
CREATE TABLE canvas_connector.oauth_client_configurations (
  organization_id text NOT NULL,
  platform_id text NOT NULL,
  client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 2048),
  client_secret_ref text NOT NULL,
  platform_config_version bigint NOT NULL CHECK(platform_config_version BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY(organization_id,platform_id),
  FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
  FOREIGN KEY(organization_id,client_secret_ref) REFERENCES canvas_connector.secrets(organization_id,reference)
);
CREATE TABLE canvas_connector.oauth_client_provisioning_audit (
  organization_id text NOT NULL,
  operation_id uuid NOT NULL,
  platform_id text NOT NULL,
  actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  client_id text NOT NULL,
  expected_version bigint NOT NULL CHECK(expected_version BETWEEN 1 AND 9007199254740991),
  key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
  receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(organization_id,operation_id),
  FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);
CREATE FUNCTION canvas_connector.keep_oauth_client_provisioning_audit()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'client provisioning audit is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER oauth_client_provisioning_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.oauth_client_provisioning_audit
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_oauth_client_provisioning_audit();

CREATE FUNCTION canvas_connector.provision_oauth_client(org text, platform text, operation uuid, actor text,
  expected bigint, requested_client text, requested_reference text, requested_key text,
  digest bytea, encrypted bytea, iv bytea, authentication_tag bytea)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE configuration canvas_connector.platforms;
  prior canvas_connector.oauth_client_provisioning_audit;
  result jsonb;
BEGIN
  IF org IS NULL OR platform IS NULL OR operation IS NULL OR actor IS NULL
    OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR expected IS NULL
    OR expected NOT BETWEEN 1 AND 9007199254740991 OR requested_client IS NULL
    OR octet_length(requested_client) NOT BETWEEN 1 AND 2048 OR requested_reference IS NULL
    OR requested_reference !~ '^[a-f0-9-]{36}$' OR requested_key IS NULL
    OR requested_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR digest IS NULL OR octet_length(digest)<>32
    OR encrypted IS NULL OR octet_length(encrypted) NOT BETWEEN 1 AND 16384
    OR iv IS NULL OR octet_length(iv)<>12 OR authentication_tag IS NULL OR octet_length(authentication_tag)<>16 THEN RETURN NULL; END IF;
  SELECT * INTO configuration FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO prior FROM canvas_connector.oauth_client_provisioning_audit WHERE organization_id=org AND operation_id=operation;
  IF FOUND THEN
    IF prior.platform_id<>platform OR prior.actor_id<>actor OR prior.client_id<>requested_client
      OR prior.expected_version<>expected OR prior.key_id<>requested_key OR prior.input_digest<>digest THEN RETURN NULL; END IF;
    RETURN prior.receipt;
  END IF;
  IF NOT configuration.enabled OR configuration.archived OR configuration.config_version<>expected
    OR EXISTS(SELECT 1 FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform)
    OR EXISTS(SELECT 1 FROM canvas_connector.revocation_jobs WHERE organization_id=org AND platform_id=platform AND completed_at IS NULL)
    OR EXISTS(SELECT 1 FROM canvas_connector.refresh_attempts WHERE organization_id=org AND platform_id=platform
      AND (phase IN ('exchanging','reconciliation_required') OR (phase='claimed' AND lease_until>clock_timestamp())))
    OR EXISTS(SELECT 1 FROM canvas_connector.authorization_attempts WHERE organization_id=org AND platform_id=platform
      AND phase IN ('exchanging','staged','reconciliation_required')) THEN RETURN NULL; END IF;
  INSERT INTO canvas_connector.secrets(organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
    VALUES(org,requested_reference,platform,'canvas','oauth_client_secret',requested_key,encrypted,iv,authentication_tag);
  -- Credential changes advance the same version fence as other platform config.
  UPDATE canvas_connector.platforms SET enabled=enabled WHERE organization_id=org AND id=platform RETURNING * INTO configuration;
  INSERT INTO canvas_connector.oauth_client_configurations(organization_id,platform_id,client_id,client_secret_ref,platform_config_version)
    VALUES(org,platform,requested_client,requested_reference,configuration.config_version)
    ON CONFLICT(organization_id,platform_id) DO UPDATE SET client_id=EXCLUDED.client_id,
      client_secret_ref=EXCLUDED.client_secret_ref,platform_config_version=EXCLUDED.platform_config_version;
  result:=jsonb_build_object('operationId',operation,'actorId',actor,'platformId',platform,'clientId',requested_client,
    'clientSecretRef',requested_reference,'configVersion',configuration.config_version);
  INSERT INTO canvas_connector.oauth_client_provisioning_audit(organization_id,operation_id,platform_id,actor_id,
    client_id,expected_version,key_id,input_digest,receipt) VALUES(org,operation,platform,actor,requested_client,expected,requested_key,digest,result);
  RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.oauth_client_configurations,canvas_connector.oauth_client_provisioning_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_oauth_client_provisioning_audit(),
  canvas_connector.provision_oauth_client(text,text,uuid,text,bigint,text,text,text,bytea,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;
