-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector-owned immutable intent and encrypted proof code. No canonical identity mirror.
BEGIN;
CREATE TABLE canvas_connector.lti_association_attempts (
 challenge_id uuid PRIMARY KEY, operation_id uuid NOT NULL UNIQUE,
 launch_id uuid NOT NULL REFERENCES canvas_connector.lti_launch_states(launch_id),
 identity_id uuid NOT NULL REFERENCES canvas_connector.lti_provider_identities(id),
 source_id text COLLATE "C" NOT NULL CHECK(source_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 source_grant_id uuid NOT NULL, binding_id text COLLATE "C" NOT NULL CHECK(binding_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 source_revision bigint NOT NULL CHECK(source_revision BETWEEN 1 AND 9007199254740991),
 binding_revision bigint NOT NULL CHECK(binding_revision BETWEEN 1 AND 9007199254740991),
 provider_revision bigint NOT NULL CHECK(provider_revision BETWEEN 1 AND 9007199254740991),
 provider_reference text COLLATE "C" NOT NULL CHECK(provider_reference ~ '^[a-f0-9]{64}$'),
 code_hash text COLLATE "C" NOT NULL UNIQUE CHECK(code_hash ~ '^[a-f0-9]{64}$'),
 expires_at_ms bigint NOT NULL CHECK(expires_at_ms BETWEEN 1 AND 9007199254740991),
 wrapping_key_id text NOT NULL CHECK(wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)=32),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12), tag bytea NOT NULL CHECK(octet_length(tag)=16),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(launch_id,source_id,binding_id),
 CHECK(expires_at_ms>floor(extract(epoch FROM created_at)*1000)
   AND expires_at_ms<=floor(extract(epoch FROM created_at)*1000)+300000)
);
CREATE FUNCTION canvas_connector.keep_lti_association_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'association intent is immutable' USING ERRCODE='23514'; END;
$$;
CREATE TRIGGER lti_association_attempt_immutable BEFORE UPDATE OR DELETE
 ON canvas_connector.lti_association_attempts FOR EACH ROW
 EXECUTE FUNCTION canvas_connector.keep_lti_association_attempt();
REVOKE ALL ON canvas_connector.lti_association_attempts FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_lti_association_attempt() FROM PUBLIC;
-- Commit this marker before any network write. A crashed or uncertain dispatch
-- is reconciled by original receipt lookup, never an automatic second write.
CREATE TABLE canvas_connector.lti_association_dispatches (
 challenge_id uuid PRIMARY KEY REFERENCES canvas_connector.lti_association_attempts(challenge_id),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER lti_association_dispatch_immutable BEFORE UPDATE OR DELETE
 ON canvas_connector.lti_association_dispatches FOR EACH ROW
 EXECUTE FUNCTION canvas_connector.keep_lti_association_attempt();
REVOKE ALL ON canvas_connector.lti_association_dispatches FROM PUBLIC;
COMMIT;
