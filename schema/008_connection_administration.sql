-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-installed connector state only. No runtime grants or provider calls.
BEGIN;
ALTER TABLE canvas_connector.connections
  ADD COLUMN connection_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;
CREATE FUNCTION canvas_connector.keep_connection_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.connection_id IS DISTINCT FROM OLD.connection_id THEN
    RAISE EXCEPTION 'connection identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER connection_identity BEFORE UPDATE ON canvas_connector.connections
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_connection_identity();

-- A disconnected platform cannot authorize a new provider grant while old
-- cleanup or an uncertain refresh could still affect that grant. Existing
-- exchange admission holds the platform lock before this transition.
CREATE FUNCTION canvas_connector.fence_authorization_cleanup()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.phase='exchanging' AND OLD.phase='consumed' AND (
    EXISTS(SELECT 1 FROM canvas_connector.revocation_jobs
      WHERE organization_id=NEW.organization_id AND platform_id=NEW.platform_id AND completed_at IS NULL)
    OR EXISTS(SELECT 1 FROM canvas_connector.refresh_attempts
      WHERE organization_id=NEW.organization_id AND platform_id=NEW.platform_id
        AND (phase IN ('exchanging','reconciliation_required')
          OR (phase='claimed' AND lease_until>clock_timestamp())))) THEN
    RAISE EXCEPTION 'previous connection cleanup is unresolved' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER authorization_cleanup BEFORE UPDATE ON canvas_connector.authorization_attempts
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.fence_authorization_cleanup();

CREATE TABLE canvas_connector.connection_operation_audit (
  organization_id text NOT NULL,
  operation_id uuid NOT NULL,
  platform_id text NOT NULL,
  connection_id uuid NOT NULL,
  expected_revision bigint NOT NULL CHECK(expected_revision BETWEEN 1 AND 9007199254740991),
  actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(organization_id,operation_id),
  FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);
CREATE FUNCTION canvas_connector.keep_connection_operation_audit()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'connection operation audit is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER connection_operation_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.connection_operation_audit
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_connection_operation_audit();

CREATE FUNCTION canvas_connector.disconnect_connection(org text, platform text, connection uuid,
  expected bigint, operation uuid, actor text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE previous canvas_connector.connections;
  prior canvas_connector.connection_operation_audit;
  cleanup uuid;
  result jsonb;
BEGIN
  IF org IS NULL OR platform IS NULL OR connection IS NULL OR expected IS NULL
    OR expected NOT BETWEEN 1 AND 9007199254740991 OR operation IS NULL OR actor IS NULL
    OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' THEN RETURN NULL; END IF;
  PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO prior FROM canvas_connector.connection_operation_audit
    WHERE organization_id=org AND operation_id=operation;
  IF FOUND THEN
    IF prior.platform_id<>platform OR prior.connection_id<>connection
      OR prior.expected_revision<>expected OR prior.actor_id<>actor THEN RETURN NULL; END IF;
    RETURN prior.receipt;
  END IF;
  SELECT * INTO previous FROM canvas_connector.connections
    WHERE organization_id=org AND platform_id=platform FOR UPDATE;
  IF NOT FOUND OR previous.connection_id<>connection OR previous.revision<>expected THEN RETURN NULL; END IF;
  -- Retain the original references and any already confirmed cleanup outcome.
  INSERT INTO canvas_connector.revocation_jobs
    (organization_id,platform_id,canvas_origin,access_token_ref,refresh_token_ref)
    VALUES(org,platform,previous.canvas_origin,previous.access_token_ref,previous.refresh_token_ref)
    ON CONFLICT(organization_id,platform_id,access_token_ref) DO NOTHING;
  SELECT id INTO cleanup FROM canvas_connector.revocation_jobs WHERE organization_id=org
    AND platform_id=platform AND access_token_ref=previous.access_token_ref
    AND canvas_origin=previous.canvas_origin AND refresh_token_ref IS NOT DISTINCT FROM previous.refresh_token_ref;
  IF NOT FOUND THEN RAISE EXCEPTION 'connection cleanup mismatch' USING ERRCODE='23514'; END IF;
  DELETE FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform;
  UPDATE canvas_connector.oauth_status SET status='reauthorization_required',authorization_hash=NULL
    WHERE organization_id=org AND platform_id=platform;
  result:=jsonb_build_object('operationId',operation,'connectionId',connection,'actorId',actor,
    'expectedRevision',expected,'status','disconnected','revocationJobId',cleanup);
  INSERT INTO canvas_connector.connection_operation_audit
    (organization_id,operation_id,platform_id,connection_id,expected_revision,actor_id,receipt)
    VALUES(org,operation,platform,connection,expected,actor,result);
  RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.connection_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_connection_identity(),
  canvas_connector.fence_authorization_cleanup(),canvas_connector.keep_connection_operation_audit(),
  canvas_connector.disconnect_connection(text,text,uuid,bigint,uuid,text) FROM PUBLIC;
COMMIT;
