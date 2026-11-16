-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector schema owner only. No canonical authority or runtime grants.
BEGIN;
CREATE TABLE canvas_connector.platform_operation_audit (
  organization_id text NOT NULL,
  operation_id uuid NOT NULL,
  platform_id text NOT NULL,
  actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  action text NOT NULL CHECK(action IN ('create','change')),
  request jsonb NOT NULL,
  receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(organization_id,operation_id),
  FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);
CREATE FUNCTION canvas_connector.keep_platform_operation_audit()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'platform operation audit is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER platform_operation_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.platform_operation_audit
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_platform_operation_audit();

CREATE FUNCTION canvas_connector.administer_platform(org text, platform text, operation uuid, actor text,
  requested_action text, requested_origin text, expected bigint, requested_enabled boolean, requested_archived boolean)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE prior canvas_connector.platform_operation_audit;
  configuration canvas_connector.platforms;
  intent jsonb;
  result jsonb;
BEGIN
  IF org IS NULL OR org !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
    OR platform IS NULL OR platform !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
    OR operation IS NULL OR actor IS NULL OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
    OR requested_action IS NULL OR requested_action NOT IN ('create','change') THEN RETURN NULL; END IF;
  IF requested_action='create' THEN
    IF requested_origin IS NULL OR octet_length(requested_origin)>2048 OR requested_origin !~ '^https://[^/[:space:]]+$'
      OR expected IS NOT NULL OR requested_enabled IS DISTINCT FROM false OR requested_archived IS DISTINCT FROM false THEN RETURN NULL; END IF;
  ELSE
    IF requested_origin IS NOT NULL OR expected IS NULL OR expected NOT BETWEEN 1 AND 9007199254740991
      OR requested_enabled IS NULL OR requested_archived IS NULL OR (requested_enabled AND requested_archived) THEN RETURN NULL; END IF;
  END IF;
  intent:=jsonb_build_object('canvasOrigin',requested_origin,'expectedVersion',expected,
    'enabled',requested_enabled,'archived',requested_archived);
  -- Creation has no row to lock yet. A connector-scoped transaction advisory
  -- lock serializes the same tenant/platform; hash collisions only serialize.
  PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array('canvas-platform-admin',org,platform)::text,0));
  SELECT * INTO prior FROM canvas_connector.platform_operation_audit WHERE organization_id=org AND operation_id=operation;
  IF FOUND THEN
    IF prior.platform_id<>platform OR prior.actor_id<>actor OR prior.action<>requested_action
      OR prior.request<>intent THEN RETURN NULL; END IF;
    RETURN prior.receipt;
  END IF;
  IF requested_action='create' THEN
    INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled,archived)
      VALUES(org,platform,requested_origin,false,false) ON CONFLICT(organization_id,id) DO NOTHING
      RETURNING * INTO configuration;
    IF NOT FOUND THEN RETURN NULL; END IF;
  ELSE
    SELECT * INTO configuration FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
    IF NOT FOUND OR configuration.config_version<>expected OR configuration.archived
      OR (configuration.enabled=requested_enabled AND configuration.archived=requested_archived) THEN RETURN NULL; END IF;
    IF requested_enabled OR requested_archived THEN
      -- Disable is immediate and fences existing snapshots. Re-enable/archive
      -- requires explicit disconnect and disposition of old provider work.
      IF EXISTS(SELECT 1 FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform)
        OR EXISTS(SELECT 1 FROM canvas_connector.revocation_jobs WHERE organization_id=org AND platform_id=platform AND completed_at IS NULL)
        OR EXISTS(SELECT 1 FROM canvas_connector.refresh_attempts WHERE organization_id=org AND platform_id=platform
          AND (phase IN ('exchanging','reconciliation_required') OR (phase='claimed' AND lease_until>clock_timestamp())))
        OR EXISTS(SELECT 1 FROM canvas_connector.authorization_attempts WHERE organization_id=org AND platform_id=platform
          AND phase IN ('exchanging','staged','reconciliation_required')) THEN RETURN NULL; END IF;
    END IF;
    UPDATE canvas_connector.platforms SET enabled=requested_enabled,archived=requested_archived
      WHERE organization_id=org AND id=platform RETURNING * INTO configuration;
  END IF;
  result:=jsonb_build_object('operationId',operation,'actorId',actor,'action',requested_action,
    'platformId',platform,'canvasOrigin',configuration.canvas_origin,'configVersion',configuration.config_version,
    'enabled',configuration.enabled,'archived',configuration.archived);
  INSERT INTO canvas_connector.platform_operation_audit(organization_id,operation_id,platform_id,actor_id,action,request,receipt)
    VALUES(org,operation,platform,actor,requested_action,intent,result);
  RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.platform_operation_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.keep_platform_operation_audit(),
  canvas_connector.administer_platform(text,text,uuid,text,text,text,bigint,boolean,boolean) FROM PUBLIC;
COMMIT;
