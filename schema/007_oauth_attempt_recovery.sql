-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-installed connector-only recovery. No grants or automatic disposition.
BEGIN;
ALTER TABLE canvas_connector.authorization_attempts
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
  ADD COLUMN recovery_job_id uuid REFERENCES canvas_connector.revocation_jobs(id);

CREATE FUNCTION canvas_connector.bump_authorization_attempt_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.authorization_hash,NEW.organization_id,NEW.platform_id) IS DISTINCT FROM
       (OLD.authorization_hash,OLD.organization_id,OLD.platform_id) THEN
        RAISE EXCEPTION 'attempt identity is immutable' USING ERRCODE='23514';
    END IF;
    NEW.revision:=OLD.revision+1;
    RETURN NEW;
END;
$$;
CREATE TRIGGER authorization_attempt_revision BEFORE UPDATE ON canvas_connector.authorization_attempts
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.bump_authorization_attempt_revision();

-- Stop a callback that was waiting to publish when an operator queued cleanup.
-- FOR UPDATE held by publication/recovery provides a definite order.
CREATE FUNCTION canvas_connector.fence_authorization_recovery_publication()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.phase='published' AND NEW.recovery_job_id IS NOT NULL THEN
        RAISE EXCEPTION 'attempt recovery is pending' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER authorization_recovery_publication BEFORE UPDATE ON canvas_connector.authorization_attempts
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.fence_authorization_recovery_publication();

CREATE TABLE canvas_connector.authorization_recovery_audit (
    organization_id text NOT NULL,
    operation_id uuid NOT NULL,
    platform_id text NOT NULL,
    authorization_hash text NOT NULL,
    actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    action text NOT NULL CHECK(action IN ('abandon_unstarted','queue_staged_revocation','finish_staged_revocation')),
    expected_revision bigint NOT NULL CHECK(expected_revision BETWEEN 1 AND 9007199254740991),
    receipt jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(organization_id,operation_id),
    FOREIGN KEY(authorization_hash) REFERENCES canvas_connector.authorization_attempts(authorization_hash),
    FOREIGN KEY(organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);
CREATE INDEX authorization_recovery_history ON canvas_connector.authorization_recovery_audit
  (organization_id,platform_id,authorization_hash,created_at DESC,operation_id DESC);
CREATE FUNCTION canvas_connector.keep_authorization_recovery_audit()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recovery audit is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER authorization_recovery_audit_immutable BEFORE UPDATE OR DELETE ON canvas_connector.authorization_recovery_audit
  FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_authorization_recovery_audit();

CREATE FUNCTION canvas_connector.recover_authorization_attempt(org text, platform text, hash text,
    expected bigint, operation uuid, actor text, requested_action text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.authorization_attempts;
    prior canvas_connector.authorization_recovery_audit;
    cleanup canvas_connector.revocation_jobs;
    result jsonb;
BEGIN
    IF org IS NULL OR platform IS NULL OR hash IS NULL OR operation IS NULL OR expected IS NULL
      OR expected NOT BETWEEN 1 AND 9007199254740991 OR actor IS NULL
      OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR requested_action IS NULL
      OR requested_action NOT IN ('abandon_unstarted','queue_staged_revocation','finish_staged_revocation') THEN
        RETURN NULL;
    END IF;
    -- Recovery remains available after platform disablement/configuration drift.
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO attempt FROM canvas_connector.authorization_attempts
      WHERE authorization_hash=hash AND organization_id=org AND platform_id=platform FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO prior FROM canvas_connector.authorization_recovery_audit
      WHERE organization_id=org AND operation_id=operation;
    IF FOUND THEN
        IF prior.platform_id<>platform OR prior.authorization_hash<>hash OR prior.actor_id<>actor
          OR prior.action<>requested_action OR prior.expected_revision<>expected THEN RETURN NULL; END IF;
        RETURN prior.receipt;
    END IF;
    IF attempt.revision<>expected THEN RETURN NULL; END IF;
    -- Never revoke credentials referenced by a current connection. In
    -- particular, a lost successful publication reply is not a cleanup grant.
    IF EXISTS(SELECT 1 FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform) THEN RETURN NULL; END IF;
    IF requested_action='abandon_unstarted' THEN
        IF attempt.phase<>'consumed' OR attempt.exchange_started_at IS NOT NULL
          OR attempt.access_token_ref IS NOT NULL OR attempt.recovery_job_id IS NOT NULL THEN RETURN NULL; END IF;
        UPDATE canvas_connector.authorization_attempts SET phase='abandoned' WHERE authorization_hash=hash;
    ELSIF requested_action='queue_staged_revocation' THEN
        IF attempt.phase NOT IN ('staged','reconciliation_required') OR attempt.access_token_ref IS NULL
          OR attempt.recovery_job_id IS NOT NULL THEN RETURN NULL; END IF;
        -- Existing ciphertext remains attempt-attributable until the scoped
        -- worker confirms Canvas revocation, deletes secrets and finishes.
        INSERT INTO canvas_connector.revocation_jobs(organization_id,platform_id,canvas_origin,access_token_ref,refresh_token_ref)
          VALUES(org,platform,attempt.canvas_origin,attempt.access_token_ref,attempt.refresh_token_ref)
          ON CONFLICT(organization_id,platform_id,access_token_ref) DO NOTHING;
        SELECT * INTO cleanup FROM canvas_connector.revocation_jobs
          WHERE organization_id=org AND platform_id=platform AND access_token_ref=attempt.access_token_ref;
        IF NOT FOUND OR cleanup.canvas_origin<>attempt.canvas_origin
          OR cleanup.refresh_token_ref IS DISTINCT FROM attempt.refresh_token_ref THEN
            RAISE EXCEPTION 'recovery job conflict' USING ERRCODE='23514';
        END IF;
        UPDATE canvas_connector.authorization_attempts SET phase='reconciliation_required',recovery_job_id=cleanup.id
          WHERE authorization_hash=hash;
    ELSE
        IF attempt.phase<>'reconciliation_required' OR attempt.recovery_job_id IS NULL THEN RETURN NULL; END IF;
        SELECT * INTO cleanup FROM canvas_connector.revocation_jobs WHERE id=attempt.recovery_job_id
          AND organization_id=org AND platform_id=platform;
        IF NOT FOUND OR cleanup.access_token_ref IS DISTINCT FROM attempt.access_token_ref
          OR cleanup.refresh_token_ref IS DISTINCT FROM attempt.refresh_token_ref
          OR cleanup.canvas_origin<>attempt.canvas_origin
          OR cleanup.provider_revoked_at IS NULL OR cleanup.completed_at IS NULL THEN RETURN NULL; END IF;
        IF EXISTS(SELECT 1 FROM canvas_connector.secrets WHERE organization_id=org
          AND reference IN (attempt.access_token_ref,attempt.refresh_token_ref)) THEN RETURN NULL; END IF;
        UPDATE canvas_connector.authorization_attempts SET phase='abandoned' WHERE authorization_hash=hash;
    END IF;
    SELECT * INTO attempt FROM canvas_connector.authorization_attempts WHERE authorization_hash=hash;
    result:=jsonb_build_object('operationId',operation,'authorizationId',hash,'actorId',actor,'action',requested_action,
      'phase',attempt.phase,'revision',attempt.revision,'revocationJobId',attempt.recovery_job_id);
    INSERT INTO canvas_connector.authorization_recovery_audit
      (organization_id,operation_id,platform_id,authorization_hash,actor_id,action,expected_revision,receipt)
      VALUES(org,operation,platform,hash,actor,requested_action,expected,result);
    RETURN result;
END;
$$;
REVOKE ALL ON canvas_connector.authorization_recovery_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.bump_authorization_attempt_revision(),
  canvas_connector.fence_authorization_recovery_publication(),canvas_connector.keep_authorization_recovery_audit(),
  canvas_connector.recover_authorization_attempt(text,text,text,bigint,uuid,text,text) FROM PUBLIC;
COMMIT;
