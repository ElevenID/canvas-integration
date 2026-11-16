-- SPDX-License-Identifier: AGPL-3.0-only
-- Install only in the connector-owned database. No core authority or secrets.
BEGIN;
CREATE SCHEMA canvas_connector;

CREATE TABLE canvas_connector.platforms (
    organization_id text NOT NULL CHECK (organization_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    id text NOT NULL CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    canvas_origin text NOT NULL CHECK (canvas_origin ~ '^https://[^/[:space:]]+$'),
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version BETWEEN 1 AND 9007199254740991),
    enabled boolean NOT NULL DEFAULT false,
    archived boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, id)
);

CREATE FUNCTION canvas_connector.bump_platform_configuration()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'platform identity is immutable' USING ERRCODE = '23514';
    END IF;
    NEW.config_version := OLD.config_version + 1;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;
CREATE TRIGGER platform_configuration_revision BEFORE UPDATE ON canvas_connector.platforms
    FOR EACH ROW EXECUTE FUNCTION canvas_connector.bump_platform_configuration();

-- Encryption keys live outside PostgreSQL. These rows contain only authenticated
-- ciphertext plus tenant/platform/provider/purpose metadata and a key version.
CREATE TABLE canvas_connector.secrets (
    organization_id text NOT NULL,
    reference text NOT NULL CHECK (reference ~ '^[a-f0-9-]{36}$'),
    platform_id text NOT NULL,
    provider text NOT NULL CHECK (provider = 'canvas'),
    purpose text NOT NULL CHECK (purpose IN ('oauth_client_secret','oauth_access_token','oauth_refresh_token')),
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 16384),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    tag bytea NOT NULL CHECK (octet_length(tag) = 16),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, reference),
    FOREIGN KEY (organization_id, platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);

CREATE TABLE canvas_connector.authorizations (
    state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),
    browser_binding_hash text NOT NULL CHECK (browser_binding_hash ~ '^[a-f0-9]{64}$'),
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    platform_config_version bigint NOT NULL CHECK (platform_config_version BETWEEN 1 AND 9007199254740991),
    canvas_origin text NOT NULL,
    client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 512),
    client_secret_ref text NOT NULL CHECK (octet_length(client_secret_ref) BETWEEN 1 AND 256),
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) BETWEEN 1 AND 32),
    scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 64),
    redirect_uri text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    FOREIGN KEY (organization_id, platform_id) REFERENCES canvas_connector.platforms(organization_id, id)
        ON DELETE RESTRICT
);
CREATE INDEX authorizations_expiry ON canvas_connector.authorizations(expires_at);

CREATE TABLE canvas_connector.oauth_status (
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'connected', 'reauthorization_required')),
    authorization_hash text CHECK (authorization_hash ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (organization_id, platform_id),
    FOREIGN KEY (organization_id, platform_id) REFERENCES canvas_connector.platforms(organization_id,id)
);

CREATE FUNCTION canvas_connector.mark_authorization_pending(org text, platform text, version bigint, hash text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM canvas_connector.platforms
     WHERE organization_id=org AND id=platform AND config_version=version AND enabled AND NOT archived
     FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.authorizations
     WHERE state_hash=hash AND organization_id=org AND platform_id=platform
       AND platform_config_version=version AND expires_at > clock_timestamp();
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO canvas_connector.oauth_status VALUES (org,platform,'pending',hash)
    ON CONFLICT (organization_id,platform_id)
    DO UPDATE SET status='pending', authorization_hash=EXCLUDED.authorization_hash;
    RETURN true;
END;
$$;

-- DELETE RETURNING consumes the state atomically across concurrent callbacks.
-- Expiry comes from the database clock, not an untrusted callback parameter.
CREATE FUNCTION canvas_connector.consume_authorization(requested_hash text, requested_browser_hash text)
RETURNS SETOF canvas_connector.authorizations LANGUAGE sql AS $$
    DELETE FROM canvas_connector.authorizations
     WHERE state_hash = requested_hash AND browser_binding_hash=requested_browser_hash AND expires_at > clock_timestamp()
    RETURNING *;
$$;

CREATE TABLE canvas_connector.connections (
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    platform_config_version bigint NOT NULL CHECK (platform_config_version BETWEEN 1 AND 9007199254740991),
    canvas_origin text NOT NULL,
    client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 512),
    client_secret_ref text NOT NULL CHECK (octet_length(client_secret_ref) BETWEEN 1 AND 256),
    access_token_ref text NOT NULL CHECK (octet_length(access_token_ref) BETWEEN 1 AND 256),
    refresh_token_ref text CHECK (octet_length(refresh_token_ref) BETWEEN 1 AND 256),
    token_expires_at timestamptz,
    capabilities text[] NOT NULL,
    scopes text[] NOT NULL,
    status text NOT NULL CHECK (status IN ('connected', 'reauthorization_required', 'revocation_pending')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, platform_id),
    CHECK (client_secret_ref <> access_token_ref),
    CHECK (refresh_token_ref IS NULL OR (refresh_token_ref <> client_secret_ref AND refresh_token_ref <> access_token_ref)),
    FOREIGN KEY (organization_id, platform_id) REFERENCES canvas_connector.platforms(organization_id, id)
        ON DELETE RESTRICT
);

-- Lock the configuration row before publishing or rotating a connection.
-- Changes to configuration and publication therefore have a definite order.
CREATE FUNCTION canvas_connector.check_connection_configuration()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE platform canvas_connector.platforms;
BEGIN
    SELECT * INTO platform FROM canvas_connector.platforms
     WHERE organization_id = NEW.organization_id AND id = NEW.platform_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'platform unavailable' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'connected' AND (NOT platform.enabled OR platform.archived
       OR platform.config_version <> NEW.platform_config_version
       OR platform.canvas_origin <> NEW.canvas_origin) THEN
        RAISE EXCEPTION 'platform configuration changed' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.platform_id IS DISTINCT FROM OLD.platform_id THEN
            RAISE EXCEPTION 'connection identity is immutable' USING ERRCODE = '23514';
        END IF;
        NEW.revision := OLD.revision + 1;
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER connection_configuration BEFORE INSERT OR UPDATE ON canvas_connector.connections
    FOR EACH ROW EXECUTE FUNCTION canvas_connector.check_connection_configuration();

-- Jobs survive connection deletion. Only opaque vault references are retained.
CREATE TABLE canvas_connector.revocation_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    canvas_origin text NOT NULL,
    access_token_ref text NOT NULL CHECK (octet_length(access_token_ref) BETWEEN 1 AND 256),
    refresh_token_ref text CHECK (octet_length(refresh_token_ref) BETWEEN 1 AND 256),
    provider_revoked_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_until timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    UNIQUE (organization_id, platform_id, access_token_ref)
);
CREATE INDEX revocation_jobs_ready ON canvas_connector.revocation_jobs(available_at)
    WHERE completed_at IS NULL;

-- Disconnect and enqueue are one atomic statement/transaction. Queue insertion
-- failures roll back deletion, preserving the only durable token reference.
CREATE FUNCTION canvas_connector.disconnect(requested_org text, requested_platform text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE connection canvas_connector.connections;
BEGIN
    PERFORM 1 FROM canvas_connector.platforms
     WHERE organization_id = requested_org AND id = requested_platform FOR UPDATE;
    DELETE FROM canvas_connector.connections
     WHERE organization_id = requested_org AND platform_id = requested_platform
     RETURNING * INTO connection;
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO canvas_connector.revocation_jobs
        (organization_id, platform_id, canvas_origin, access_token_ref, refresh_token_ref)
    VALUES (connection.organization_id, connection.platform_id,
            connection.canvas_origin, connection.access_token_ref, connection.refresh_token_ref)
    ON CONFLICT (organization_id, platform_id, access_token_ref) DO NOTHING;
    UPDATE canvas_connector.oauth_status SET status='reauthorization_required',authorization_hash=NULL
     WHERE organization_id=requested_org AND platform_id=requested_platform;
    RETURN true;
END;
$$;

CREATE FUNCTION canvas_connector.claim_revocation()
RETURNS SETOF canvas_connector.revocation_jobs LANGUAGE sql AS $$
    WITH candidate AS (
        SELECT id FROM canvas_connector.revocation_jobs
         WHERE completed_at IS NULL AND available_at <= clock_timestamp()
           AND (lease_until IS NULL OR lease_until <= clock_timestamp())
         ORDER BY available_at, id FOR UPDATE SKIP LOCKED LIMIT 1
    )
    UPDATE canvas_connector.revocation_jobs job
       SET lease_id = gen_random_uuid(), lease_until = clock_timestamp() + interval '1 minute',
           attempts = attempts + 1
      FROM candidate WHERE job.id = candidate.id RETURNING job.*;
$$;

-- An expired worker cannot acknowledge a job reclaimed by another worker.
CREATE FUNCTION canvas_connector.record_provider_revocation(requested_id uuid, expected_lease uuid)
RETURNS boolean LANGUAGE sql AS $$
    WITH recorded AS (
        UPDATE canvas_connector.revocation_jobs
           SET provider_revoked_at = coalesce(provider_revoked_at,clock_timestamp())
         WHERE id=requested_id AND lease_id=expected_lease
           AND lease_until > clock_timestamp() AND completed_at IS NULL RETURNING id
    ) SELECT EXISTS(SELECT 1 FROM recorded);
$$;

CREATE FUNCTION canvas_connector.finish_revocation(requested_id uuid, expected_lease uuid)
RETURNS boolean LANGUAGE sql AS $$
    WITH finished AS (
        UPDATE canvas_connector.revocation_jobs
           SET completed_at = clock_timestamp(), lease_id = NULL, lease_until = NULL
         WHERE id = requested_id AND lease_id = expected_lease
           AND lease_until > clock_timestamp() AND completed_at IS NULL
           AND provider_revoked_at IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM canvas_connector.secrets secret
                WHERE secret.organization_id=revocation_jobs.organization_id
                  AND secret.reference IN (revocation_jobs.access_token_ref,revocation_jobs.refresh_token_ref))
        RETURNING id
    ) SELECT EXISTS(SELECT 1 FROM finished);
$$;

CREATE FUNCTION canvas_connector.retry_revocation(requested_id uuid, expected_lease uuid)
RETURNS boolean LANGUAGE sql AS $$
    WITH retried AS (
        UPDATE canvas_connector.revocation_jobs
           SET available_at = clock_timestamp() + interval '1 second' *
                   least(3600, power(2::numeric, least(attempts, 12)))::double precision,
               lease_id = NULL, lease_until = NULL
         WHERE id = requested_id AND lease_id = expected_lease
           AND lease_until > clock_timestamp() AND completed_at IS NULL
        RETURNING id
    ) SELECT EXISTS(SELECT 1 FROM retried);
$$;

-- Refresh attempts retain only references. An expired in-flight exchange is
-- never reclaimed automatically: its external outcome must be reconciled.
CREATE TABLE canvas_connector.refresh_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    lease_id uuid NOT NULL DEFAULT gen_random_uuid(),
    lease_until timestamptz NOT NULL DEFAULT clock_timestamp()+interval '1 minute',
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    connection_revision bigint NOT NULL,
    config_version bigint NOT NULL,
    canvas_origin text NOT NULL,
    client_id text NOT NULL,
    client_secret_ref text NOT NULL,
    access_token_ref text NOT NULL,
    refresh_token_ref text NOT NULL,
    phase text NOT NULL DEFAULT 'claimed' CHECK (phase IN ('claimed','exchanging','published','abandoned','reconciliation_required')),
    new_access_token_ref text,
    new_refresh_token_ref text,
    new_token_expires_at timestamptz,
    CHECK ((new_access_token_ref IS NULL AND new_refresh_token_ref IS NULL AND new_token_expires_at IS NULL) OR (new_access_token_ref IS NOT NULL AND new_refresh_token_ref IS NOT NULL AND new_token_expires_at IS NOT NULL)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX refresh_active_platform ON canvas_connector.refresh_attempts(organization_id,platform_id)
    WHERE phase IN ('claimed','exchanging','reconciliation_required');

CREATE FUNCTION canvas_connector.claim_refresh(org text, platform text)
RETURNS SETOF canvas_connector.refresh_attempts LANGUAGE plpgsql AS $$
DECLARE configuration canvas_connector.platforms; connection canvas_connector.connections;
BEGIN
    SELECT * INTO configuration FROM canvas_connector.platforms
     WHERE organization_id=org AND id=platform FOR UPDATE;
    IF NOT FOUND OR NOT configuration.enabled OR configuration.archived THEN RETURN; END IF;
    SELECT * INTO connection FROM canvas_connector.connections
     WHERE organization_id=org AND platform_id=platform FOR UPDATE;
    IF NOT FOUND OR connection.status <> 'connected' OR connection.refresh_token_ref IS NULL
       OR connection.platform_config_version <> configuration.config_version
       OR connection.token_expires_at IS NULL
       OR connection.token_expires_at > clock_timestamp()+interval '5 minutes' THEN RETURN; END IF;
    UPDATE canvas_connector.refresh_attempts SET phase='abandoned'
     WHERE organization_id=org AND platform_id=platform AND phase='claimed' AND lease_until <= clock_timestamp();
    IF EXISTS(SELECT 1 FROM canvas_connector.refresh_attempts WHERE organization_id=org AND platform_id=platform
              AND phase IN ('claimed','exchanging','reconciliation_required')) THEN RETURN; END IF;
    RETURN QUERY INSERT INTO canvas_connector.refresh_attempts
      (organization_id,platform_id,connection_revision,config_version,canvas_origin,client_id,
       client_secret_ref,access_token_ref,refresh_token_ref)
      VALUES (org,platform,connection.revision,configuration.config_version,connection.canvas_origin,
        connection.client_id,connection.client_secret_ref,connection.access_token_ref,connection.refresh_token_ref)
      RETURNING *;
END;
$$;

CREATE FUNCTION canvas_connector.begin_refresh_exchange(job uuid, lease uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.refresh_attempts; configuration canvas_connector.platforms;
        connection canvas_connector.connections;
BEGIN
    SELECT * INTO attempt FROM canvas_connector.refresh_attempts WHERE id=job;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO configuration FROM canvas_connector.platforms
      WHERE organization_id=attempt.organization_id AND id=attempt.platform_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO connection FROM canvas_connector.connections
      WHERE organization_id=attempt.organization_id AND platform_id=attempt.platform_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO attempt FROM canvas_connector.refresh_attempts WHERE id=job FOR UPDATE;
    IF lease IS NULL OR attempt.lease_id <> lease OR attempt.phase <> 'claimed' OR attempt.lease_until <= clock_timestamp()
       OR NOT configuration.enabled OR configuration.archived OR configuration.config_version <> attempt.config_version
       OR connection.revision <> attempt.connection_revision OR connection.status <> 'connected' THEN RETURN false; END IF;
    UPDATE canvas_connector.refresh_attempts SET phase='exchanging' WHERE id=job;
    RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.require_refresh_reconciliation(job uuid, lease uuid)
RETURNS boolean LANGUAGE sql AS $$
    WITH changed AS (UPDATE canvas_connector.refresh_attempts SET phase='reconciliation_required'
      WHERE id=job AND lease_id=lease AND phase='exchanging' RETURNING id)
    SELECT EXISTS(SELECT 1 FROM changed);
$$;
CREATE FUNCTION canvas_connector.abandon_unstarted_refresh(job uuid, lease uuid)
RETURNS boolean LANGUAGE sql AS $$
    WITH changed AS (UPDATE canvas_connector.refresh_attempts SET phase='abandoned'
      WHERE id=job AND lease_id=lease AND phase='claimed' RETURNING id)
    SELECT EXISTS(SELECT 1 FROM changed);
$$;

-- Custody is independent of publication eligibility. Preserve a completed
-- external exchange even after disconnect/config change/lease expiry.
CREATE FUNCTION canvas_connector.stage_refresh_result(job uuid, lease uuid, org text, platform text,
  access_ref text, access_key text, access_cipher bytea, access_nonce bytea, access_tag bytea,
  refresh_ref text, refresh_key text, refresh_cipher bytea, refresh_nonce bytea, refresh_tag bytea,
  expiry timestamptz)
RETURNS SETOF canvas_connector.refresh_attempts LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.refresh_attempts;
BEGIN
    -- Platform-before-attempt order matches publication; FK inserts must never
    -- wait for a platform row while holding an attempt needed by its owner.
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR KEY SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO attempt FROM canvas_connector.refresh_attempts WHERE id=job FOR UPDATE;
    IF NOT FOUND OR lease IS NULL OR attempt.lease_id<>lease OR attempt.organization_id<>org OR attempt.platform_id<>platform
       OR attempt.phase NOT IN ('exchanging','reconciliation_required') OR expiry IS NULL OR NOT isfinite(expiry)
       OR access_ref IS NULL OR access_ref=attempt.access_token_ref THEN RETURN; END IF;
    IF attempt.new_access_token_ref IS NOT NULL THEN
        IF attempt.new_access_token_ref<>access_ref
           OR attempt.new_refresh_token_ref<>coalesce(refresh_ref,attempt.refresh_token_ref)
           OR attempt.new_token_expires_at<>expiry THEN RETURN; END IF;
        PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND reference=access_ref
          AND platform_id=platform AND provider='canvas' AND purpose='oauth_access_token'
          AND key_id=access_key AND ciphertext=access_cipher AND nonce=access_nonce AND tag=access_tag;
        IF NOT FOUND THEN RETURN; END IF;
        IF refresh_ref IS NOT NULL THEN
            PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND reference=refresh_ref
              AND platform_id=platform AND provider='canvas' AND purpose='oauth_refresh_token'
              AND key_id=refresh_key AND ciphertext=refresh_cipher AND nonce=refresh_nonce AND tag=refresh_tag;
            IF NOT FOUND THEN RETURN; END IF;
        END IF;
        RETURN QUERY SELECT * FROM canvas_connector.refresh_attempts WHERE id=job;
        RETURN;
    END IF;
    INSERT INTO canvas_connector.secrets(organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
      VALUES(org,access_ref,platform,'canvas','oauth_access_token',access_key,access_cipher,access_nonce,access_tag);
    IF refresh_ref IS NOT NULL THEN
        INSERT INTO canvas_connector.secrets(organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
          VALUES(org,refresh_ref,platform,'canvas','oauth_refresh_token',refresh_key,refresh_cipher,refresh_nonce,refresh_tag);
    ELSIF refresh_key IS NOT NULL OR refresh_cipher IS NOT NULL OR refresh_nonce IS NOT NULL OR refresh_tag IS NOT NULL THEN
        RAISE EXCEPTION 'invalid staged refresh result' USING ERRCODE='23514';
    END IF;
    RETURN QUERY UPDATE canvas_connector.refresh_attempts SET new_access_token_ref=access_ref,
      new_refresh_token_ref=coalesce(refresh_ref,attempt.refresh_token_ref),new_token_expires_at=expiry WHERE id=job RETURNING *;
END;
$$;

CREATE FUNCTION canvas_connector.publish_refresh(job uuid, lease uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.refresh_attempts; configuration canvas_connector.platforms;
        connection canvas_connector.connections;
BEGIN
    SELECT * INTO attempt FROM canvas_connector.refresh_attempts WHERE id=job;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO configuration FROM canvas_connector.platforms
      WHERE organization_id=attempt.organization_id AND id=attempt.platform_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO connection FROM canvas_connector.connections
      WHERE organization_id=attempt.organization_id AND platform_id=attempt.platform_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO attempt FROM canvas_connector.refresh_attempts WHERE id=job FOR UPDATE;
    IF lease IS NULL OR attempt.lease_id <> lease OR attempt.phase <> 'exchanging' OR attempt.lease_until <= clock_timestamp()
       OR NOT configuration.enabled OR configuration.archived OR configuration.config_version <> attempt.config_version
       OR connection.revision <> attempt.connection_revision OR connection.status <> 'connected'
       OR attempt.new_token_expires_at IS NULL OR attempt.new_token_expires_at<=clock_timestamp()
       OR attempt.new_access_token_ref IS NULL OR attempt.new_refresh_token_ref IS NULL THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=attempt.organization_id AND platform_id=attempt.platform_id
      AND reference=attempt.new_access_token_ref AND provider='canvas' AND purpose='oauth_access_token' AND enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=attempt.organization_id AND platform_id=attempt.platform_id
      AND reference=attempt.new_refresh_token_ref AND provider='canvas' AND purpose='oauth_refresh_token' AND enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE canvas_connector.connections SET access_token_ref=attempt.new_access_token_ref,refresh_token_ref=attempt.new_refresh_token_ref,token_expires_at=attempt.new_token_expires_at
      WHERE organization_id=attempt.organization_id AND platform_id=attempt.platform_id;
    UPDATE canvas_connector.refresh_attempts SET phase='published'
      WHERE id=job;
    RETURN true;
END;
$$;

REVOKE ALL ON SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA canvas_connector FROM PUBLIC;
COMMIT;
