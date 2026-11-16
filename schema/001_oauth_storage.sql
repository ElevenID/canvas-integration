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

CREATE TABLE canvas_connector.authorizations (
    state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),
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

-- DELETE RETURNING consumes the state atomically across concurrent callbacks.
-- Expiry comes from the database clock, not an untrusted callback parameter.
CREATE FUNCTION canvas_connector.consume_authorization(requested_hash text)
RETURNS SETOF canvas_connector.authorizations LANGUAGE sql AS $$
    DELETE FROM canvas_connector.authorizations
     WHERE state_hash = requested_hash AND expires_at > clock_timestamp()
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

REVOKE ALL ON SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA canvas_connector FROM PUBLIC;
COMMIT;
