-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector database only; apply with the schema owner, never at HTTP startup.
BEGIN;
CREATE TABLE canvas_connector.authorization_attempts (
    authorization_hash text PRIMARY KEY CHECK (authorization_hash ~ '^[a-f0-9]{64}$'),
    organization_id text NOT NULL,
    platform_id text NOT NULL,
    platform_config_version bigint NOT NULL,
    canvas_origin text NOT NULL,
    client_id text NOT NULL,
    client_secret_ref text NOT NULL,
    capabilities text[] NOT NULL,
    scopes text[] NOT NULL,
    redirect_uri text NOT NULL,
    authorization_expires_at timestamptz NOT NULL,
    phase text NOT NULL DEFAULT 'consumed' CHECK (phase IN
        ('consumed','exchanging','staged','published','reconciliation_required','abandoned')),
    access_token_ref text,
    refresh_token_ref text,
    token_expires_at timestamptz CHECK (token_expires_at IS NULL OR isfinite(token_expires_at)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    exchange_started_at timestamptz,
    staged_at timestamptz,
    published_at timestamptz,
    FOREIGN KEY (organization_id,platform_id) REFERENCES canvas_connector.platforms(organization_id,id),
    CHECK (access_token_ref IS NULL OR access_token_ref <> client_secret_ref),
    CHECK (refresh_token_ref IS NULL OR
        (refresh_token_ref <> client_secret_ref AND refresh_token_ref <> access_token_ref)),
    CHECK ((staged_at IS NULL) = (access_token_ref IS NULL)),
    CHECK (phase NOT IN ('staged','published') OR access_token_ref IS NOT NULL)
);
-- An unresolved external exchange cannot be silently superseded by another.
CREATE UNIQUE INDEX authorization_active_exchange ON canvas_connector.authorization_attempts(organization_id,platform_id)
    WHERE phase IN ('exchanging','staged','reconciliation_required');

-- Separate from the legacy consumer until the callback is migrated. State
-- consumption and the durable snapshot commit in one statement, with no code,
-- browser proof, client secret, token or provider response in the attempt.
CREATE FUNCTION canvas_connector.consume_authorization_attempt(hash text, browser_hash text)
RETURNS SETOF canvas_connector.authorizations LANGUAGE plpgsql AS $$
DECLARE saved canvas_connector.authorizations;
BEGIN
    DELETE FROM canvas_connector.authorizations
      WHERE state_hash=hash AND browser_binding_hash=browser_hash AND expires_at>clock_timestamp()
      RETURNING * INTO saved;
    IF NOT FOUND THEN RETURN; END IF;
    INSERT INTO canvas_connector.authorization_attempts
      (authorization_hash,organization_id,platform_id,platform_config_version,canvas_origin,
       client_id,client_secret_ref,capabilities,scopes,redirect_uri,authorization_expires_at)
      VALUES(saved.state_hash,saved.organization_id,saved.platform_id,
       saved.platform_config_version,saved.canvas_origin,saved.client_id,
       saved.client_secret_ref,saved.capabilities,saved.scopes,
       saved.redirect_uri,saved.expires_at);
    RETURN NEXT saved;
END;
$$;

CREATE FUNCTION canvas_connector.begin_authorization_exchange(hash text, org text, platform text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.authorization_attempts;
BEGIN
    PERFORM 1 FROM canvas_connector.platforms
      WHERE organization_id=org AND id=platform AND enabled AND NOT archived FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO attempt FROM canvas_connector.authorization_attempts
      WHERE authorization_hash=hash AND organization_id=org AND platform_id=platform FOR UPDATE;
    IF NOT FOUND OR attempt.phase<>'consumed' OR attempt.authorization_expires_at<=clock_timestamp() THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform
      AND config_version=attempt.platform_config_version AND canvas_origin=attempt.canvas_origin;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.oauth_status WHERE organization_id=org AND platform_id=platform
      AND status='pending' AND authorization_hash=hash FOR UPDATE;
    IF NOT FOUND OR EXISTS(SELECT 1 FROM canvas_connector.connections WHERE organization_id=org AND platform_id=platform)
      OR EXISTS(SELECT 1 FROM canvas_connector.authorization_attempts WHERE organization_id=org AND platform_id=platform
        AND phase IN ('exchanging','staged','reconciliation_required')) THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND platform_id=platform
      AND reference=attempt.client_secret_ref AND provider='canvas' AND purpose='oauth_client_secret' AND enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE canvas_connector.authorization_attempts SET phase='exchanging',exchange_started_at=clock_timestamp()
      WHERE authorization_hash=hash;
    -- Locks and triggers may have waited after the first deadline check.
    -- Raising rolls back this transition; returning false would commit it.
    IF attempt.authorization_expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'authorization expired during exchange admission' USING ERRCODE='23514';
    END IF;
    RETURN true;
END;
$$;

-- Custody survives expiry, reconfiguration and unknown provider/DB outcomes.
-- No retry of the provider exchange is authorized by this transition.
CREATE FUNCTION canvas_connector.require_authorization_reconciliation(hash text, org text, platform text)
RETURNS boolean LANGUAGE sql AS $$
    WITH changed AS (UPDATE canvas_connector.authorization_attempts SET phase='reconciliation_required'
      WHERE authorization_hash=hash AND organization_id=org AND platform_id=platform
        AND phase IN ('exchanging','staged','reconciliation_required') RETURNING authorization_hash)
    SELECT EXISTS(SELECT 1 FROM changed);
$$;

CREATE FUNCTION canvas_connector.stage_authorization_result(hash text, org text, platform text,
    access_ref text, access_key text, access_cipher bytea, access_nonce bytea, access_tag bytea,
    refresh_ref text, refresh_key text, refresh_cipher bytea, refresh_nonce bytea, refresh_tag bytea,
    expiry timestamptz)
RETURNS SETOF canvas_connector.authorization_attempts LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.authorization_attempts;
BEGIN
    -- Platform before attempt; matches publication and FK lock order.
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform FOR KEY SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO attempt FROM canvas_connector.authorization_attempts WHERE authorization_hash=hash FOR UPDATE;
    IF NOT FOUND OR attempt.organization_id<>org OR attempt.platform_id<>platform
      OR attempt.phase NOT IN ('exchanging','staged','reconciliation_required')
      OR access_ref IS NULL OR access_ref=attempt.client_secret_ref
      OR (expiry IS NOT NULL AND NOT isfinite(expiry)) THEN RETURN; END IF;
    IF refresh_ref IS NULL AND (refresh_key IS NOT NULL OR refresh_cipher IS NOT NULL
      OR refresh_nonce IS NOT NULL OR refresh_tag IS NOT NULL) THEN RETURN; END IF;
    IF attempt.access_token_ref IS NOT NULL THEN
        IF attempt.access_token_ref<>access_ref OR attempt.refresh_token_ref IS DISTINCT FROM refresh_ref
          OR attempt.token_expires_at IS DISTINCT FROM expiry THEN RETURN; END IF;
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
        RETURN NEXT attempt;
        RETURN;
    END IF;
    INSERT INTO canvas_connector.secrets(organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
      VALUES(org,access_ref,platform,'canvas','oauth_access_token',access_key,access_cipher,access_nonce,access_tag);
    IF refresh_ref IS NOT NULL THEN
        INSERT INTO canvas_connector.secrets(organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
          VALUES(org,refresh_ref,platform,'canvas','oauth_refresh_token',refresh_key,refresh_cipher,refresh_nonce,refresh_tag);
    END IF;
    RETURN QUERY UPDATE canvas_connector.authorization_attempts SET access_token_ref=access_ref,
      refresh_token_ref=refresh_ref,token_expires_at=expiry,staged_at=clock_timestamp(),
      phase=CASE WHEN phase='exchanging' THEN 'staged' ELSE phase END
      WHERE authorization_hash=hash RETURNING *;
END;
$$;

-- Normal publication only. Reconciliation-required attempts need an explicit
-- operator disposition; this is never an automatic recovery/retry mechanism.
CREATE FUNCTION canvas_connector.publish_authorization_connection(hash text, org text, platform text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE attempt canvas_connector.authorization_attempts;
BEGIN
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform
      AND enabled AND NOT archived FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO attempt FROM canvas_connector.authorization_attempts
      WHERE authorization_hash=hash AND organization_id=org AND platform_id=platform FOR UPDATE;
    IF NOT FOUND OR attempt.phase<>'staged' OR
      (attempt.token_expires_at IS NOT NULL AND attempt.token_expires_at<=clock_timestamp()) THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.platforms WHERE organization_id=org AND id=platform
      AND config_version=attempt.platform_config_version AND canvas_origin=attempt.canvas_origin;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.oauth_status WHERE organization_id=org AND platform_id=platform
      AND status='pending' AND authorization_hash=hash FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND platform_id=platform
      AND reference=attempt.client_secret_ref AND provider='canvas' AND purpose='oauth_client_secret' AND enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND platform_id=platform
      AND reference=attempt.access_token_ref AND provider='canvas' AND purpose='oauth_access_token' AND enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF attempt.refresh_token_ref IS NOT NULL THEN
        PERFORM 1 FROM canvas_connector.secrets WHERE organization_id=org AND platform_id=platform
          AND reference=attempt.refresh_token_ref AND provider='canvas' AND purpose='oauth_refresh_token' AND enabled FOR SHARE;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    INSERT INTO canvas_connector.connections
      (organization_id,platform_id,platform_config_version,canvas_origin,client_id,client_secret_ref,
       access_token_ref,refresh_token_ref,token_expires_at,capabilities,scopes,status)
      VALUES(org,platform,attempt.platform_config_version,attempt.canvas_origin,attempt.client_id,
       attempt.client_secret_ref,attempt.access_token_ref,attempt.refresh_token_ref,
       attempt.token_expires_at,attempt.capabilities,attempt.scopes,'connected')
      ON CONFLICT(organization_id,platform_id) DO NOTHING;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE canvas_connector.authorization_attempts SET phase='published',published_at=clock_timestamp()
      WHERE authorization_hash=hash;
    IF attempt.token_expires_at IS NOT NULL AND attempt.token_expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'token expired during publication' USING ERRCODE='23514';
    END IF;
    RETURN true;
END;
$$;

REVOKE ALL ON canvas_connector.authorization_attempts FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.consume_authorization_attempt(text,text),
    canvas_connector.begin_authorization_exchange(text,text,text),
    canvas_connector.require_authorization_reconciliation(text,text,text),
    canvas_connector.stage_authorization_result(text,text,text,text,text,bytea,bytea,bytea,text,text,bytea,bytea,bytea,timestamptz),
    canvas_connector.publish_authorization_connection(text,text,text) FROM PUBLIC;
COMMIT;
