-- SPDX-License-Identifier: AGPL-3.0-only
-- Install once with the connector schema owner. Runtime performs no DDL.
BEGIN;
-- One shared budget per connector database, independent of request headers,
-- tenant claims or attacker-selected IP keys. Policy is owner-managed.
CREATE TABLE canvas_connector.oauth_http_limit (
    singleton boolean PRIMARY KEY CHECK (singleton),
    request_limit integer NOT NULL DEFAULT 60 CHECK (request_limit BETWEEN 1 AND 1000),
    window_ms integer NOT NULL DEFAULT 60000 CHECK (window_ms BETWEEN 1000 AND 60000),
    window_started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    hits integer NOT NULL DEFAULT 0 CHECK (hits BETWEEN 0 AND 1000)
);
INSERT INTO canvas_connector.oauth_http_limit(singleton) VALUES (true);

CREATE FUNCTION canvas_connector.consume_oauth_http_limit()
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE
    current_limit canvas_connector.oauth_http_limit%ROWTYPE;
    checked_at timestamptz;
BEGIN
    SELECT * INTO current_limit FROM canvas_connector.oauth_http_limit
        WHERE singleton=true FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'connector HTTP limit is unavailable';
    END IF;
    -- Read the database clock after acquiring the shared row lock. A backward
    -- clock change must not manufacture a new budget.
    checked_at := clock_timestamp();
    IF checked_at < current_limit.window_started_at THEN RETURN false; END IF;
    IF checked_at >= current_limit.window_started_at
        + current_limit.window_ms * interval '1 millisecond' THEN
        UPDATE canvas_connector.oauth_http_limit
            SET window_started_at=checked_at,hits=1 WHERE singleton=true;
        RETURN true;
    END IF;
    IF current_limit.hits >= current_limit.request_limit THEN RETURN false; END IF;
    UPDATE canvas_connector.oauth_http_limit SET hits=hits+1 WHERE singleton=true;
    RETURN true;
END;
$$;
REVOKE ALL ON canvas_connector.oauth_http_limit FROM PUBLIC;
REVOKE ALL ON FUNCTION canvas_connector.consume_oauth_http_limit() FROM PUBLIC;
COMMIT;
