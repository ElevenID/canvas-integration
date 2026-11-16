-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-installed guard for a narrow PostgreSQL row-lock privilege. An HTTP
-- role may receive UPDATE(created_at) to lock secrets without changing them.
-- This migration grants no privileges and changes no existing timestamps.
BEGIN;
CREATE FUNCTION canvas_connector.keep_secret_created_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'secret creation time is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER secret_creation_time BEFORE UPDATE ON canvas_connector.secrets
    FOR EACH ROW EXECUTE FUNCTION canvas_connector.keep_secret_created_at();
REVOKE ALL ON FUNCTION canvas_connector.keep_secret_created_at() FROM PUBLIC;
COMMIT;
