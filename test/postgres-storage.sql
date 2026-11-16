-- SPDX-License-Identifier: AGPL-3.0-only
-- Disposable database only. Run after schema/001_oauth_storage.sql.
INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
VALUES ('org-one','platform-one','https://canvas.example.test',true);
INSERT INTO canvas_connector.authorizations
(state_hash,organization_id,platform_id,platform_config_version,canvas_origin,client_id,
 client_secret_ref,capabilities,scopes,redirect_uri,expires_at)
VALUES (repeat('a',64),'org-one','platform-one',1,'https://canvas.example.test','client',
 'vault-client',ARRAY['catalog'],ARRAY['read'],'https://connector.example.test/oauth/callback',clock_timestamp()+interval '5 minutes');
DO $$ BEGIN
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('a',64))) <> 1 THEN
        RAISE EXCEPTION 'fresh authorization not consumed'; END IF;
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('a',64))) <> 0 THEN
        RAISE EXCEPTION 'authorization replay accepted'; END IF;
END $$;
INSERT INTO canvas_connector.authorizations
(state_hash,organization_id,platform_id,platform_config_version,canvas_origin,client_id,
 client_secret_ref,capabilities,scopes,redirect_uri,created_at,expires_at)
VALUES (repeat('b',64),'org-one','platform-one',1,'https://canvas.example.test','client',
 'vault-client',ARRAY['catalog'],ARRAY['read'],'https://connector.example.test/oauth/callback',
 clock_timestamp()-interval '6 minutes',clock_timestamp()-interval '1 minute');
DO $$ BEGIN
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('b',64))) <> 0 THEN
        RAISE EXCEPTION 'expired authorization accepted'; END IF;
END $$;
INSERT INTO canvas_connector.connections
(organization_id,platform_id,platform_config_version,canvas_origin,client_id,
client_secret_ref,access_token_ref,refresh_token_ref,capabilities,scopes,status)
VALUES ('org-one','platform-one',1,'https://canvas.example.test','client',
'vault-client','vault-access','vault-refresh',ARRAY['catalog'],ARRAY['read'],'connected');
DO $$ BEGIN
    BEGIN
        UPDATE canvas_connector.connections SET access_token_ref=client_secret_ref;
        RAISE EXCEPTION 'secret reference collision accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        UPDATE canvas_connector.platforms SET organization_id='other';
        RAISE EXCEPTION 'tenant reassignment accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END $$;
UPDATE canvas_connector.platforms SET enabled=false;
DO $$ BEGIN
    IF (SELECT config_version FROM canvas_connector.platforms) <> 2 THEN
        RAISE EXCEPTION 'configuration revision not advanced'; END IF;
    BEGIN
        UPDATE canvas_connector.connections SET access_token_ref='new-access';
        RAISE EXCEPTION 'stale configuration publication accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END $$;
-- Disablement must not prevent revocation/reauthorization cleanup.
UPDATE canvas_connector.connections SET status='reauthorization_required';
INSERT INTO canvas_connector.revocation_jobs(organization_id,platform_id,canvas_origin,access_token_ref)
SELECT organization_id,platform_id,canvas_origin,access_token_ref FROM canvas_connector.connections;
DELETE FROM canvas_connector.connections;
DO $$ BEGIN
    IF (SELECT count(*) FROM canvas_connector.revocation_jobs) <> 1 THEN
        RAISE EXCEPTION 'durable revocation job lost'; END IF;
END $$;
