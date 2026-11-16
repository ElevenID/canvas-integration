-- SPDX-License-Identifier: AGPL-3.0-only
-- Disposable database only. Run after schema/001_oauth_storage.sql.
INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
VALUES ('org-one','platform-one','https://canvas.example.test',true);
INSERT INTO canvas_connector.authorizations
(state_hash,browser_binding_hash,organization_id,platform_id,platform_config_version,canvas_origin,client_id,
 client_secret_ref,capabilities,scopes,redirect_uri,expires_at)
VALUES (repeat('a',64),repeat('e',64),'org-one','platform-one',1,'https://canvas.example.test','client',
 'vault-client',ARRAY['catalog'],ARRAY['read'],'https://connector.example.test/oauth/callback',clock_timestamp()+interval '5 minutes');
DO $$ BEGIN
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('a',64),repeat('e',64))) <> 1 THEN
        RAISE EXCEPTION 'fresh authorization not consumed'; END IF;
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('a',64),repeat('e',64))) <> 0 THEN
        RAISE EXCEPTION 'authorization replay accepted'; END IF;
END $$;
INSERT INTO canvas_connector.authorizations
(state_hash,browser_binding_hash,organization_id,platform_id,platform_config_version,canvas_origin,client_id,
 client_secret_ref,capabilities,scopes,redirect_uri,created_at,expires_at)
VALUES (repeat('b',64),repeat('e',64),'org-one','platform-one',1,'https://canvas.example.test','client',
 'vault-client',ARRAY['catalog'],ARRAY['read'],'https://connector.example.test/oauth/callback',
 clock_timestamp()-interval '6 minutes',clock_timestamp()-interval '1 minute');
DO $$ BEGIN
    IF (SELECT count(*) FROM canvas_connector.consume_authorization(repeat('b',64),repeat('e',64))) <> 0 THEN
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
-- Inject a queue-write failure: disconnect must retain the connection.
ALTER TABLE canvas_connector.revocation_jobs ADD CONSTRAINT synthetic_queue_failure CHECK (attempts < 0) NOT VALID;
DO $$ BEGIN
    BEGIN
        PERFORM canvas_connector.disconnect('org-one','platform-one');
        RAISE EXCEPTION 'injected queue failure was ignored';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    IF (SELECT count(*) FROM canvas_connector.connections) <> 1 THEN
        RAISE EXCEPTION 'failed enqueue lost the connection token reference'; END IF;
END $$;
ALTER TABLE canvas_connector.revocation_jobs DROP CONSTRAINT synthetic_queue_failure;
DO $$ BEGIN
    IF canvas_connector.disconnect('other-org','platform-one') THEN
        RAISE EXCEPTION 'cross-tenant disconnect accepted'; END IF;
    IF NOT canvas_connector.disconnect('org-one','platform-one') THEN
        RAISE EXCEPTION 'disconnect failed'; END IF;
    IF canvas_connector.disconnect('org-one','platform-one') THEN
        RAISE EXCEPTION 'repeated disconnect changed state'; END IF;
    IF (SELECT count(*) FROM canvas_connector.revocation_jobs) <> 1 THEN
        RAISE EXCEPTION 'durable revocation job lost'; END IF;
    IF EXISTS(SELECT 1 FROM canvas_connector.connections) THEN
        RAISE EXCEPTION 'disconnect left an active connection'; END IF;
END $$;
DO $$ DECLARE job canvas_connector.revocation_jobs; replacement canvas_connector.revocation_jobs;
BEGIN
    SELECT * INTO job FROM canvas_connector.claim_revocation();
    IF job.lease_id IS NULL OR job.attempts <> 1 THEN RAISE EXCEPTION 'lease not acquired'; END IF;
    IF EXISTS(SELECT 1 FROM canvas_connector.claim_revocation()) THEN
        RAISE EXCEPTION 'live lease claimed twice'; END IF;
    IF canvas_connector.finish_revocation(job.id,gen_random_uuid()) THEN
        RAISE EXCEPTION 'foreign lease acknowledged'; END IF;
    UPDATE canvas_connector.revocation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=job.id;
    IF canvas_connector.finish_revocation(job.id,job.lease_id) THEN
        RAISE EXCEPTION 'expired lease acknowledged'; END IF;
    SELECT * INTO replacement FROM canvas_connector.claim_revocation();
    IF replacement.lease_id = job.lease_id OR replacement.attempts <> 2 THEN
        RAISE EXCEPTION 'reclaimed job did not rotate lease'; END IF;
    IF canvas_connector.retry_revocation(job.id,job.lease_id) THEN
        RAISE EXCEPTION 'stale worker rescheduled current job'; END IF;
    IF NOT canvas_connector.retry_revocation(replacement.id,replacement.lease_id) THEN
        RAISE EXCEPTION 'current worker retry failed'; END IF;
    IF EXISTS(SELECT 1 FROM canvas_connector.claim_revocation()) THEN
        RAISE EXCEPTION 'backoff was bypassed'; END IF;
    UPDATE canvas_connector.revocation_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE id=job.id;
    SELECT * INTO replacement FROM canvas_connector.claim_revocation();
    IF canvas_connector.finish_revocation(replacement.id,replacement.lease_id) THEN
        RAISE EXCEPTION 'completion accepted before confirmed provider revocation'; END IF;
    IF NOT canvas_connector.record_provider_revocation(replacement.id,replacement.lease_id) THEN
        RAISE EXCEPTION 'provider revocation was not recorded'; END IF;
    IF NOT canvas_connector.finish_revocation(replacement.id,replacement.lease_id) THEN
        RAISE EXCEPTION 'current worker completion failed'; END IF;
    IF EXISTS(SELECT 1 FROM canvas_connector.claim_revocation()) THEN
        RAISE EXCEPTION 'completed job reclaimed'; END IF;
END $$;
