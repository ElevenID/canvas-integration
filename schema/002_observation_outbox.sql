-- SPDX-License-Identifier: AGPL-3.0-only
-- Connector delivery state only. Routing labels never confer core authority.
BEGIN;
CREATE FUNCTION canvas_connector.valid_outbox_claims(value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE item record; text_value text; size integer;
BEGIN
    IF jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
    SELECT count(*) INTO size FROM jsonb_each(value);
    IF size NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
    FOR item IN SELECT * FROM jsonb_each(value) LOOP
        IF item.key !~ '^[A-Za-z0-9_.:-]{1,128}$' OR lower(item.key)=ANY(ARRAY[
            'verified','verification','policy_allowed','approved','organization_id','subject_id','application_id',
            'provider','fact_type','scope','issuer_key','signing_key','private_key','token','access_token',
            'refresh_token','client_secret','password','__proto__','constructor','prototype','tojson']) THEN RETURN false; END IF;
        CASE jsonb_typeof(item.value)
            WHEN 'null','boolean' THEN NULL;
            WHEN 'number' THEN IF abs(item.value::text::numeric)>9007199254740991 THEN RETURN false; END IF;
            WHEN 'string' THEN
                text_value:=item.value#>>'{}';
                IF octet_length(text_value) NOT BETWEEN 1 AND 512 OR text_value~'[[:cntrl:]]'
                    OR text_value~U&'[\007f-\009f]' THEN RETURN false; END IF;
            ELSE RETURN false;
        END CASE;
    END LOOP;
    RETURN true;
END;
$$;
CREATE TABLE canvas_connector.observation_counters (
    organization_id text NOT NULL CHECK (organization_id~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    binding_id text NOT NULL CHECK (binding_id~'^[A-Za-z0-9_-]{1,128}$'),
    current_sequence bigint NOT NULL DEFAULT 0 CHECK (current_sequence BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY(organization_id,binding_id)
);
CREATE TABLE canvas_connector.observation_outbox (
    organization_id text NOT NULL,
    observation_id text NOT NULL CHECK (observation_id~'^[A-Za-z0-9_-]{1,128}$'),
    producer_ref text NOT NULL CHECK (producer_ref~'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
    binding_id text NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision BETWEEN 1 AND 9007199254740991),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    observed_at_ms bigint NOT NULL CHECK (observed_at_ms BETWEEN 1 AND 9007199254740991),
    effective_at_ms bigint NOT NULL CHECK (effective_at_ms BETWEEN 1 AND observed_at_ms),
    claims jsonb NOT NULL CHECK (canvas_connector.valid_outbox_claims(claims)),
    body text CHECK (octet_length(body) BETWEEN 1 AND 65536),
    phase text NOT NULL DEFAULT 'preparing' CHECK (phase IN ('preparing','pending','leased','retry','parked','acknowledged','retired')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000000),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_expires_at timestamptz,
    receipt_id text CHECK (receipt_id~'^[A-Za-z0-9_-]{1,128}$'),
    replayed boolean,
    last_error text CHECK (last_error IN ('submission_rejected','submission_outcome_unknown','delivery_attempt_limit','invalid_stored_observation')),
    last_status integer CHECK (last_status BETWEEN 300 AND 599),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(organization_id,observation_id),
    UNIQUE(organization_id,binding_id,sequence),
    FOREIGN KEY(organization_id,binding_id) REFERENCES canvas_connector.observation_counters(organization_id,binding_id),
    CHECK ((phase='preparing' AND body IS NULL) OR (phase<>'preparing' AND body IS NOT NULL)),
    CHECK ((phase='leased' AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (phase<>'leased' AND lease_id IS NULL AND lease_expires_at IS NULL)),
    CHECK ((phase='acknowledged' AND receipt_id IS NOT NULL AND replayed IS NOT NULL)
        OR (phase<>'acknowledged' AND receipt_id IS NULL AND replayed IS NULL))
);
CREATE INDEX observation_delivery_order ON canvas_connector.observation_outbox(organization_id,binding_id,sequence);
CREATE FUNCTION canvas_connector.protect_outbox()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'outbox retention required'; END IF;
    IF TG_OP='UPDATE' THEN
        IF (NEW.organization_id,NEW.observation_id,NEW.producer_ref,NEW.binding_id,NEW.binding_revision,NEW.sequence,
            NEW.observed_at_ms,NEW.effective_at_ms,NEW.claims,NEW.created_at)
          IS DISTINCT FROM (OLD.organization_id,OLD.observation_id,OLD.producer_ref,OLD.binding_id,OLD.binding_revision,OLD.sequence,
            OLD.observed_at_ms,OLD.effective_at_ms,OLD.claims,OLD.created_at)
          OR (OLD.body IS NOT NULL AND NEW.body IS DISTINCT FROM OLD.body) THEN
            RAISE EXCEPTION 'immutable observation';
        END IF;
        IF OLD.phase IN ('acknowledged','retired') AND
            (NEW.phase,NEW.receipt_id,NEW.replayed,NEW.attempts,NEW.available_at,NEW.lease_id,NEW.lease_expires_at,NEW.last_error,NEW.last_status)
            IS DISTINCT FROM (OLD.phase,OLD.receipt_id,OLD.replayed,OLD.attempts,OLD.available_at,OLD.lease_id,OLD.lease_expires_at,OLD.last_error,OLD.last_status) THEN
            RAISE EXCEPTION 'terminal delivery is immutable';
        END IF;
        NEW.updated_at:=clock_timestamp();
    END IF;
    IF NEW.body IS NOT NULL AND NEW.body::jsonb IS DISTINCT FROM jsonb_build_object(
        'binding_id',NEW.binding_id,'binding_revision',NEW.binding_revision,'observation_id',NEW.observation_id,
        'sequence',NEW.sequence,'observed_at_ms',NEW.observed_at_ms,'effective_at_ms',NEW.effective_at_ms,'claims',NEW.claims) THEN
        RAISE EXCEPTION 'observation body mismatch';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER observation_immutable BEFORE INSERT OR UPDATE OR DELETE ON canvas_connector.observation_outbox
    FOR EACH ROW EXECUTE FUNCTION canvas_connector.protect_outbox();
CREATE FUNCTION canvas_connector.enqueue_observation(org text,producer text,binding text,revision bigint,
    observation text,observed bigint,effective bigint,assertions jsonb)
RETURNS SETOF canvas_connector.observation_outbox LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE existing canvas_connector.observation_outbox; current bigint;
BEGIN
    INSERT INTO canvas_connector.observation_counters(organization_id,binding_id) VALUES(org,binding) ON CONFLICT DO NOTHING;
    SELECT current_sequence INTO current FROM canvas_connector.observation_counters
        WHERE organization_id=org AND binding_id=binding FOR UPDATE;
    SELECT * INTO existing FROM canvas_connector.observation_outbox WHERE organization_id=org AND observation_id=observation;
    IF FOUND THEN
        IF (existing.producer_ref,existing.binding_id,existing.binding_revision,existing.observed_at_ms,existing.effective_at_ms,existing.claims)
            IS DISTINCT FROM (producer,binding,revision,observed,effective,assertions) THEN RAISE EXCEPTION 'observation identity conflict'; END IF;
        RETURN NEXT existing; RETURN;
    END IF;
    IF current>=9007199254740991 THEN RAISE EXCEPTION 'sequence exhausted'; END IF;
    UPDATE canvas_connector.observation_counters SET current_sequence=current+1 WHERE organization_id=org AND binding_id=binding;
    RETURN QUERY INSERT INTO canvas_connector.observation_outbox
        (organization_id,observation_id,producer_ref,binding_id,binding_revision,sequence,observed_at_ms,effective_at_ms,claims)
        VALUES(org,observation,producer,binding,revision,current+1,observed,effective,assertions) RETURNING *;
END;
$$;
CREATE FUNCTION canvas_connector.seal_observation(org text,producer text,observation text,original text)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item canvas_connector.observation_outbox;
BEGIN
    SELECT * INTO item FROM canvas_connector.observation_outbox
        WHERE organization_id=org AND producer_ref=producer AND observation_id=observation FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF item.body IS NOT NULL THEN RETURN item.body=original; END IF;
    UPDATE canvas_connector.observation_outbox SET body=original,phase='pending'
        WHERE organization_id=org AND observation_id=observation;
    RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.claim_observation(org text,producer text)
RETURNS SETOF canvas_connector.observation_outbox LANGUAGE sql SET search_path=pg_catalog AS $$
    WITH candidate AS (
        SELECT item.organization_id,item.observation_id FROM canvas_connector.observation_outbox item
        WHERE item.organization_id=org AND item.producer_ref=producer AND item.available_at<=clock_timestamp()
          AND (item.phase IN ('pending','retry') OR (item.phase='leased' AND item.lease_expires_at<=clock_timestamp()))
          AND NOT EXISTS(SELECT 1 FROM canvas_connector.observation_outbox earlier
            WHERE earlier.organization_id=item.organization_id AND earlier.binding_id=item.binding_id
              AND earlier.sequence<item.sequence AND earlier.phase NOT IN ('acknowledged','retired'))
        ORDER BY item.created_at,item.binding_id,item.sequence FOR UPDATE OF item SKIP LOCKED LIMIT 1
    ) UPDATE canvas_connector.observation_outbox item SET phase='leased',lease_id=gen_random_uuid(),
        lease_expires_at=clock_timestamp()+interval '3 minutes',attempts=attempts+1
        FROM candidate WHERE item.organization_id=candidate.organization_id AND item.observation_id=candidate.observation_id
        RETURNING item.*;
$$;
CREATE FUNCTION canvas_connector.acknowledge_observation(org text,producer text,observation text,lease uuid,receipt text,replay boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item canvas_connector.observation_outbox;
BEGIN
    SELECT * INTO item FROM canvas_connector.observation_outbox
        WHERE organization_id=org AND producer_ref=producer AND observation_id=observation FOR UPDATE;
    IF NOT FOUND OR item.phase<>'leased' OR item.lease_id IS DISTINCT FROM lease
        OR item.lease_expires_at<=clock_timestamp() THEN RETURN false; END IF;
    UPDATE canvas_connector.observation_outbox SET phase='acknowledged',receipt_id=receipt,replayed=replay,
        lease_id=NULL,lease_expires_at=NULL,last_error=NULL,last_status=NULL
        WHERE organization_id=org AND observation_id=observation;
    IF item.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'delivery lease expired'; END IF;
    RETURN true;
END;
$$;
CREATE FUNCTION canvas_connector.defer_observation(org text,producer text,observation text,lease uuid,code text,status integer,park boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item canvas_connector.observation_outbox;
BEGIN
    SELECT * INTO item FROM canvas_connector.observation_outbox
        WHERE organization_id=org AND producer_ref=producer AND observation_id=observation FOR UPDATE;
    IF NOT FOUND OR item.phase<>'leased' OR item.lease_id IS DISTINCT FROM lease
        OR item.lease_expires_at<=clock_timestamp() THEN RETURN false; END IF;
    UPDATE canvas_connector.observation_outbox SET phase=CASE WHEN park THEN 'parked' ELSE 'retry' END,
        available_at=clock_timestamp()+make_interval(secs=>least(300,power(2,least(attempts,10)))::integer),
        lease_id=NULL,lease_expires_at=NULL,last_error=code,last_status=status
        WHERE organization_id=org AND observation_id=observation;
    IF item.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'delivery lease expired'; END IF;
    RETURN true;
END;
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA canvas_connector FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA canvas_connector FROM PUBLIC;
COMMIT;
