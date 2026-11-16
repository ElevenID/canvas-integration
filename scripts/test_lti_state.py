#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real isolated PostgreSQL LTI state/receipt contracts; no Core or provider access."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import hashlib
import base64
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'


def main():
    name = 'canvas-lti-state-' + uuid.uuid4().hex
    subprocess.run(['docker', 'run', '--detach', '--name', name, '--network', 'none',
                    '--label', 'elevenid.owner=canvas-lti-state-test', '--env', 'POSTGRES_PASSWORD=synthetic-only', IMAGE], check=True)
    try:
        def sql(source):
            result = subprocess.run(['docker', 'exec', '-i', name, 'psql', '-X', '-q', '-A', '-t',
                                     '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1'], input=source,
                                    text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError('LTI SQL contract failed: ' + result.stderr)
            return result.stdout.strip()

        for _ in range(60):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True).returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('owned PostgreSQL readiness failed')
        for migration in sorted((ROOT / 'schema').glob('*.sql')):
            sql(migration.read_text(encoding='utf-8'))
        sql("""INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
            VALUES('org-one','canvas-one','https://canvas.example',true);
            INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,
              trust_profile,target_link_uri,enabled)
            VALUES('10000000-0000-4000-8000-000000000001','org-one','canvas-one','client-one','deployment-one',
              'self_managed_same_origin','https://connector.example/lti/resource',true);
            CREATE ROLE lti_runtime;
            GRANT USAGE ON SCHEMA canvas_connector TO lti_runtime;
            GRANT SELECT ON canvas_connector.platforms,canvas_connector.lti_registrations,
              canvas_connector.lti_launch_states,canvas_connector.lti_launch_receipts TO lti_runtime;
            GRANT UPDATE(updated_at) ON canvas_connector.platforms,canvas_connector.lti_registrations TO lti_runtime;
            GRANT INSERT(state_hash,launch_id,browser_hash,organization_id,platform_id,registration_id,
              platform_version,registration_version,registration_snapshot,nonce) ON canvas_connector.lti_launch_states TO lti_runtime;
            GRANT UPDATE(phase,token_hash,protocol_claims,accepted_at) ON canvas_connector.lti_launch_states TO lti_runtime;
            GRANT INSERT(state_hash,launch_id,token_hash,receipt) ON canvas_connector.lti_launch_receipts TO lti_runtime;
            GRANT EXECUTE ON FUNCTION canvas_connector.lti_visible_identifier(text),canvas_connector.lti_numeric_date(jsonb),
             canvas_connector.lti_claims_match(jsonb,canvas_connector.lti_registrations,canvas_connector.platforms,text),
             canvas_connector.begin_lti_launch(uuid,bigint,bigint,text,text,text,uuid),
             canvas_connector.stage_lti_launch(text,text,jsonb),canvas_connector.confirm_lti_launch(text,text,text) TO lti_runtime;""")
        reg = '10000000-0000-4000-8000-000000000001'
        browser = 'b' * 64
        challenges = {}
        def runtime(source):
            return sql('SET ROLE lti_runtime; ' + source)
        def start(state, p=1, r=1):
            launch = str(uuid.uuid4())
            challenge = base64.urlsafe_b64encode(hashlib.sha256(state.encode()).digest()).decode().rstrip('=')
            challenges[state] = challenge
            return runtime(f"SELECT canvas_connector.begin_lti_launch('{reg}',{p},{r},'{state}','{browser}','{challenge}','{launch}');")
        def payload(state):
            now = int(sql('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint;'))
            return dict(issuer='https://canvas.example', clientId='client-one', deploymentId='deployment-one',
                        subject='provider-subject', nonce=challenges[state], issuedAt=now-1, expiresAt=now+120,
                        notBefore=None, targetLinkUri='https://connector.example/lti/resource',
                        resourceLinkId='resource-one', contextId=None, messageType='LtiResourceLinkRequest',
                        version='1.3.0')
        def encoded(value):
            return "'" + json.dumps(value, separators=(',', ':')).replace("'", "''") + "'::jsonb"
        def stage(state, token, claims):
            return runtime(f"SELECT canvas_connector.stage_lti_launch('{state}','{token}',{encoded(claims)});")
        def confirm(state, token, proof=browser):
            return runtime(f"SELECT canvas_connector.confirm_lti_launch('{state}','{proof}','{token}');")
        state, token_hash = 'a' * 64, 'c' * 64
        saved = json.loads(start(state)); claims = payload(state)
        assert saved['phase'] == 'pending' and saved['organization_id'] == 'org-one'
        assert not confirm(state, token_hash), 'unstaged state must not confirm'
        assert json.loads(stage(state, token_hash, claims))['phase'] == 'staged'
        assert not confirm(state, token_hash, 'd' * 64), 'wrong browser must not consume'
        assert not confirm(state, 'e' * 64), 'changed token must not consume'
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(lambda _: confirm(state, token_hash), range(8)))
        assert len(set(receipts)) == 1 and receipts[0]
        receipt = json.loads(receipts[0])
        assert receipt['launchId'] == saved['launch_id'] and 'subject' not in receipt and 'verified' not in receipt
        assert sql('SELECT count(*) FROM canvas_connector.lti_launch_receipts;') == '1'
        assert not stage(state, 'f' * 64, claims), 'changed original token must conflict'
        # Historical receipt replays are not active-session authority.
        sql("UPDATE canvas_connector.platforms SET enabled=false WHERE id='canvas-one';")
        assert confirm(state, token_hash) == receipts[0]
        assert not start('1' * 64), 'disabled platform must not start'
        sql("UPDATE canvas_connector.platforms SET enabled=true WHERE id='canvas-one';")
        pending = '2' * 64
        assert start(pending, p=3)
        sql(f"UPDATE canvas_connector.lti_registrations SET enabled=false WHERE id='{reg}';")
        sql(f"UPDATE canvas_connector.lti_registrations SET enabled=true WHERE id='{reg}';")
        assert not stage(pending, token_hash, payload(pending)), 'disable/enable ABA invalidates original registration revision'
        pending = '3' * 64
        assert start(pending, p=3, r=3)
        claims = payload(pending)
        bad_claims = [dict(claims, issuer='https://other.example'), dict(claims, nonce='wrong'),
                      dict(claims, expiresAt=0), dict(claims, issuedAt=0), dict(claims, clientId=1000),
                      dict(claims, resourceLinkId='x' * 256), dict(claims, extra='ignored-by-SQL-is-not-allowed')]
        for candidate in bad_claims:
            assert not stage(pending, token_hash, candidate), 'invalid protocol claims must not stage'
        assert json.loads(stage(pending, token_hash, payload(pending)))['phase'] == 'staged'
        # A failed final receipt write rolls acceptance back; same identity can retry.
        sql("""CREATE FUNCTION canvas_connector.test_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic receipt failure'; END; $$;
            CREATE TRIGGER zz_receipt_failure BEFORE INSERT ON canvas_connector.lti_launch_receipts
              FOR EACH ROW EXECUTE FUNCTION canvas_connector.test_receipt_failure();""")
        try:
            confirm(pending, token_hash)
            raise AssertionError('receipt fault unexpectedly committed')
        except RuntimeError:
            pass
        assert sql(f"SELECT phase FROM canvas_connector.lti_launch_states WHERE state_hash='{pending}';") == 'staged'
        sql('DROP TRIGGER zz_receipt_failure ON canvas_connector.lti_launch_receipts;')
        accepted = confirm(pending, token_hash)
        assert accepted and confirm(pending, token_hash) == accepted, 'lost commit reply reconciles original receipt'
        for source in ["UPDATE canvas_connector.lti_launch_receipts SET receipt='{}';",
                       "DELETE FROM canvas_connector.lti_launch_receipts;",
                       "UPDATE canvas_connector.lti_launch_states SET browser_hash=repeat('e',64);",
                       "UPDATE canvas_connector.lti_registrations SET client_id='other';"]:
            try:
                runtime(source)
                raise AssertionError('runtime exceeded state privilege boundary')
            except RuntimeError:
                pass
        # Owner writes also cannot silently rewrite an accepted receipt or identity.
        for source in ["UPDATE canvas_connector.lti_launch_receipts SET receipt='{}';",
                       "UPDATE canvas_connector.lti_launch_states SET phase='staged' WHERE phase='accepted';"]:
            try:
                sql(source)
                raise AssertionError('immutable evidence changed')
            except RuntimeError:
                pass
        # BEFORE trigger postimage corruption must not substitute for explicit intent.
        rewritten = '4' * 64
        assert start(rewritten, p=3, r=3)
        sql("""CREATE FUNCTION canvas_connector.test_lti_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN NEW.protocol_claims:=NEW.protocol_claims||jsonb_build_object('subject','rewritten'); RETURN NEW; END; $$;
            CREATE TRIGGER aa_lti_rewrite BEFORE UPDATE ON canvas_connector.lti_launch_states
              FOR EACH ROW WHEN (NEW.phase='staged') EXECUTE FUNCTION canvas_connector.test_lti_rewrite();""")
        try:
            stage(rewritten, token_hash, payload(rewritten))
            raise AssertionError('rewritten candidate unexpectedly staged')
        except RuntimeError:
            pass
        assert sql(f"SELECT phase FROM canvas_connector.lti_launch_states WHERE state_hash='{rewritten}';") == 'pending'
        sql('DROP TRIGGER aa_lti_rewrite ON canvas_connector.lti_launch_states;')
        # Expiry during an otherwise valid acceptance rolls both writes back.
        expiring = '5' * 64
        sql("""CREATE FUNCTION canvas_connector.test_lti_short_expiry() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN NEW.expires_at:=clock_timestamp()+interval '2 seconds'; RETURN NEW; END; $$;
            CREATE TRIGGER aa_lti_short_expiry BEFORE INSERT ON canvas_connector.lti_launch_states
              FOR EACH ROW EXECUTE FUNCTION canvas_connector.test_lti_short_expiry();""")
        assert start(expiring, p=3, r=3)
        sql('DROP TRIGGER aa_lti_short_expiry ON canvas_connector.lti_launch_states;')
        assert stage(expiring, token_hash, payload(expiring))
        sql("""CREATE OR REPLACE FUNCTION canvas_connector.test_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_sleep(2.2); RETURN NEW; END; $$;
            CREATE TRIGGER zz_receipt_delay BEFORE INSERT ON canvas_connector.lti_launch_receipts
              FOR EACH ROW EXECUTE FUNCTION canvas_connector.test_receipt_failure();""")
        try:
            confirm(expiring, token_hash)
            raise AssertionError('late-expiry acceptance unexpectedly committed')
        except RuntimeError:
            pass
        sql('DROP TRIGGER zz_receipt_delay ON canvas_connector.lti_launch_receipts;')
        assert sql(f"SELECT phase FROM canvas_connector.lti_launch_states WHERE state_hash='{expiring}';") == 'staged'
        assert sql(f"SELECT count(*) FROM canvas_connector.lti_launch_receipts WHERE state_hash='{expiring}';") == '0'
        assert not confirm(expiring, token_hash), 'expired staged state cannot consume later'
        competing = '6' * 64
        assert start(competing, p=3, r=3)
        claims = payload(competing)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda token: stage(competing, token, claims), ['a' * 64, 'e' * 64]))
        assert sum(bool(value) for value in outcomes) == 1, 'only the original token intent may stage'
        subprocess.run(['node', str(ROOT / 'test/lti-launch-state-contract.mjs'), name], check=True, cwd=ROOT)
        print('LTI PostgreSQL16 state, 8-way receipt replay, browser/token fences, ABA, rollback and least-privilege contracts passed')
    finally:
        subprocess.run(['docker', 'rm', '--force', name], check=True)


if __name__ == '__main__':
    main()
