#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Qualify connector schema only against a task-owned disposable PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'


def main():
    name = 'canvas-storage-test-' + uuid.uuid4().hex
    subprocess.run(['docker', 'run', '--detach', '--name', name, '--network', 'none',
                    '--label', 'elevenid.owner=canvas-storage-test',
                    '--env', 'POSTGRES_PASSWORD=synthetic-storage-only',
                    '--env', 'POSTGRES_DB=canvas_storage_test', IMAGE], check=True)
    try:
        def sql(source):
            result = subprocess.run(['docker', 'exec', '-i', name, 'psql', '-X', '-q', '-A', '-t',
                                   '-U', 'postgres', '-d', 'canvas_storage_test',
                                   '-v', 'ON_ERROR_STOP=1'], input=source, text=True,
                                  capture_output=True)
            if result.returncode:
                raise RuntimeError('disposable schema contract failed: ' + result.stderr)
            return result.stdout.strip()

        for attempt in range(60):
            ready = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'],
                                   capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('disposable PostgreSQL failed readiness')
        sql((ROOT / 'schema/001_oauth_storage.sql').read_text(encoding='utf-8'))
        sql((ROOT / 'schema/005_initial_oauth_custody.sql').read_text(encoding='utf-8'))
        sql((ROOT / 'test/postgres-storage.sql').read_text(encoding='utf-8'))
        subprocess.run(['node', str(ROOT / 'test/postgres-repository-contract.mjs'), name], check=True)
        sql("""INSERT INTO canvas_connector.authorizations
            (state_hash,browser_binding_hash,organization_id,platform_id,platform_config_version,canvas_origin,
             client_id,client_secret_ref,capabilities,scopes,redirect_uri,expires_at)
            VALUES (repeat('c',64),repeat('e',64),'org-one','platform-one',2,'https://canvas.example.test',
            'client','vault-client',ARRAY['catalog'],ARRAY['read'],
            'https://connector.example.test/oauth/callback',clock_timestamp()+interval '5 minutes');""")
        with ThreadPoolExecutor(max_workers=8) as executor:
            counts = list(executor.map(lambda _: sql(
                "SELECT count(*) FROM canvas_connector.consume_authorization(repeat('c',64),repeat('e',64));"), range(8)))
        if sorted(counts) != ['0'] * 7 + ['1']:
            raise AssertionError('concurrent authorization consumption was not exactly once')
        # Prior fault scenarios intentionally retain retryable cleanup jobs.
        # Preserve them, but isolate the single available job for this census.
        sql("UPDATE canvas_connector.revocation_jobs SET available_at=clock_timestamp()+interval '1 day' WHERE completed_at IS NULL;")
        sql("""INSERT INTO canvas_connector.revocation_jobs
            (organization_id,platform_id,canvas_origin,access_token_ref)
            VALUES ('org-one','platform-one','https://canvas.example.test','concurrent-vault-ref');""")
        with ThreadPoolExecutor(max_workers=8) as executor:
            counts = list(executor.map(lambda _: sql(
                "SELECT count(*) FROM canvas_connector.claim_revocation();"), range(8)))
        if sorted(counts) != ['0'] * 7 + ['1']:
            raise AssertionError('concurrent workers acquired more than one live job lease')
        print('Storage contracts, eight callback consumers and eight concurrent revocation workers passed')
    finally:
        # This name was generated above for this invocation; no shared workloads.
        subprocess.run(['docker', 'rm', '--force', name], check=True)


if __name__ == '__main__':
    main()
