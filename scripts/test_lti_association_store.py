#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable real PostgreSQL qualification; existing local Docker only."""
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'


def main():
    name = 'canvas-association-' + uuid.uuid4().hex
    def docker(*args, source=None):
        return subprocess.run(['docker', *args], input=source, text=True, capture_output=True, check=True).stdout.strip()
    docker('run', '--detach', '--name', name, '--label', 'elevenid.owner=canvas-association-test',
           '--publish', '127.0.0.1::5432', '--env', 'POSTGRES_PASSWORD=synthetic-association-only', IMAGE)
    try:
        for attempt in range(100):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('disposable PostgreSQL unavailable')
        def sql(source):
            return docker('exec', '-i', name, 'psql', '-X', '-q', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', source=source)
        for path in sorted((ROOT/'schema').glob('*.sql')):
            sql(path.read_text(encoding='utf-8'))
        sql("""CREATE ROLE association_runtime LOGIN PASSWORD 'synthetic-runtime-only';
          GRANT USAGE ON SCHEMA canvas_connector TO association_runtime;
          GRANT SELECT ON canvas_connector.lti_launch_states,canvas_connector.lti_launch_receipts,
            canvas_connector.lti_registrations,canvas_connector.platforms,canvas_connector.lti_provider_identities TO association_runtime;
          GRANT SELECT,INSERT ON canvas_connector.lti_association_attempts,canvas_connector.lti_association_dispatches TO association_runtime;
          GRANT UPDATE(phase) ON canvas_connector.lti_launch_states TO association_runtime;
          GRANT UPDATE(updated_at) ON canvas_connector.platforms,canvas_connector.lti_registrations,
            canvas_connector.lti_provider_identities TO association_runtime;
          GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA canvas_connector TO association_runtime;
          INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
            VALUES('association-org','association-platform','https://canvas.example',true);
          INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,
            trust_profile,target_link_uri,enabled)
            VALUES('10000000-0000-4000-8000-000000000001','association-org','association-platform','client-one','deployment-one',
            'self_managed_same_origin','https://connector.example/lti/resource',true);""")
        port = docker('port', name, '5432/tcp').rsplit(':', 1)[1]
        environment = {**os.environ, 'CANVAS_ASSOCIATION_TEST_PORT': port}
        subprocess.run(['node', '--test', str(ROOT/'scripts/lti-association-store.contract.mjs')],
                       cwd=ROOT, env=environment, check=True)
    finally:
        docker('rm', '--force', name)


if __name__ == '__main__':
    main()
