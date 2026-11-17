#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable real PostgreSQL qualification; existing local Docker only."""
import os
import json
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'


def main():
    scope = uuid.uuid4().hex
    name = 'canvas-association-' + scope
    container_id = None
    def docker(*args, source=None):
        return subprocess.run(['docker', *args], input=source, text=True, capture_output=True, check=True, timeout=30).stdout.strip()
    # Never pull or allocate persistent PGDATA. Creation is covered by recovery
    # even when the Docker acknowledgement is lost before we capture its ID.
    image_id = json.loads(docker('image', 'inspect', IMAGE))[0]['Id']
    tmpfs = {'/var/lib/postgresql/data': 'rw,nosuid,nodev,size=256m',
             '/var/run/postgresql': 'rw,nosuid,nodev', '/tmp': 'rw,nosuid,nodev'}
    try:
        arguments = ['create', '--pull=never', '--name', name, '--read-only',
                     '--label', 'elevenid.owner=canvas-association-test',
                     '--label', 'elevenid.test-scope=' + scope,
                     '--publish', '127.0.0.1::5432',
                     '--env', 'POSTGRES_PASSWORD=synthetic-association-only']
        for target, options in tmpfs.items():
            arguments.extend(['--tmpfs', target + ':' + options])
        container_id = docker(*arguments, IMAGE)
        print('Owned tmpfs PostgreSQL: ' + container_id, flush=True)
        docker('start', container_id)
        for attempt in range(100):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True, timeout=30).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('disposable PostgreSQL unavailable')
        def sql(source):
            return docker('exec', '-i', name, 'psql', '-X', '-q', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', source=source)
        for path in sorted((ROOT/'schema').glob('*.sql')):
            try:
                sql(path.read_text(encoding='utf-8'))
            except subprocess.CalledProcessError as error:
                raise RuntimeError('Synthetic fixture migration failed: ' + path.name + ': ' + error.stderr[:2048]) from error
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
                       cwd=ROOT, env=environment, check=True, timeout=120)
    finally:
        inspection = subprocess.run(['docker', 'inspect', name], text=True, capture_output=True, timeout=30)
        if inspection.returncode:
            if 'No such object:' not in inspection.stderr and 'No such container:' not in inspection.stderr:
                raise RuntimeError('Cannot inspect owned fixture; preserve it for recovery')
            if container_id is not None:
                raise RuntimeError('Owned fixture disappeared before cleanup verification')
        else:
            candidate, = json.loads(inspection.stdout)
            labels = candidate['Config'].get('Labels') or {}
            if (candidate['Name'] != '/' + name or candidate['Image'] != image_id
                    or candidate['Config']['Image'] != IMAGE
                    or labels.get('elevenid.owner') != 'canvas-association-test'
                    or labels.get('elevenid.test-scope') != scope
                    or container_id is not None and candidate['Id'] != container_id
                    or not candidate['HostConfig']['ReadonlyRootfs']
                    or candidate['HostConfig'].get('Tmpfs') != tmpfs
                    or any(mount['Type'] != 'tmpfs' for mount in candidate.get('Mounts', []))):
                raise RuntimeError('Fixture identity or storage differs; preserve it for recovery')
            if candidate['State']['Running']:
                docker('stop', '--time', '5', candidate['Id'])
            docker('rm', candidate['Id'])
            print('Removed owned tmpfs PostgreSQL: ' + candidate['Id'], flush=True)


if __name__ == '__main__':
    main()
