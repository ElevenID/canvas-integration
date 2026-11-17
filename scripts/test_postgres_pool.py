#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real verified-TLS JS driver + readonly OpenBao + connector vault/database.

Only uniquely named disposable fixtures and synthetic credentials. No defaults,
operator configuration, existing database, core database or AWS connection.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
PG_IMAGE='postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'
BAO_IMAGE='quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878'

def main():
    arguments=sys.argv[1:]
    if arguments and (len(arguments)!=2 or arguments[0]!='--operator-browser-tests' or not Path(arguments[1]).is_absolute()):
        raise RuntimeError('unsupported physical contract arguments')
    suffix=uuid.uuid4().hex
    pg='canvas-pg-driver-'+suffix
    bao='canvas-pg-key-'+suffix
    def docker(*args,input=None):
        return subprocess.run(['docker',*args],input=input,text=True,capture_output=True,check=True).stdout.strip()
    def sql(text):
        return docker('exec','-i',pg,'psql','-X','-q','-A','-t','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1',input=text)
    def key(*args,input=None):
        return docker('exec','-i','-e','BAO_ADDR=https://127.0.0.1:8200','-e','BAO_CACERT=/tmp/canvas-tls/vault-ca.pem',
            '-e','BAO_TOKEN=synthetic-driver-key-bootstrap',bao,'bao',*args,input=input)
    try:
        with tempfile.TemporaryDirectory(prefix='canvas-driver-contract-') as directory:
            path=Path(directory).resolve()
            if path.parent!=Path(tempfile.gettempdir()).resolve():raise AssertionError('unexpected fixture path')
            # These certificates protect disposable loopback fixtures only.
            empty=path/'openssl.cnf';empty.write_text('')
            env={**os.environ,'OPENSSL_CONF':str(empty)}
            for name in ['server','untrusted']:
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                  '-keyout',str(path/(name+'.key')),'-out',str(path/(name+'.crt')),'-subj','/CN=localhost',
                  '-addext','subjectAltName=DNS:localhost'],check=True,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            docker('run','--detach','--name',pg,'--label','elevenid.owner=codex-canvas-split',
                '--publish','127.0.0.1::5432','--mount','type=bind,source='+str(path)+',target=/tls,readonly',
                '--env','POSTGRES_PASSWORD=synthetic-driver-bootstrap','--env','POSTGRES_DB=canvas_driver_test',
                '--entrypoint','sh',PG_IMAGE,'-c',
                'cp /tls/server.crt /tmp/server.crt && cp /tls/server.key /tmp/server.key && chown postgres:postgres /tmp/server.* && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key')
            for attempt in range(100):
                try:sql('SELECT 1;');break
                except subprocess.CalledProcessError:
                    if attempt==99:raise
                    time.sleep(0.1)
            sql((ROOT/'schema/001_oauth_storage.sql').read_text())
            sql((ROOT/'schema/002_observation_outbox.sql').read_text())
            sql((ROOT/'schema/003_rest_capture.sql').read_text())
            sql((ROOT/'schema/004_oauth_http_limit.sql').read_text())
            sql((ROOT/'schema/005_initial_oauth_custody.sql').read_text())
            sql((ROOT/'schema/006_secret_lock_privilege.sql').read_text())
            sql((ROOT/'schema/007_oauth_attempt_recovery.sql').read_text())
            sql((ROOT/'schema/008_connection_administration.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/009_platform_administration.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/010_oauth_client_provisioning.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/011_rest_route_administration.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/012_lti_launch_state.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/013_lti_registration_administration.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/014_lti_provider_identities.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/015_rest_capture_scheduling.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/016_lti_tool_keys.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/017_lti_service_attempts.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/018_lti_service_recovery.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/019_lti_capture.sql').read_text(encoding='utf-8'))
            sql((ROOT/'schema/020_lti_capture_administration.sql').read_text(encoding='utf-8'))
            sql("""CREATE ROLE canvas_runtime LOGIN PASSWORD 'synthetic-driver-runtime';
                GRANT CONNECT ON DATABASE canvas_driver_test TO canvas_runtime;
                GRANT USAGE ON SCHEMA canvas_connector TO canvas_runtime;
                GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA canvas_connector TO canvas_runtime;
                GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA canvas_connector TO canvas_runtime;
                GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA canvas_connector TO canvas_runtime;
                CREATE SCHEMA unrelated_private; CREATE TABLE unrelated_private.denied(value text);
                INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
                VALUES ('driver-org','driver-platform','https://canvas.example.test',true);""")
            docker('run','--detach','--name',bao,'--label','elevenid.owner=codex-canvas-split','--publish','127.0.0.1::8200',
                '--entrypoint','sh',BAO_IMAGE,'-c','mkdir -p /tmp/canvas-tls && exec bao server -dev -dev-tls -dev-tls-cert-dir=/tmp/canvas-tls -dev-root-token-id=synthetic-driver-key-bootstrap -dev-listen-address=0.0.0.0:8200')
            for attempt in range(100):
                try:key('status','-format=json');break
                except subprocess.CalledProcessError:
                    if attempt==99:raise
                    time.sleep(0.1)
            key('secrets','enable','-path=connector-kv','kv-v2')
            for key_id,byte in [('canvas-key-one',31),('canvas-key-two',47)]:
                key('kv','put','-mount=connector-kv','-cas=0','canvas-envelope/keys/'+key_id,'key_base64='+base64.b64encode(bytes([byte])*32).decode())
            key('kv','put','-mount=connector-kv','-cas=0','canvas-envelope/current','id=canvas-key-one')
            key('policy','write','canvas-key-reader','-',input='path "connector-kv/data/canvas-envelope/current" { capabilities=["read"] }\npath "connector-kv/data/canvas-envelope/keys/*" { capabilities=["read"] }\n')
            token=json.loads(key('token','create','-policy=canvas-key-reader','-no-default-policy','-format=json'))['auth']['client_token']
            file_token=json.loads(key('token','create','-policy=canvas-key-reader','-no-default-policy','-format=json'))['auth']['client_token'] if os.name!='nt' else None
            pgport=docker('port',pg,'5432/tcp').splitlines()[0]
            baoport=docker('port',bao,'8200/tcp').splitlines()[0]
            if not all(v.startswith('127.0.0.1:') for v in [pgport,baoport]):raise AssertionError('fixture exposure must be loopback')
            fixture=path/'synthetic-fixture.json'
            fixture.write_text(json.dumps({'port':int(pgport.rsplit(':',1)[1]),'ca':(path/'server.crt').read_text(),
                'untrustedCa':(path/'untrusted.crt').read_text(),'baoOrigin':'https://'+baoport,
                'baoCa':docker('exec',bao,'cat','/tmp/canvas-tls/vault-ca.pem'),'baoToken':token,'baoFileToken':file_token}))
            def node(stage):subprocess.run(['node',str(ROOT/'test/postgres-pool-contract.mjs'),str(fixture),stage,pg],check=True,cwd=ROOT,env=env,timeout=30)
            node('initial')
            subprocess.run(['node',str(ROOT/'test/connector-oauth-runtime-contract.mjs'),str(fixture),pg,bao],check=True,cwd=ROOT,env=env,timeout=60)
            if arguments:
                subprocess.run(['node',str(ROOT/'test/operator-browser-fixture.mjs'),str(fixture),pg,arguments[1]],check=True,cwd=ROOT,env=env,timeout=180)
            subprocess.run(['node',str(ROOT/'test/connector-worker-runtime-contract.mjs'),str(fixture),pg],check=True,cwd=ROOT,env=env,timeout=90)
            subprocess.run(['node',str(ROOT/'test/observation-outbox-contract.mjs'),str(fixture),pg],check=True,cwd=ROOT,env=env,timeout=60)
            subprocess.run(['node',str(ROOT/'test/rest-capture-contract.mjs'),str(fixture),pg],check=True,cwd=ROOT,env=env,timeout=60)
            key('kv','put','-mount=connector-kv','-cas=1','canvas-envelope/current','id=canvas-key-two')
            node('rotated')
            key('token','revoke',token)
            node('key-denied')
            # Auth-ok without a password challenge must not bypass custody.
            docker('exec','-i',pg,'sh','-c','cat > /tmp/canvas-trust-hba.conf',input=
                'local all all trust\nhostssl all canvas_runtime all trust\nhostnossl all all all reject\n')
            docker('exec',pg,'sh','-c',
                'cat /tmp/canvas-trust-hba.conf "$PGDATA/pg_hba.conf" > /tmp/canvas-merged-hba.conf && cat /tmp/canvas-merged-hba.conf > "$PGDATA/pg_hba.conf"')
            sql('SELECT pg_reload_conf();')
            time.sleep(0.1)
            if sql("SELECT auth_method FROM pg_hba_file_rules WHERE line_number=2")!='trust':
                raise AssertionError('disposable trust-HBA fixture invalid')
            node('trust-custody')
            docker('stop',pg)
            node('database-denied')
        print('Actual verified-TLS PostgreSQL driver/OpenBao/encrypted-vault composition and negative contracts passed')
    finally:
        for name in [pg,bao]:
            subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
if __name__=='__main__':main()
