#!/usr/bin/env python3
"""Disposable OpenBao2.5.2/TLS + real Node key provider, synthetic data only."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
ROOT=Path(__file__).resolve().parents[1]
IMAGE="quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878"
def main():
    name="canvas-key-test-"+uuid.uuid4().hex
    def docker(*args, input=None):
        return subprocess.run(["docker",*args],input=input,text=True,capture_output=True,check=True).stdout.strip()
    def bao(*args,input=None):
        return docker("exec","-i","-e","BAO_ADDR=https://127.0.0.1:8200","-e","BAO_CACERT=/tmp/canvas-tls/vault-ca.pem",
          "-e","BAO_TOKEN=synthetic-key-bootstrap-token",name,"bao",*args,input=input)
    try:
        docker("run","--detach","--name",name,"--label","elevenid.owner=codex-canvas-split","--publish","127.0.0.1::8200",
          "--entrypoint","sh",IMAGE,"-c","mkdir -p /tmp/canvas-tls && exec bao server -dev -dev-tls -dev-tls-cert-dir=/tmp/canvas-tls -dev-root-token-id=synthetic-key-bootstrap-token -dev-listen-address=0.0.0.0:8200")
        for attempt in range(100):
            try: bao("status","-format=json");break
            except subprocess.CalledProcessError:
                if attempt==99:raise
                time.sleep(0.1)
        port=docker("port",name,"8200/tcp").splitlines()[0]
        if not port.startswith("127.0.0.1:"):raise AssertionError("test port must be loopback only")
        bao("secrets","enable","-path=connector-kv","kv-v2")
        for key_id,byte in [("canvas-key-one",37),("canvas-key-two",41)]:
            bao("kv","put","-mount=connector-kv","-cas=0","canvas-envelope/keys/"+key_id,"key_base64="+base64.b64encode(bytes([byte])*32).decode())
        bao("kv","put","-mount=connector-kv","-cas=0","canvas-envelope/current","id=canvas-key-one")
        policy='path "connector-kv/data/canvas-envelope/current" { capabilities=["read"] }\npath "connector-kv/data/canvas-envelope/keys/*" { capabilities=["read"] }\n'
        bao("policy","write","canvas-key-reader","-",input=policy)
        token=json.loads(bao("token","create","-policy=canvas-key-reader","-no-default-policy","-format=json"))["auth"]["client_token"]
        ca=docker("exec",name,"cat","/tmp/canvas-tls/vault-ca.pem")
        with tempfile.TemporaryDirectory(prefix="canvas-key-contract-") as directory:
            path=Path(directory).resolve()
            if path.parent!=Path(tempfile.gettempdir()).resolve():raise AssertionError("unexpected test directory")
            fixture=path/"synthetic-fixture.json"
            fixture.write_text(json.dumps({"origin":"https://"+port,"token":token,"ca":ca}),encoding="utf-8")
            def node(stage):subprocess.run(["node",str(ROOT/"test/openbao-key-provider-contract.mjs"),str(fixture),stage],check=True,cwd=ROOT)
            node("initial")
            # Rotate only the pointer repeatedly: immutable key version1 survives
            # beyond the KV default per-record retention of10 pointer versions.
            for version in range(2,15):bao("kv","put","-mount=connector-kv","-cas="+str(version-1),"canvas-envelope/current","id=canvas-key-two")
            node("rotated")
            bao("kv","destroy","-mount=connector-kv","-versions=1","canvas-envelope/keys/canvas-key-one")
            node("destroyed")
            bao("token","revoke",token)
            node("revoked")
        print("OpenBao2.5.2 TLS, read-only path policy, immutable-key retention and revocation contracts passed")
    finally:
        # Remove only this task-owned uniquely named disposable container.
        subprocess.run(["docker","rm","--force",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
if __name__=="__main__":main()
