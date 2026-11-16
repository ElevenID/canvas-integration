#!/usr/bin/env python3
"""Fail on unreviewed runtime modules, dependencies or transport entry points.

This is a regression gate, not a sandbox for malicious JavaScript. Deployment
network isolation and Gateway authorization remain separate requirements.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
IMPORTS = {'bin/probe.mjs': {'../src/gateway-client.mjs', '../src/configuration.mjs'},
 'bin/serve-oauth.mjs': {'../src/oauth-service-config.mjs', '../src/connector-oauth-runtime.mjs'},
 'bin/serve-workers.mjs': {'../src/worker-service-config.mjs','../src/connector-worker-runtime.mjs'},
 'src/browser-denied.mjs': set(),
 'src/canvas-oauth-provider.mjs': {'./canvas-rest-network.mjs', 'node:https'},
 'src/canvas-oauth.mjs': {'./canvas-rest-network.mjs', 'node:crypto', './oauth-browser-binding.mjs'},
 'src/canvas-rest-contract.mjs': set(),
 'src/canvas-rest-network.mjs': {'node:net', './canvas-rest-contract.mjs', 'node:dns/promises'},
 'src/canvas-rest-reader.mjs': {'./canvas-rest-network.mjs', './canvas-rest-contract.mjs', 'node:https'},
 'src/capture-route-contract.mjs': {'./canvas-rest-contract.mjs', './canvas-rest-network.mjs'},
 'src/configuration.mjs': {'node:fs/promises', './gateway-client.mjs'},
 'src/connection-admin.mjs': set(),
 'src/platform-admin.mjs': {'./canvas-rest-network.mjs'},
 'src/oauth-client-contract.mjs': set(),
 'src/oauth-client-admin.mjs': {'./oauth-client-contract.mjs'},
 'src/connector-https-service.mjs': {'node:https', './oauth-admin-http.mjs', './oauth-callback-http.mjs','./oauth-attempt-recovery.mjs','./connection-admin.mjs','./platform-admin.mjs','./oauth-client-admin.mjs'},
 'src/connector-oauth-runtime.mjs': {'./postgres-pool.mjs', './postgres-repository.mjs', './openbao-key-provider.mjs',
   './encrypted-vault.mjs', './canvas-oauth-provider.mjs', './canvas-oauth.mjs', './gateway-admin-auth.mjs',
   './connector-https-service.mjs', './oauth-http-rate-limiter.mjs','./oauth-attempt-recovery.mjs','./connection-admin.mjs','./platform-admin.mjs','./oauth-client-admin.mjs'},
 'src/encrypted-vault.mjs': {'node:crypto','./oauth-client-contract.mjs'},
 'src/connector-worker-runtime.mjs': {'./postgres-pool.mjs','./postgres-repository.mjs','./openbao-key-provider.mjs',
   './encrypted-vault.mjs','./canvas-oauth-provider.mjs','./refresh-worker.mjs','./revocation-worker.mjs',
   './rest-capture.mjs','./observation-outbox.mjs','./observation-submit.mjs','./worker-loop.mjs'},
 'src/file-credentials.mjs': {'./private-file.mjs'},
 'src/private-file.mjs': {'node:fs/promises', 'node:path'},
 'src/private-json.mjs': set(),
 'src/gateway-admin-auth.mjs': {'node:https'},
 'src/gateway-binding-reader.mjs': {'node:https', './gateway-admin-auth.mjs', './private-json.mjs'},
 'src/gateway-client.mjs': {'./operations.mjs', 'node:https'},
 'src/observation-outbox.mjs': {'./observation-submit.mjs'},
 'src/observation-submit.mjs': {'node:https'},
 'src/oauth-admin-http.mjs': {'./oauth-browser-binding.mjs'},
 'src/oauth-browser-binding.mjs': {'node:crypto'},
 'src/oauth-callback-http.mjs': {'./oauth-browser-binding.mjs'},
 'src/oauth-http-rate-limiter.mjs': set(),
 'src/oauth-attempt-recovery.mjs': set(),
 'src/oauth-service-config.mjs': {'node:path', './private-file.mjs', './file-credentials.mjs','./private-json.mjs'},
 'src/worker-service-config.mjs': {'node:path','./private-json.mjs','./private-file.mjs','./file-credentials.mjs'},
 'src/worker-loop.mjs': set(),
 'src/openbao-key-provider.mjs': {'node:https'},
 'src/operations.mjs': set(),
 'src/postgres-pool.mjs': {'pg/lib/client.js', 'pg-pool'},
 'src/postgres-repository.mjs': set(),
 'src/rest-capture.mjs': {'./canvas-rest-reader.mjs', './canvas-rest-contract.mjs', './canvas-rest-network.mjs', './observation-submit.mjs'},
 'src/refresh-worker.mjs': set(),
 'src/revocation-worker.mjs': set()}
IMPORT = re.compile(r"^import\s+[^;]+?\s+from\s+['\"]([^'\"]+)['\"];", re.MULTILINE)
DYNAMIC = re.compile(r"\b(?:eval|require|fetch|WebSocket|XMLHttpRequest)\s*\(|\bimport\s*\(|\bnew\s+Function\b|process\s*\.\s*(?:binding|dlopen)\b")


def audit(root: Path) -> list[str]:
    errors = []
    files = {path.relative_to(root).as_posix(): path for parent in ("src", "bin")
             for path in (root / parent).rglob("*") if path.is_file() or path.is_symlink()}
    if set(files) != set(IMPORTS):
        errors.append("runtime file inventory differs from reviewed boundary")
    for name, path in files.items():
        if path.is_symlink():
            errors.append(f"runtime symlink forbidden: {name}")
            continue
        source = path.read_text(encoding="utf-8")
        if set(IMPORT.findall(source)) != IMPORTS.get(name, set()):
            errors.append(f"unreviewed import: {name}")
        if DYNAMIC.search(source):
            errors.append(f"dynamic code or alternate transport: {name}")
        # New import syntaxes require an explicit review of this gate.
        without_imports = IMPORT.sub("", source)
        if re.search(r"^\s*(?:import\s|export\s+.*\bfrom\s)", without_imports, re.MULTILINE):
            errors.append(f"unreviewed module syntax: {name}")
        if name.startswith(("src/canvas-rest-", "src/canvas-oauth")) and re.search(
            r"X-API-Key|X-Organization-ID|gatewayOrigin|apiKey|process\s*\.\s*env|/internal/", source
        ):
            errors.append(f"core authority in Canvas provider: {name}")
    package = json.loads((root / "package.json").read_text())
    if package.get("dependencies") != {"pg": "8.23.1", "pg-pool": "3.14.0"}:
        errors.append("unreviewed production driver dependencies")
    for field in ("devDependencies", "optionalDependencies", "peerDependencies"):
        if package.get(field):
            errors.append(f"unreviewed package dependencies: {field}")
    lock = json.loads((root / "package-lock.json").read_text())
    # Exact reviewed dependency graph, including registry integrity and optional metadata.
    graph = {k: v for k, v in lock.get("packages", {}).items() if k}
    if hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != "a19f44c0f4c66c2f8ee255126d59d16cddb12e3a29213a306c9cad0af9a5c68d":
        errors.append("lock contains unreviewed external packages")
    if lock.get("packages", {}).get("", {}).get("dependencies") != package.get("dependencies"):
        errors.append("root lock dependencies differ from reviewed package")
    expected = {'.': './src/gateway-client.mjs',
     './canvas-oauth': './src/canvas-oauth.mjs',
     './canvas-oauth-provider': './src/canvas-oauth-provider.mjs',
     './canvas-rest': './src/canvas-rest-reader.mjs',
     './configuration': './src/configuration.mjs',
     './connector-https-service': './src/connector-https-service.mjs',
     './connector-oauth-runtime': './src/connector-oauth-runtime.mjs',
     './connector-worker-runtime': './src/connector-worker-runtime.mjs',
     './encrypted-vault': './src/encrypted-vault.mjs',
     './file-credentials': './src/file-credentials.mjs',
     './gateway-admin-auth': './src/gateway-admin-auth.mjs',
     './observation-outbox': './src/observation-outbox.mjs',
     './observations': './src/observation-submit.mjs',
     './oauth-admin-http': './src/oauth-admin-http.mjs',
     './oauth-browser-binding': './src/oauth-browser-binding.mjs',
     './oauth-callback-http': './src/oauth-callback-http.mjs',
     './oauth-http-rate-limiter': './src/oauth-http-rate-limiter.mjs',
     './oauth-service-config': './src/oauth-service-config.mjs',
     './worker-service-config': './src/worker-service-config.mjs',
     './openbao-key-provider': './src/openbao-key-provider.mjs',
     './postgres-pool': './src/postgres-pool.mjs',
     './postgres-repository': './src/postgres-repository.mjs',
     './rest-capture': './src/rest-capture.mjs',
     './refresh-worker': './src/refresh-worker.mjs',
     './revocation-worker': './src/revocation-worker.mjs'}
    if set(package.get("exports", {})) != set(expected):
        errors.append("unexpected package export")
    for name, target in expected.items():
        if package.get("exports", {}).get(name) != {
            "browser": "./src/browser-denied.mjs", "node": target,
            "default": "./src/browser-denied.mjs"}:
            errors.append(f"server-only export boundary changed: {name}")
    service = (root / "src/connector-https-service.mjs").read_text()
    for invariant in ("import { createServer } from 'node:https';", "minVersion: 'TLSv1.2'",
                      "maxHeaderSize: 16384", "hosts[0] !== origin.host", "request.rawHeaders.length > 128",
                      "inFlight.size >= maxConcurrentRequests", "inFlight.add(work)",
                      "await Promise.allSettled([...inFlight])"):
        if invariant not in service:
            errors.append("connector inbound HTTPS boundary invariant missing")
    if len(re.findall(r"from ['\"]node:https['\"]", service)) != 1:
        errors.append("outbound transport forbidden in inbound connector service")
    client = (root / "src/gateway-client.mjs").read_text()
    for invariant in ("rejectUnauthorized: true", "agent: false", "'X-API-Key': apiKey",
                      "'X-Organization-ID': organizationId", "redirect_denied", "operation_not_allowed"):
        if invariant not in client:
            errors.append("Gateway transport invariant missing")
    provider = (root / "src/canvas-rest-reader.mjs").read_text()
    for invariant in ("rejectUnauthorized: true", "agent: false", "method: 'GET'", "resolveAddress(origin",
                      "lookup: pinnedLookup", "'Authorization': `Bearer ${accessToken}`", "redirect_denied",
                      "controller.abort()", "prepareRequirement(input)"):
        if invariant not in provider:
            errors.append("Canvas provider transport invariant missing")
    oauth = (root / "src/canvas-oauth-provider.mjs").read_text()
    for invariant in ("rejectUnauthorized: true", "agent: false", "method:", "POST",
                      "resolveAddress(origin", "lookup: pinnedLookup",
                      "/login/oauth2/token", "redirect_denied", "controller.abort()",
                      "grant_type: grantType"):
        if invariant not in oauth:
            errors.append("Canvas OAuth transport invariant missing")
    lifecycle = (root / "src/canvas-oauth.mjs").read_text()
    for invariant in ("browserBindingHash", "matchesOAuthBrowserBindingHash", "createHash", "stateHash: stateHash(state)", "repository.consumeAuthorizationAttempt(stateHash(input.state)",
                      "cancelAuthorization", "clientSecretRef", "accessTokenRef",
                      "publishAuthorizationConnection", "stageAuthorizationResult", "beginAuthorizationExchange", "completionLocation"):
        if invariant not in lifecycle:
            errors.append("Canvas OAuth lifecycle invariant missing")
    if re.search(r"vault\s*\.\s*(put|delete)\s*\(|provider\s*\.\s*revoke\s*\(|repository\s*\.\s*publishConnection\s*\(", lifecycle):
        errors.append("OAuth callback bypasses atomic custody or discards uncertain credentials")
    capture = (root / "src/rest-capture.mjs").read_text()
    for invariant in ("canvas_connector.schedule_rest_capture", "canvas_connector.complete_rest_capture",
                      "job?.organizationId!==organizationId", "job.producerRef!==producerRef",
                      "purpose:'oauth_access_token'", "effective_time_source=source", "createCanvasRestReader",
                      "job.effective_time_policy!=='as_of_read'", "job.attempts>=maxAttempts"):
        if invariant not in capture:
            errors.append("REST capture invariant missing")
    if re.search(r"process\s*\.\s*env|X-API-Key|getApiKey|/internal/|VERIFIED|DELETE FROM", capture):
        errors.append("unreviewed REST capture credential/authority/retention")
    outbox = (root / "src/observation-outbox.mjs").read_text()
    for invariant in ("canvas_connector.enqueue_observation", "canvas_connector.seal_observation", "bodyFor(item)",
                      "item?.organizationId!==organizationId", "item.producerRef!==producerRef",
                      "receipt=undefined", "submitter.submit(item.body)", "item.attempts>=maxAttempts"):
        if invariant not in outbox:
            errors.append("Observation outbox invariant missing")
    if re.search(r"process\s*\.\s*env|X-API-Key|/v1/|/internal/|DELETE FROM", outbox):
        errors.append("outbox transport/credential/retention violation")
    observation = (root / "src/observation-submit.mjs").read_text()
    for invariant in ("new URL('/v1/evidence/observations',origin)", "method:'POST'", "agent:false",
                      "rejectUnauthorized:true", "minVersion:'TLSv1.2'", "apiKeyProvider.getApiKey",
                      "'Idempotency-Key':envelope.observation_id", "'X-API-Key':apiKey",
                      "encodeExternalObservation(envelope)!==body", "controller.signal.aborted", "size>2048"):
        if invariant not in observation:
            errors.append("Observation Gateway transport invariant missing")
    if re.search(r"process\s*\.\s*env|X-Organization-ID|X-User-ID|/internal/|/canvas/|Bearer ", observation):
        errors.append("unreviewed observation credential/authority/route")
    driver = (root / "src/postgres-pool.mjs").read_text()
    workers = (root / "src/connector-worker-runtime.mjs").read_text()
    if re.search(r"process\s*\.\s*env|/internal/|DATABASE_URL|ISSUANCE_|SIGNING_KEYS_", workers):
        errors.append("unreviewed worker ambient credentials or core authority")
    for invariant in ("rejectUnauthorized:true", "minVersion:'TLSv1.2'", "queryMode:'extended'",
                      "client.getTransactionStatus()!=='I'", "client?.release(failed)",
                      "this.connection.stream.destroy()", "credentialProvider.getPassword", "active>=maxConnections", "replication:'false'"):
        if invariant not in driver:
            errors.append("PostgreSQL transport invariant missing")
    if re.search(r"process\s*\.\s*env|connectionString|pg-native|/internal/", driver):
        errors.append("unreviewed PostgreSQL credential or transport fallback")
    key_provider = (root / "src/openbao-key-provider.mjs").read_text()
    for invariant in ("rejectUnauthorized:true", "agent:false", "method:'GET'", "'X-Vault-Token':token",
                      "?version=1", "metadata.destroyed!==false", "controller.abort()", "keyPath}/current"):
        if invariant not in key_provider:
            errors.append("OpenBao key-provider transport/custody invariant missing")
    for workflow in (root / ".github/workflows").glob("*.yml"):
        text = workflow.read_text()
        for action in re.findall(r"uses:\s*([^\s]+)", text):
            if not re.fullmatch(r"[A-Za-z0-9_./-]+@[0-9a-f]{40}", action):
                errors.append("workflow action is not commit-pinned")
        if "pull_request_target" in text or re.search(r"secrets\s*\.", text):
            errors.append("unreviewed privileged workflow")
    return errors


if __name__ == "__main__":
    violations = audit(ROOT)
    if violations:
        print("Boundary check failed:\n" + "\n".join(violations), file=sys.stderr)
        sys.exit(1)
    print("Boundary check passed: reviewed runtime modules, separate Gateway/Canvas HTTPS owners, exact pinned PostgreSQL dependency graph.")
