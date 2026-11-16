#!/usr/bin/env python3
"""Fail on unreviewed runtime modules, dependencies or transport entry points.

This is a regression gate, not a sandbox for malicious JavaScript. Deployment
network isolation and Gateway authorization remain separate requirements.
"""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
IMPORTS = {
    "src/oauth-callback-http.mjs": set(),
    "src/operations.mjs": set(),
    "src/browser-denied.mjs": set(),
    "src/gateway-client.mjs": {"node:https", "./operations.mjs"},
    "src/configuration.mjs": {"node:fs/promises", "./gateway-client.mjs"},
    "bin/probe.mjs": {"../src/gateway-client.mjs", "../src/configuration.mjs"},
    "src/canvas-rest-contract.mjs": set(),
    "src/canvas-rest-network.mjs": {"node:dns/promises", "node:net", "./canvas-rest-contract.mjs"},
    "src/canvas-rest-reader.mjs": {"node:https", "./canvas-rest-contract.mjs", "./canvas-rest-network.mjs"},
    "src/canvas-oauth.mjs": {"node:crypto", "./canvas-rest-network.mjs"},
    "src/canvas-oauth-provider.mjs": {"node:https", "./canvas-rest-network.mjs"},
}
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
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if package.get(field):
            errors.append(f"unreviewed package dependencies: {field}")
    lock = json.loads((root / "package-lock.json").read_text())
    if set(lock.get("packages", {})) != {""}:
        errors.append("lock contains unreviewed external packages")
    expected = {".": "./src/gateway-client.mjs", "./configuration": "./src/configuration.mjs",
                "./canvas-rest": "./src/canvas-rest-reader.mjs",
                "./canvas-oauth": "./src/canvas-oauth.mjs",
                "./canvas-oauth-provider": "./src/canvas-oauth-provider.mjs",
                "./oauth-callback-http": "./src/oauth-callback-http.mjs"}
    if set(package.get("exports", {})) != set(expected):
        errors.append("unexpected package export")
    for name, target in expected.items():
        if package.get("exports", {}).get(name) != {
            "browser": "./src/browser-denied.mjs", "node": target,
            "default": "./src/browser-denied.mjs"}:
            errors.append(f"server-only export boundary changed: {name}")
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
    for invariant in ("createHash", "stateHash: stateHash(state)", "repository.consumeAuthorization(stateHash(input.state)",
                      "cancelAuthorization", "clientSecretRef", "accessTokenRef",
                      "publishConnection", "completionLocation"):
        if invariant not in lifecycle:
            errors.append("Canvas OAuth lifecycle invariant missing")
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
    print("Boundary check passed: eleven runtime modules, separate Gateway/Canvas HTTPS owners, no external dependencies.")
