# Connector-owned OpenBao envelope keys

The server-only `./openbao-key-provider` export implements encrypted-vault's
`current()` / `byId(id)` key-provider interface against a dedicated connector
OpenBao KV v2 path. It is read-only. It never initializes a server, creates keys,
changes policies, writes/deletes data, or retrieves keys from Marty or Gateway.
Only the OpenBao token is sent to the configured OpenBao HTTPS origin. Neither
Canvas bearer credentials nor ElevenID organization API keys belong here.

Pass explicit `openbaoOrigin`, KV `mount`, `keyPath`, `keyNamespace`, and an
external `tokenProvider.getToken({signal})`. Provide a trusted CA when needed.
No token, encryption key, environment lookup, key cache or fallback is supplied.
The token provider must obtain a fresh valid least-privilege workload/agent token;
renewal and role provisioning are deployment responsibilities. Errors contain
no upstream response, token, key material or configuration values.

## Immutable layout and rotation

The dedicated path contains:

- `current`: JSON data exactly `{ "id": "<namespace>-<unique-key-id>" }`.
- `keys/<id>`: JSON data exactly `{ "key_base64": "<canonical base64 of 32 random bytes>" }`.

The current pointer is read at its latest KV version. Each immutable key record
is read explicitly at version1 and validated as live/non-destroyed. Never reuse
or overwrite an ID. A provisioning role should have create-only access to key
records and use CAS0. Runtime has only read access to the pointer and its keys.
A separately authorized operator creates the new key under a new ID first,
then CAS-updates current. A concurrent reader may finish with the previous key,
which remains a valid historical ID. Existing encrypted-vault rotation reencrypts
rows with fresh nonce/AAD and a ciphertext compare-and-set.

Keep old key records until all affected database rows AND retained backups have
been migrated and verified. Do not impose automatic deletion on these records.
Separate key paths prevent repeated pointer rotation pruning historical keys
through KV's per-record version retention. Explicit key destruction or token
revocation fails closed; there is no stale-key fallback. A stable namespace and
path are part of custody configuration; changing them requires a planned migration.

Example runtime read-only policy for an operator-chosen mount/path:

```hcl
path "connector-kv/data/canvas-envelope/current" { capabilities = ["read"] }
path "connector-kv/data/canvas-envelope/keys/*" { capabilities = ["read"] }
```

Do not grant this runtime token create/update/patch/delete/destroy/list, metadata,
mount, policy or token-administration capabilities, nor access to core secrets.
Provisioner/rotation/retirement roles and audited approval are separate. Limit
agent/file-token access to the connector server; do not broaden browser cookies
or expose this token through the public application.

## Transport and memory boundary

Requests use verified TLS1.2+, a direct nonpersistent agent, fixed bounded KV
paths, namespace-constrained IDs, redirect denial and no automatic retry. Each
operation has one total deadline including credential lookup and both current
pointer/key reads. A late credential lookup cannot initiate a request after the
deadline. Responses are bounded to8KiB and strict UTF-8 JSON with required live
KV metadata and canonical 32-byte key encoding. No write method or user-controlled
URL/path is exposed.

Raw envelope keys are returned only to the connector process; PostgreSQL stores
ciphertext, metadata and opaque key IDs. Callers should clear owned key Buffers.
The existing vault copies and clears its temporary buffers without mutating
provider-owned buffers. JavaScript strings/library copies cannot be guaranteed
erased; forbid secrets in application/proxy logs and traces.

## Evidence and limits

The implementation follows the official [OpenBao2.5 KV v2 API](https://openbao.org/docs/2.5.x/api/secret/kv/kv-v2/).
The local/CI contract pins OpenBao2.5.2 by immutable image digest, uses generated
TLS and synthetic keys in an ephemeral server bound only to a random loopback
port, and removes its task-owned container. It verifies a real read-only policy,
initial/current and historical reads after more than10 pointer updates, explicit
key destruction, token revocation, and denied writes/out-of-path/admin reads.
It does not use an existing service or AWS resources. The dev server/root token
are test bootstrap only and must never be a deployment configuration.

Run `python3 scripts/test_openbao_key_provider.py` with Docker and Node installed.
Unit HTTPS and mutation tests additionally cover TLS/redirect/response/deadline
failures, invalid IDs/paths, no cached fallback, and credential isolation.

This supplies a concrete external key reader, not a qualified managed OpenBao
installation. Production unseal/storage/backup/agent roles, token renewal,
network policy, rootless deployment and full server composition,
retirement audit and end-to-end qualification remain required before activation.

The actual verified-TLS PostgreSQL driver and encrypted-vault composition now has a separate disposable contract in `scripts/test_postgres_pool.py`; see [POSTGRES_DRIVER.md](POSTGRES_DRIVER.md). This does not qualify a deployed server or core integration.
