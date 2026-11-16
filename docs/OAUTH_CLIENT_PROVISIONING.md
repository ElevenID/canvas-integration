# OAuth client provisioning

The connector HTTPS service provisions Canvas OAuth application credentials under
its own encrypted custody. Browser administration uses the existing session and
fresh public Common Gateway `integration-connector:edit` permission. Gateway sees
only its session/permission requests; the client secret goes to the connector TLS
endpoint and later to Canvas's pinned token endpoint. It is never sent to Core,
stored as plaintext, returned in a response or included in diagnostic errors.

| POST route | Form fields | Result |
|---|---|---|
| `/platforms/{id}/oauth/client/inspect` | Empty body | Current version-matched client ID/reference or null |
| `/platforms/{id}/oauth/client/receipt` | `operation_id` | Original operation receipt or null |
| `/platforms/{id}/oauth/client/provision` | `operation_id`, `expected_version`, `client_id`, `client_secret` | Atomic encrypted credential/configuration receipt |

Provisioning requires an enabled, unarchived platform at the exact version with no
connection, incomplete revocation, live refresh claim or uncertain refresh/initial
exchange. Create the platform disabled, enable it, then provision against the new
version. Provisioning advances that version again. Existing pending authorization
snapshots are invalidated; live or uncertain provider work must be resolved first.
The credential record and its AES-GCM ciphertext are scoped to that tenant,
platform, provider, purpose, reference and envelope-key version.

Requests require one exact same-origin header and form Content-Type, strict UTF-8,
no unknown/duplicate decoded fields and the distributed rate budget. Bodies are
bounded to65536 bytes for percent-encoded secrets. Client IDs are nonempty,
trimmed and at most512 JavaScript code units; secrets are nonempty and at most4096
code units/16384 UTF-8 bytes. Both reject control characters and malformed Unicode.
The original secret is preserved without trimming or normalization. Actor and
tenant come only from Gateway, with another check after body parsing before any
encryption or mutation. HTTP request bodies and JavaScript strings cannot provide
a secure-memory erasure guarantee; do not retain or log them.

The vault selects one external envelope-key version, derives a separate receipt
HMAC key with a fixed domain, and authenticates the exact operation metadata plus
secret bytes. It encrypts the secret with authenticated scope metadata. One SQL
function locks current platform state and atomically inserts ciphertext, updates
the current client configuration, advances the version and writes immutable actor
and operation metadata. No provider request happens in that transaction.

Persist the operation ID and intent before submission. On a lost response, read
that receipt. No automatic write retry or new operation ID is generated. A retry
of the same operation uses the original receipt key version to compare the keyed
secret digest in constant time; another secret or metadata conflicts. Concurrent
requests serialize and retain one ciphertext. A concurrent key rotation can
produce a conflict; receipt inspection preserves the original committed result.
Returning an old receipt does not reactivate or replace later configuration.

Responses contain public client ID, opaque client-secret reference, version and
operation/actor/platform metadata. They contain no secret bytes, ciphertext, key
material or keyed digest. Reference use remains tenant/platform/purpose scoped.
Metadata receipt lookup does not require the old envelope key. Secret-bearing
replay and decryption do: immutable audit digests retain their original key ID even
after the ciphertext is rotated to another key. Retain every key version required
by token/credential rows, audit digests and backups until reviewed retention and
disposition are complete. Retiring an audit key makes secret-bearing replay fail
closed while leaving metadata receipt lookup available.

Production `/platforms/{id}/oauth/start` now accepts `capabilities` alone and loads
the current configured client for the exact platform version. Supplying both
legacy client fields additionally requires an exact match; substitution fails.
The production runtime hardcodes configured-client mode and exposes no switch in
service configuration. The lower-level lifecycle library still supports explicit
trusted server embedding; production HTTP does not fall back to that manual mode.
Existing browser proof, one-time state, exchange admission and custody fences
continue through callback and token publication.

Install owner migrations001–010. HTTP needs selected current-client configuration
read/insert/update rights, immutable provisioning-audit SELECT/INSERT and EXECUTE
on the atomic provision function. It gains no secret deletion or worker-completion
right. The provisioning audit guard joins the existing startup trigger checks.
Runtime performs no migration or privilege grant. Actual role ownership/membership,
schema provenance, deployment, agent/TLS/key retention and provider-grant behavior
still need production qualification. Operator UI, unknown-outcome resolution,
retention and actual deployed Core Gateway-to-OB3/wallet/network qualification
remain open.
