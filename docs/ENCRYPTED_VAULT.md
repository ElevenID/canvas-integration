# Connector encrypted secret custody

The server-only `./encrypted-vault` adapter implements the OAuth lifecycle's
`metadata`, `put`, `get` and `delete` operations against connector PostgreSQL.
It encrypts each secret with AES-256-GCM, a fresh random 96-bit nonce and a
128-bit authentication tag. The authenticated context includes a format version,
organization, opaque reference, platform, provider, purpose and key version.
Changing those fields or substituting ciphertext causes decryption to fail.

Provide a dedicated connector database pool and an explicit key provider:
`current()` returns `{ id, key }`; `byId(id)` returns that version's 32-byte
Buffer. The provider must use connector-owned external custody such as a
dedicated OpenBao key path. It must enforce caller authorization, rotation and
revocation. The separate OPENBAO_KEY_PROVIDER.md describes a concrete read-only external
provider; no transport, policy or credential is implicitly configured by this vault. Neither encryption keys nor plaintext secrets enter PostgreSQL.
There is no default key, environment lookup, in-memory production fallback or
access to the Marty integration vault or Gateway credentials.

`rotate(organization, reference)` authenticates the old ciphertext, encrypts with
the current key and fresh nonce, and compares the previous key, ciphertext,
nonce, tag and metadata before replacing the row. A concurrent change returns
false; errors remain redacted exceptions. Retain old key versions until all
live secrets and required backups have been migrated and verified. An uncertain
rotation acknowledgment requires rereading the reference, never deleting it.

Tenant identity must come from authenticated connector administration. Metadata
lookup exposes only tenant-scoped non-secret lifecycle metadata. Disabled or
missing records cannot be decrypted. `delete` is tenant-scoped and irreversible;
call it only after definite publication rejection or confirmed provider
revocation. Never delete references following an uncertain connection commit.
An uncertain `put` may leave an orphan encrypted row: retain and reconcile it
using its platform/purpose/creation metadata rather than guessing which live
references may be removed.

Configure verified database TLS, timeouts and least-privilege runtime roles.
Restrict ciphertext reads, writes and key access separately; PUBLIC has no
database access. Database role provisioning, production OpenBao integration,
key inventory/backup procedures and administrator audit events remain deployment
requirements. This adapter does not establish a production vault qualification.

Temporary owned plaintext/key Buffers are cleared after use. JavaScript strings
and cryptographic-library internal copies cannot be guaranteed erased; keep
secrets inside the server process and exclude them from logs, traces and errors.

The PostgreSQL contract runner tests encryption round trips, distinct ciphertext
for repeated plaintext, tenant isolation, authenticated metadata/ciphertext
tampering, disablement, deletion, missing keys and key rotation followed by old
key retirement, using synthetic external key-provider fixtures only.

## Scoped worker access and refresh staging

Workers pass `{platformId,provider:'canvas',purpose}` to `get` and `delete`.
The vault checks that context against the same row it authenticates/decrypts.
Deletion predicates repeat the exact context; a missing row is idempotent and a
disabled row can be cleaned after durable revocation confirmation. Wrong-platform
or wrong-purpose rows cannot be decrypted, sent to Canvas or deleted by workers.

Refresh workers use `stageRefreshResult`, rather than independent `put` calls.
Ciphertext inserts and immutable attempt association commit atomically as
described in POSTGRES_STORAGE.md. No plaintext or encryption key is passed to
PostgreSQL. Lost acknowledgment preserves exact attempt-associated references;
publication consumes those staged references under current fences. Ordinary
`put` and initial-authorization publication retain their separately documented
uncertain-outcome/reconciliation limits; this does not qualify a deployment.
