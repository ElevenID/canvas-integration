# Initial OAuth exchange custody

The initial callback still uses the legacy consumer and independent vault writes.
Its migration to the attempt adapters below is required before this recovery gap
is closed. These adapters add no HTTP route, worker, deployment or automatic retry.

The connector schema owner applies `schema/005_initial_oauth_custody.sql` after
`001_oauth_storage.sql`. The other installed connector migrations remain required
for their respective adapters. HTTP startup performs no DDL. All new functions
use caller privileges; PUBLIC receives no table or function access. Production
role provisioning and exact named-role qualification remain separate work.

`consumeAuthorizationAttempt(hash, browserBindingHash)` atomically consumes the
short-lived browser-bound authorization and persists its configuration snapshot.
The attempt contains no authorization code, raw state, browser proof, client
secret, token or provider response. A consumed attempt alone does not authorize
an exchange: `beginAuthorizationExchange` must commit successfully first.

Beginning checks the current enabled platform revision/origin, pending
authorization, enabled client-secret metadata and absence of a connection or
unresolved exchange. It transitions exactly once. A lost acknowledgment leaves
the durable state available for inspection; it never authorizes calling Canvas
again. A process crash after beginning leaves an unresolved exchange. A later
authorization cannot bypass it.

`stageAuthorizationResult` encrypts the access token and optional refresh token
before a single autocommitted database function inserts both ciphertexts and
associates their exact references with the attempt. Either all commit or none
commit. A lost reply cannot leave an unassociated ciphertext row. An exact SQL
replay is checked against the retained ciphertext, metadata and expiry; a fresh
vault call generates different references and is rejected after staging.

Custody remains possible after disablement, configuration change, expiry or a
reconciliation transition. Such changes must not discard credentials that
Canvas may already have issued. Normal publication requires a staged attempt,
current configuration and pending authorization, enabled scoped secrets,
unexpired tokens when an expiry is known, and no conflicting connection. The
connection and published attempt commit together. Repeating publication does
not reopen or replace a connection.

The internal tenant/platform/hash-scoped `authorizationAttempt` snapshot can
identify committed references after a lost reply. It exports no ciphertext or
plaintext and is not an operator authorization API. Recovery UI, audited
operator disposition, revocation/retention, process-crash detection and migration
of the actual callback are unfinished. Do not expire or delete unresolved
attempts or their secrets automatically. The active-exchange index deliberately
blocks another exchange until that uncertainty has been resolved.

The disposable PostgreSQL contracts exercise wrong-browser/tenant denial,
eight consumers and eight begin calls, nullable expiry/refresh, atomic rollback
on the second ciphertext insert, lost consumption/staging/publication replies,
exact SQL replay, conflicting staging, key failure, and configuration,
authorization, secret and expiry publication fences. They run through the psql
bridge and the verified-TLS production driver with a real OpenBao key provider.
The broad synthetic fixture role is not production least-privilege evidence.

All state remains connector-owned. No core database, private Marty service,
authority mirror, KMS signer or issuance integration is added. The public Common
Gateway remains the sole connector-to-Marty integration boundary.
