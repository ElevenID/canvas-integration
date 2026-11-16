# Connector PostgreSQL storage

`schema/001_oauth_storage.sql` is a transactional initial schema for a separate
connector-owned database. It has no dependency on Marty databases or private
service APIs. Organization identifiers are routing labels here; core grants,
application authority and issuance decisions remain behind the public Gateway.

The schema stores platform configuration, hashed OAuth authorization state,
opaque vault references, connection metadata and durable revocation jobs.
The secrets table stores only authenticated encrypted Canvas tokens/client secrets;
plaintext encryption keys and ElevenID API-key secrets never belong in this database.
Canvas origin canonicalization, scope/capability allowlists and secret-reference
metadata validation remain required in the existing service layer.

Platform updates increment a database-enforced version. Connection publication
and rotation lock that platform and require its enabled state, origin and exact
configuration version. A configuration change does not delete token references;
the worker must mark the connection for reauthorization or durable revocation.
Those cleanup transitions remain possible after platform disablement. Update
operations must acquire platform locks before connection locks to avoid lock
inversion. Treat deadlocks/serialization failures as conflicts, not permission
to blindly retry a token exchange or uncertain commit.

Call `canvas_connector.consume_authorization(hash)` inside a committed
transaction before token exchange. It atomically deletes and returns at most
one unexpired state, using the database clock. A rollback restores the state;
therefore never perform provider network operations before this consumption
commits. On an uncertain consumption commit, reconcile rather than exchanging
the code speculatively. Expired rows require bounded periodic cleanup.

One connection per organization/platform is enforced by its primary key.
Publication needs an exact version compare-and-set and reconciliation by opaque
references after an uncertain acknowledgment. Deleting or replacing a connection
must enqueue revocation in the same transaction. Jobs intentionally survive
connection deletion. Workers must use lease IDs and compare-and-set completion;
the schema alone does not execute revocation or refresh tokens.

Use `disconnect(organization, platform)` for atomic connection deletion and
revocation enqueue; a failed enqueue rolls back the deletion. Repeated or
cross-tenant disconnects have no effect. `claim_revocation()` uses SKIP LOCKED
and returns one job with a fresh one-minute lease. Perform the provider call
only after committing that claim. `finish_revocation(id, lease)` and
`retry_revocation(id, lease)` require the exact unexpired lease. Retries apply
exponential backoff capped at one hour. Lease expiry permits reclamation, so
provider revocation must tolerate repeated execution after uncertain outcomes.
Vault cleanup must follow confirmed provider revocation; these functions never
read or delete vault secrets. Provision separate least-privilege worker grants
for these operations rather than granting arbitrary table updates.

PUBLIC receives no schema, table or function access. Deployment must provision
distinct migration, administrator and worker roles with reviewed least-privilege
grants, encrypted transport and connector-only database credentials. No runtime
role provisioning or production migration registration is supplied here.

Run `python3 scripts/test_postgres_storage.py` with local Docker. It creates a
uniquely named PostgreSQL container from an immutable image, exposes no port,
uses synthetic data and removes its own container. Tests cover expiry, replay,
configuration fencing, immutable tenant identity, reference separation, durable
revocation and eight concurrent consumers with exactly one state winner.

The server-only `./postgres-repository` export now maps the existing OAuth
lifecycle repository methods to parameterized statements against this schema.
Supply a dedicated connector-owned PostgreSQL **autocommit pool**, with a
`query(sql, values)` API returning parsed PostgreSQL rows (booleans, float8
numbers and text arrays). Never supply a transaction-bound client: consumption
must commit before the lifecycle starts the provider exchange. There is no
in-memory, environment-based or plaintext fallback. Configure the driver pool
with verified TLS, connection/query deadlines and least-privilege connector
credentials. This module deliberately does not instantiate a database driver.

Publication errors remain exceptions with fixed redacted messages, including
uncertain commit acknowledgments. Only explicit zero-row conflicts return
false; the OAuth lifecycle preserves vault references when publication throws.
The separate oauth_status table tracks pending/connected state without
incrementing platform configuration versions. Repository integration contracts
execute the actual parameterized statements through a test-only psql bridge;
that bridge is not a production driver or transport implementation.

The encrypted vault adapter is documented in ENCRYPTED_VAULT.md. External key-provider
wiring, administrative operations, driver/deployment wiring,
refresh/revocation workers and deployed acceptance tests remain required.
