# Connector PostgreSQL transport

`./postgres-pool` owns the production JavaScript PostgreSQL transport for the
connector-owned database. It never contacts a Marty database or private service.
The public Gateway remains the sole connector-to-Marty integration point.

```js
import { createConnectorPostgresPool } from '@elevenid/canvas-integration/postgres-pool';
import { createPostgresRepository } from '@elevenid/canvas-integration/postgres-repository';
import { createEncryptedVault } from '@elevenid/canvas-integration/encrypted-vault';

const pool = createConnectorPostgresPool({
  host: connectorDatabaseHost,
  port: connectorDatabasePort,
  database: connectorDatabaseName,
  user: connectorRuntimeRole,
  ca: connectorDatabaseCaPem,
  credentialProvider: connectorDatabaseCredentialProvider,
});
const repository = createPostgresRepository(pool);
const secretVault = createEncryptedVault({ pool, keyProvider: connectorOpenBaoKeyProvider });
// Await workers/HTTP shutdown before closing their shared transport.
// await pool.close();
```

The bootstrap must supply `getPassword({signal})` from connector-owned credential
custody. A fresh password is requested per new physical connection. No password,
URI or host is read from environment variables or a default configuration.
Missing/empty/invalid credentials fail closed; there is no pgpass fallback.
Database credentials belong only to this connector database. They must never be
Canvas tokens, organization Gateway API keys or core service credentials.

The exact JavaScript driver is `pg@8.23.1` with `pg-pool@3.14.0`, locked including
registry integrity. The direct pure-JS Client import bypasses pg's ambient native
selector. Explicit connection parameters override libpq environment defaults.
TLS verifies the supplied CA and host with TLS 1.2 minimum; socket paths,
connection strings, SSL overrides and unreviewed configuration fields are denied.
No custom certificate checker, plaintext transport or optional runtime transport
is exposed. Use `npm ci --ignore-scripts --omit=optional --no-audit --no-fund`.

Only `query(text,values)` and idempotent `close()` are exposed. Each statement uses
extended protocol and must begin with SELECT/INSERT/UPDATE/DELETE. Stacked
statements are rejected by PostgreSQL; transaction-control and setup commands
are not accepted. The driver verifies idle transaction status before and after
each successful query, so repository state consumption commits before provider
exchange. Only trusted repository/vault SQL may call this adapter: it is not a
public SQL endpoint or a parser/sandbox for arbitrary SQL functions.

Default limits: four concurrent operations, five-second connection/credential
acquisition, ten-second query read deadline, an eight-second server statement
timeout and five-second lock timeout. Configuration permits 1?16 connections and
100?30,000ms connect/query deadlines. Excess operations fail immediately rather
than growing an unbounded queue. Idle connections expire after ten seconds;
connection lifetime is at most five minutes. Credential/TLS failures explicitly
close the socket, including cases where upstream pool error handling forgets it.
Failed queries destroy their physical client; no automatic query or write retry
occurs. Active queries remain bounded during orderly close.

All errors have only `connector_database_unavailable`, with no raw SQL, server
error/cause or credential. An error may mean a write committed but its reply was
lost. Callers must preserve token references and reconcile; never infer rollback
or retry a provider exchange from this error. This adapter adds no reconciliation
API or transactional DDL/role provisioning.

## Actual contract and remaining qualification

`python3 scripts/test_postgres_pool.py` runs the real Node driver against a
uniquely named, pinned PostgreSQL 16 container with verified TLS and a non-owner,
non-superuser connector role. It composes the actual encrypted vault with a
separate pinned OpenBao 2.5.2 HTTPS server and read-only path-scoped token.
Synthetic fixtures are loopback-only and removed in `finally`; each Node stage
has a 30-second watchdog. No existing database/configuration is consumed.

The contract checks typed parameter round-trips and SQL-injection literals,
verified TLS and current runtime role, cross-schema denial, stacked SQL and BEGIN
rejection, actual repository consumption with eight concurrent callers and one
winner, wrong browser-proof rejection, ciphertext-only database custody, scoped
secret reads, key rotation preserving historical decryptability, revoked-key
read/write denial without deleting ciphertext, certificate/hostname/password
rejection, hanging credential lookup, query timeout/recovery, bounded overload,
hostile libpq defaults, idempotent shutdown and database outage. This is local
composition evidence, not a deployed Canvas-to-Gateway-to-OB3 qualification.

Still required: deployment credential acquisition/rotation; reviewed per-worker
least-privilege role provisioning and migrations; durable initial-exchange
uncertainty/reconciliation; full HTTP server/token-agent/worker scheduling and
shutdown composition; deployed network-denial/outage/unknown-commit tests;
provider functionality and cross-repository retirement. The fixture role has
combined connector table/function access solely to exercise both adapters; it
is not a production least-privilege grant template.

Driver behavior was checked against the official [Client API](https://node-postgres.com/apis/client)
and [Pool API](https://node-postgres.com/apis/pool), plus the exact installed
8.23.1 source. The exact lock graph remains a review gate for dependency updates.
