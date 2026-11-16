# OAuth runtime composition

`./connector-oauth-runtime` composes the actual connector PostgreSQL transport,
repository, encrypted vault, read-only OpenBao key provider, Canvas OAuth provider,
lifecycle, public Gateway session authenticator, database HTTP budget and HTTPS
listener. It exposes only `listen()` and `close()`. Capture, delivery, refresh and
revocation worker scheduling remain separate work.

```js
import { createConnectorOAuthRuntime } from '@elevenid/canvas-integration/connector-oauth-runtime';
const runtime = await createConnectorOAuthRuntime({
  database: { host: 'connector-db.example.org', port: 5432,
    database: 'canvas_connector', user: 'canvas_oauth_http',
    ca: connectorDatabaseCa, credentialProvider: connectorDatabaseCredentialProvider },
  keyCustody: { openbaoOrigin: 'https://connector-vault.example.org',
    mount: 'connector-kv', keyPath: 'canvas-envelope', keyNamespace: 'canvas',
    tokenProvider: connectorVaultTokenProvider, ca: connectorVaultCa },
  canvas: { timeoutMs: 15000 },
  gatewayAuthentication: { gatewayOrigin: 'https://gateway.example.org',
    sessionCookieName: '__Host-marty_session' },
  http: { publicOrigin: 'https://canvas-connector.example.org',
    completionUrl: 'https://canvas-connector.example.org/complete',
    tls: { key: connectorTlsKey, cert: connectorTlsCertificateChain },
    host: '0.0.0.0', port: 8443, maxConcurrentRequests: 4 },
});
await runtime.listen();
// Keep credential agents alive until pending operations have finished.
await runtime.close();
```

Bootstrap supplies `getPassword({signal})` for the connector database and
`getToken({signal})` for connector envelope-key custody. They are never substituted
for each other or sent to Canvas or Marty. No environment/file credentials or
plaintext fallback are loaded here. Agent renewal, file loading and TLS rotation
remain deployment work. There are no replacement repository, vault, provider,
HTTP-authentication or outbound-transport hooks. Platform/client-secret provisioning
remains an owner/operator task.

Before listening, the runtime probes database adapter privileges and budget policy,
then reads the current OpenBao envelope key and clears its probe buffer. It performs
no DDL, grants, token exchange or authorization writes. Startup failures close the
instance with a redacted error; construct a new instance after fixing the cause.
These probes do not attest schema provenance, ownership or production role approval.
Gateway session and current permission are checked per administrative request.

Shutdown stops HTTP admission, waits startup probes and actual handlers, then
closes the private pool. Client disconnect does not cancel an exchange or prove
rollback. No authorization-code exchange is retried. Adapter deadlines remain
bounded; workers and credential-agent lifetimes belong to the embedding process.

## Shared ingress budget

The connector schema owner installs `schema/004_oauth_http_limit.sql` after the
earlier connector migrations. Runtime installs nothing. One row and an invoker
function share a ceiling across all replicas, clients, organizations and OAuth
routes: default 60 requests/minute, owner-configurable to 1–1000 requests and a
1000–60000ms window. The function locks the row before reading the database clock.
Backward clock movement denies until that stored window is reached. Unknown
database results fail closed and may consume quota; no automatic retry occurs.

No addresses or attacker-selected keys are retained. This global ceiling provides
no per-client fairness; an untrusted caller can exhaust it. Deployment needs
ingress abuse controls and an aggregate ceiling chosen for its traffic. The
counter role can update hits/window directly; policy columns remain owner-managed.
This is not a boundary against compromised runtime SQL. Installation revokes PUBLIC
table/function privileges.

## Constrained role and qualification

The real contract's non-owner HTTP role has platform SELECT and `UPDATE(id)` for
row locks; SELECT/INSERT/DELETE on secrets and authorizations;
SELECT/INSERT/UPDATE on OAuth status and connections; SELECT on the budget and
UPDATE only on its hits/window; and required function EXECUTE privileges.
Preflight rejects the role without any platform update-column grant. The identity
trigger rejects changing its ID. Platform definitions, deletion, unrelated refresh
state and schema CREATE remain denied. A no-op ID update can still increment the
platform revision. This is trusted connector code, not a public SQL interface;
fixture grants do not approve production ownership, memberships or provisioning.

`python3 scripts/test_postgres_pool.py` runs actual verified-TLS PostgreSQL,
OpenBao, encrypted vault and HTTPS runtime with synthetic Canvas and
Gateway-protocol peers. It checks concurrent quota calls and clock movement,
constrained-role rejection and successful OAuth, browser proof, token destinations,
ciphertext publication after disconnect, shutdown waiting, replay without another
exchange, revoked permission, quota before Gateway calls, missing policy and
database/key custody failures. Fixtures never consume an existing database.

Production credential agents, owner migrations/role approval, deployment ingress
and network policy, worker scheduling, operator UI, LTI/AGS/NRPS, initial-exchange
uncertainty recovery and actual Canvas-to-Gateway-to-OB3-wallet qualification remain
unfinished. The public Common Gateway remains the sole connector-to-Marty boundary.
