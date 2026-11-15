# Canvas OAuth provider extraction

## Implemented boundary

The new `./canvas-oauth` module owns the service-level Canvas authorization-code lifecycle. The new `./canvas-oauth-provider` module owns Canvas token-endpoint HTTPS requests. Both are server-only package exports and import no Marty code, Gateway client, core service credential, database driver, or signing capability.

The separation is deliberate:

- Canvas OAuth client secrets and Canvas access/refresh tokens belong in connector-owned secret custody.
- The connector's persistent repository stores only opaque secret references and OAuth lifecycle metadata.
- Canvas Bearer tokens are sent only to the configured Canvas HTTPS origin.
- ElevenID API keys are sent only by the separate Common Gateway client to the public Gateway.
- No Canvas token is sent to the Gateway, and no Gateway API key is sent to Canvas.

## Authorization-code lifecycle

`createCanvasOAuthLifecycle` receives explicit repository, secret-vault and provider adapters. It has no default in-memory or plaintext production fallback.

Starting authorization:
1. Require a server-authenticated organization and platform identifier; browser-supplied organization authority is not accepted by this service boundary.
2. Load the platform from connector-owned configuration and require matching tenant, enabled/non-archived status, HTTPS Canvas origin and a positive configuration version.
3. Reject an existing connection.
4. Validate the client-secret reference against connector-vault metadata (`provider=canvas`, `purpose=oauth_client_secret`, enabled and same organization).
5. Normalize the supported capability allowlist and derive the exact Canvas OAuth scopes.
6. Generate 256 bits of cryptographic state, store only its SHA-256 hash, and set a ten-minute expiry.
7. Use the fixed connector callback URI `/oauth/callback`; no caller-supplied redirect URI is accepted.
8. Persist authorization state and mark the platform pending with a configuration-version compare-and-set. If the platform changes, cancel the pending state.

Callback:
1. Hash the returned state and atomically consume the matching unexpired authorization exactly once. The repository adapter must implement consume as a transaction/atomic delete-or-mark-consumed operation.
2. Re-read the platform and require the same organization, platform, Canvas origin and configuration version as the stored authorization snapshot.
3. Re-derive capabilities/scopes from the stored allowlist and reject a changed or malformed snapshot.
4. Load the client secret from connector-owned vault custody and exchange the authorization code.
5. Store access and refresh tokens separately in connector-owned secret custody. Persist only opaque references.
6. Publish the connection with a configuration-version compare-and-set, then mark the platform connected with a second compare-and-set.

The completion URL is fixed in server configuration. Callback parameters cannot select a redirect host or inject provider error text into the completion URL. The callback response never contains an authorization code, state or token.

## Canvas token transport

The provider uses a fixed `POST /login/oauth2/token` path and form-encoded authorization-code or refresh-token grants. It:
- requires HTTPS and validates the Canvas origin;
- resolves and validates every DNS answer before connecting;
- pins the connection to the selected vetted address while preserving TLS hostname and certificate verification;
- permits private addresses only when individually allowlisted by operator configuration;
- rejects redirects, metadata endpoints, private/reserved destinations by default and unsupported content encodings;
- enforces TLS 1.2+, response-size bounds and one absolute deadline spanning DNS, TLS, headers and body;
- does not automatically retry token exchanges;
- parses only the expected token fields and returns fixed errors without response-body or credential disclosure.

The optional provider `revoke` method is used only as best-effort cleanup when a connection insert is definitively rejected. A failed/unknown database commit outcome preserves secret references for reconciliation; deleting a token after an uncertain commit could break a connection row that actually committed.

## Required adapter contracts before deployment

The service is not an HTTP server or a production storage adapter. Before deployment, implement and qualify:

- Connector-owned PostgreSQL (or equivalent transactional repository) with unique active connection per organization/platform.
- Atomic, one-time authorization-state consumption and TTL enforcement.
- Atomic configuration-version compare-and-set for pending, connection publication and connected state.
- Idempotent publication/reconciliation for uncertain commit acknowledgments. Never delete token refs until the repository proves the connection did not commit.
- Connector-owned encrypted secret vault with tenant-scoped metadata, access control, rotation and deletion. No Marty integration-secret vault or core database access.
- A server-authenticated admin backend that derives organization/platform authority from the authenticated user session and checks management permissions before calling `start`.
- A public callback HTTP adapter that rejects duplicate query parameters, bounds query/body sizes, accepts only expected fields, redacts query strings from access logs and applies rate limits.
- Refresh leases, token rotation, durable revocation queue, backoff and cleanup workers. The provider exposes a refresh-token exchange, but lifecycle refresh/disconnect workers are not yet implemented.
- Integration acceptance against a synthetic Canvas tenant and connector-owned storage; no real tenant or production OAuth grants were used in this stage.

No public Gateway route, API-key scope, core database migration or Canvas production callback was enabled by this PR. The existing Marty implementation remains in place until the new service, persistence and HTTP adapters are independently qualified.

## Tests

The service tests cover state hashing and one-time consumption, tenant/platform/configuration binding, fixed callback/completion URLs, exact capability-derived scopes, secret-reference-only persistence, token cleanup, uncertain commit reconciliation and post-publication races.

The provider tests use an actual local HTTPS server with temporary certificates. They verify form payloads, redirect rejection, TLS verification, pinned private test addresses, bounded responses and absolute timeouts. These tests do not claim live Canvas compatibility or production secret-vault qualification.
