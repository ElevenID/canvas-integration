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
1. Generate a fresh `createOAuthBrowserBinding()` proof in the authenticated start HTTP handler, pass it as `browserBinding`, and require a server-authenticated organization and platform identifier; browser-supplied organization authority is not accepted by this service boundary.
2. Load the platform from connector-owned configuration and require matching tenant, enabled/non-archived status, HTTPS Canvas origin and a positive configuration version.
3. Reject an existing connection.
4. Validate the client-secret reference against connector-vault metadata (`provider=canvas`, `purpose=oauth_client_secret`, enabled and same organization and platform).
5. Normalize the supported capability allowlist and derive the exact Canvas OAuth scopes.
6. Generate 256 bits of cryptographic state, store only its SHA-256 hash plus `browserBindingHash` (also SHA-256), and set a ten-minute expiry. No plaintext browser proof is persisted.
7. Use the fixed connector callback URI `/oauth/callback`; no caller-supplied redirect URI is accepted.
8. Persist authorization state and mark the platform pending with a configuration-version compare-and-set. If the platform changes, cancel the pending state.

Callback:
1. Require the initiating browser proof from its transaction cookie. Hash the returned state and proof and call `consumeAuthorization(stateHash, now, browserBindingHash)`. The repository MUST match both hashes and expiry atomically before consuming exactly once. A wrong or missing proof must not consume a legitimate transaction. Rows created before browser binding was supported fail closed. The lifecycle additionally checks the returned proof hash before token exchange.
2. Re-read the platform and require the same organization, platform, Canvas origin and configuration version as the stored authorization snapshot.
3. Re-derive capabilities/scopes from the stored allowlist and reject a changed or malformed snapshot.
4. Revalidate client-secret metadata for the exact organization, platform, Canvas provider and OAuth-client-secret purpose, then load it from connector-owned vault custody and exchange the code. A reference from another platform is rejected.
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

## Connector callback HTTP adapter

The server-only `./oauth-callback-http` export provides a Node HTTP request
handler for GET `/oauth/callback`. Supply the OAuth lifecycle, a fixed HTTPS
completion URL without query or fragment, and an explicit rate limiter whose
`consume(remoteAddress)` method returns true only when admitted. Limiter errors
fail closed. Forwarded IP headers are not trusted; deployments behind a proxy
must apply their own authenticated ingress rate limits as well.

The handler bounds the raw request target to 8 KiB, rejects request bodies,
unknown or duplicate decoded query parameters, invalid UTF-8/percent encoding,
and simultaneous code/error results. Completion redirects are restricted to the
configured origin and path with typed result parameters. Responses have empty
bodies, no-store, no-referrer, and closed connections. The module does not log;
server/proxy access logs MUST omit callback query strings. Configure TLS,
header/time limits and ingress rate limits on the enclosing server/proxy.

This adapter is not a deployed server. The administrator start endpoint,
production repository/vault and refresh/revocation workers remain required.

## Browser-bound authorization transaction

The server-only `./oauth-browser-binding` export generates an independent random
256-bit proof and formats a per-state `__Host-canvas_oauth_<state-hash>` cookie.
After authenticated start succeeds, its HTTP adapter must set the header returned
by `oauthBrowserBindingCookie(state, proof)`, where state is extracted from the
validated lifecycle authorization URL. Never put the proof in that URL, JSON
response, logs or persistent plaintext storage. It is not a caller form field.

Cookies use Secure, HttpOnly, SameSite=Lax, Path=/, no Domain and Max-Age=600.
The host prefix prevents a sibling host setting a Domain cookie. The proof is
sent back only to the connector; Canvas receives only its OAuth state. A separate
cookie name per transaction permits parallel browser attempts. The callback
rejects missing/malformed/duplicate proof cookies and clears the matching cookie
after a lifecycle callback. Server/proxy logs must omit Cookie/Set-Cookie headers
as well as callback query strings. TLS is mandatory in deployment.

The public callback now requires this proof even when called at the service
layer. A stolen or attacker-initiated authorization URL alone cannot bind another
browser's Canvas grant. Production start HTTP and PostgreSQL adapters must adopt
the new input/hash/atomic-consume contract before activation; no state-only
compatibility fallback is provided.
