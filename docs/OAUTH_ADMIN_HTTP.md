# Administrator authorization start

`./oauth-admin-http` exposes a server-only Node request handler for
POST `/platforms/{platform}/oauth/start`. It requires an OAuth lifecycle,
an exact HTTPS admin origin, rate limiter and `authenticateAndAuthorize` adapter.
Form fields are `client_id`, `client_secret_ref` and comma-separated
`capabilities`. Tenant fields and plaintext client secrets are rejected. Forms
are bounded to 8 KiB; unknown/duplicate decoded fields and invalid encoding fail.

The authenticator receives the original request and the operation
`{ platformId, action: 'integration-connector:edit' }`. It must validate the
session, CSRF policy and canonical organization permission through the public
Common Gateway, returning `{ organizationId, authorized: true }` only on success.
No request header or body may supply organization authority. Do not implement
this adapter using connector-side membership/role mirrors or private core APIs.
The server-only `./gateway-admin-auth` export implements that adapter against
the existing public Gateway contracts. It forwards only the explicitly named
session cookie to GET `/v1/auth/me`, derives the active organization from its
authenticated response, then loads current permissions from
GET `/v1/organizations/{org_id}/members/me/permissions`. Only the exact
`integration-connector:edit` permission grants access. Roles, owner flags,
wildcards, API-key scopes and caller organization headers never substitute for
that permission. Neither identity nor permissions are cached.

The source contracts were inspected at Marty-ui main `9e098423b`: auth
`http_service.rs` (me/auth_status), organization `rbac_http.rs`
(get_my_permissions), and Gateway `authorization.rs` (OrganizationMembership
allows and permission-route requirements). The permission-read route itself
requires organization:view; missing authority fails closed.

Configure the exact public Gateway HTTPS origin, exact admin origin and actual
session-cookie name. Transport uses a direct verified TLS agent, fixed paths,
64 KiB response bounds, redirect rejection and one total deadline across both
requests. It forwards no other cookies, API keys, caller headers or query data.
Duplicate session cookies/origins are rejected. It never calls private core APIs.
The operator console additionally supplies an optional
`X-Connector-Organization-Intent` UUID. A single canonical value must match the
organization derived from the current Gateway session on every authentication
call, before permission lookup. Missing values preserve existing API behavior;
malformed, duplicate or mismatching values fail closed. This is an intent
precondition, never tenant authority, and is not forwarded to Gateway.
The origin requirement provides the endpoint's same-origin CSRF policy.
Deploy the connector endpoint where the browser's existing session cookie is
available under the established login/reverse-proxy setup; this module does not
broaden cookie domains or invent a cross-origin session-sharing mechanism.

Requests additionally require the configured same-origin Origin header. The
handler emits no CORS permissions. Authorization failures occur before reading
the form or calling the lifecycle. Only the resulting Canvas authorization URL
is returned, with no-store/no-referrer headers. It contains OAuth state and must
not be logged or cached. Error responses exclude internal provider/storage
details. The enclosing server/proxy must set TLS, header, body-read, authentication
and response deadlines; redact callback/query/body data from logs. Configure a
trusted-ingress rate limiter separately when behind a reverse proxy, since this
handler uses the direct socket address and ignores forwarded-IP headers.

HTTP tests include composition with the concrete authenticator against a real
local HTTPS server implementing synthetic Gateway responses. Removing its
permission denies the next request. Lifecycle composition tests use synthetic
repository/vault/provider adapters. These contract tests do not establish a
deployed Gateway session, production authorization or live Canvas qualification.
Actual login/reverse-proxy wiring and deployed negative tests remain required.

## Browser-bound transaction cookie

After canonical Gateway authorization, this handler generates a fresh 256-bit
proof using `createOAuthBrowserBinding()` and passes it to the lifecycle. It
never accepts browser proof as a form field. The lifecycle persists only its
hash. The returned state must occur exactly once in a valid HTTPS Canvas
authorization URL; both lifecycle redirectUri and URL redirect_uri must equal
this admin origin's `/oauth/callback`. Substituted callback hosts or ambiguous
states produce a redacted failure and no cookie.

Successful start sets the per-state __Host cookie from oauth-browser-binding:
Secure, HttpOnly, SameSite=Lax, Path=/, no Domain, ten-minute expiry. The JSON
response remains authorizationUrl only; proof must never enter a URL, JSON,
logs or traces. Cookie/Set-Cookie headers require log redaction too. The callback
requires the proof and the PostgreSQL adapter atomically matches its hash before
state consumption. A different browser cannot complete an attacker-shared URL.

Synthetic composition tests cover the concrete public Gateway authenticator,
HTTP start/callback handlers, actual PostgreSQL repository, encrypted vault and
pinned Canvas HTTPS provider together. They verify permission denial, missing
browser proof, successful custody, replay and credential separation. Tests use
an HTTP browser fixture that manually returns cookies; actual browser cookie
policy, login/proxy session availability, deployment and Canvas remain separate
qualification requirements.
