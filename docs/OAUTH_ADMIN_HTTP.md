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
No concrete Gateway authentication transport is provided in this change: it is
a mandatory deployment dependency, and the endpoint cannot be activated safely
with a permissive or synthetic authenticator.

Requests additionally require the configured same-origin Origin header. The
handler emits no CORS permissions. Authorization failures occur before reading
the form or calling the lifecycle. Only the resulting Canvas authorization URL
is returned, with no-store/no-referrer headers. It contains OAuth state and must
not be logged or cached. Error responses exclude internal provider/storage
details. The enclosing server/proxy must set TLS, header, body-read, authentication
and response deadlines; redact callback/query/body data from logs. Configure a
trusted-ingress rate limiter separately when behind a reverse proxy, since this
handler uses the direct socket address and ignores forwarded-IP headers.

HTTP tests use synthetic authentication. Lifecycle composition tests use
synthetic repository/vault/provider adapters. These are contract tests and do
not establish Gateway authentication, production authorization or live Canvas
qualification. This work does not add any private connector-to-core interface.
