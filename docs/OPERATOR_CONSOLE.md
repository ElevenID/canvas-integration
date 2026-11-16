# Canvas operator console

Open `/admin` on the connector's configured public HTTPS origin. The console
provides platform create/state changes, encrypted developer-key provisioning,
OAuth authorization, connection inspection/disconnect, capture configuration and
manual allocation/status, LTI registration administration and authorization-attempt
inspection/recovery. Optional runtime adapters determine the available sections.
Automatic capture cadence remains private worker configuration.

The shell and its fixed script/style assets are public and contain no account
data. Controls start disabled until the browser script initializes; forms have a
fixed POST fallback, so a missing script cannot turn a secret into a query string.
Data operations use the existing POST adapters, each with their original Origin,
rate, current Gateway session/permission, tenant, version and receipt checks.
There is no browser-supplied organization, local membership cache or producer key.
No new database grants, migrations or provider transport are required.

`POST /admin/session` accepts only an empty same-origin form and the existing
Gateway session, under the shared request budget and current permission checks.
It returns only the canonical active organization ID. The console displays and
fixes that organization as its intent context. Subsequent API requests carry
`X-Connector-Organization-Intent` only as a precondition: the authenticator compares
one canonical UUID with current Gateway session state before permission lookup
on each authorization/reauthorization, and never forwards or uses it to select a
tenant. Existing clients without this optional guard still derive authority
exclusively from Gateway. A mismatch stops the action; there is no silent context
adoption or write retry. Explicit context reload clears platform selection,
versions, cursors and secret fields while preserving original pending pointers.
This detects switches observed by those checks, not an atomic transaction spanning
Gateway authentication and connector PostgreSQL.

## Public origin and login

Serve the console where the existing Gateway session cookie is available. For a
host-only `__Host-marty_session`, use one existing public HTTPS origin with ingress
routing `/v1/` to the public Common Gateway, `/admin`, `/platforms/`, `/oauth/`,
`/lti/` and `/complete` to the connector, and the established sign-in/application
UI routes to Marty. Reserve these paths explicitly; verify current ingress users
before changing routing. The connector's configured Gateway origin can then be
that same public origin. The sample HTTP service configuration uses this layout.

The ingress must preserve the configured public Host and original security
headers, reject ambiguity, and provide its own aggregate abuse controls. Forwarded
headers do not establish caller identity. Connector-to-Gateway calls still use
verified public HTTPS and only `/v1/` contracts; do not route them to private Core
services. No example activates or modifies a deployment.

Sign in to ElevenID through its existing authentication flow, then open `/admin`.
The console does not issue or copy a session. A cookie for a different hostname
does not become available by configuring another URL. Do not broaden cookie
domains, expose a session to JavaScript, add permissive CORS or share API keys to
work around this. Missing sessions or current permissions fail closed. Verify
actual public-origin, ingress and cookie deployment separately from local tests.

## Operator flow

1. Load platforms, select one and inspect its current version. Create a new
   platform disabled; enable it with the expected current version.
2. Provision the approved Canvas developer key, then inspect the new platform
   version. The secret is cleared from its visible field before the request and
   is never stored in the operation journal or result. Select approved OAuth
   capabilities and continue to Canvas. After the callback, inspect connection
   status; visiting the completion page alone proves no connection outcome.
3. Create/approve the application's producer grant and binding through canonical
   ElevenID administration. Enter the approved source/binding ID, revision and
   exact Canvas resources into a route. The server rechecks the binding through
   Gateway, including current eligible application and resource scope. No
   application/subject authority is copied into connector configuration. Activate
   explicitly, then request a manual capture or configure private worker cadence.
4. Create LTI registrations disabled using an original UUID and approved client,
   deployment and hosted/self-managed trust policy. Inspect their target link URI
   before activation. Launch/provider assertions do not establish Marty identity.

Versions are optimistic concurrency inputs, not permissions. Inspect current
state after a mutation before making another change. API decisions remain current
and canonical even when a previously loaded console or form is stale.

## Unconfirmed operations

Before a durable mutation, the browser preserves a bounded receipt pointer in
this tab's session storage: original organization/form/platform IDs, fixed API and receipt paths, the
original operation UUID, and an authorization ID when recovery needs it. It
contains no intent body, client secret, token, session, application authority or
permission. The browser must be able to persist/read this pointer before sending
a change; invalid/unavailable storage disables mutations while inspections remain
available. Reload keeps pending pointers, but closing the tab may discard them.
Copy the original IDs before closing it.

A matching receipt resolves the pointer. Known adapter rejection statuses remove
it without resubmission. Transport errors, server failures and malformed or
mismatching success responses retain it and block another mutation from that form.
Use **Inspect original receipt**. Missing receipts are snapshots, not proof of
rollback; keep the original ID and reconcile the same intent. Nothing generates
a replacement operation or repeats a write automatically. Tenant switches do not
grant receipt access or move the original operation into the new tenant.

The page uses no inline scripts/styles, third-party assets, HTML result insertion,
arbitrary endpoint input or credential destinations. CSP restricts resources and
connections to the same origin, disallows framing/base changes, and responses are
no-store/no-referrer. These controls do not make browser storage a security boundary
against a compromised same-origin application or browser profile.

## Qualification and remaining work

`python scripts/test_postgres_pool.py --operator-browser-tests /absolute/path/to/playwright/index.mjs`
runs separately installed, lock-pinned Playwright1.59.1 with the actual connector
runtime, constrained PostgreSQL role, encrypted vault and OpenBao. Only synthetic
public Gateway and Canvas HTTPS peers supply canonical/provider responses. The
browser exercises real HttpOnly session cookies on a shared public origin and a
distinct Canvas hostname, OAuth, route/LTI administration and receipt recovery.
It retains the existing physical runtime/worker/outbox tests. Synthetic certificate
exceptions apply only to isolated browser contexts; connector transports verify TLS.

This does not qualify live Gateway authority, deployed ingress/cookie routing,
canonical learner-owned application association, remaining LTI services/AGS/NRPS,
managed credential agents, recovery/retention operations, existing-AWS Canvas to
OB3/wallet acceptance or cross-repository provider retirement. Those remain part
of the full split goal. External observations remain unsigned and unverified.
