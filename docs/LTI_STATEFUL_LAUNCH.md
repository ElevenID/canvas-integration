# Stateful Canvas launch implementation

This branch implements connector-owned protocol state and inbound LTI
login/launch/confirmation/resource handlers. The HTTPS service can explicitly
embed this lifecycle; the production OAuth runtime/CLI does not compose it yet,
so its deployment still has no enabled LTI endpoint. Registration administration,
production runtime/CLI/preflight and actual TLS PostgreSQL-role composition remain
required before this draft can merge. Canonical Gateway learner association and
deployed end-to-end qualification remain full-goal requirements.

Migration012 adds globally identified local registrations and immutable revisions,
expiring launch state, and immutable acceptance receipts in the connector database.
No Core data, permissions, grants, applications or identity authority are copied.
A separate schema owner installs migrations and provisions roles; runtime installs
no schema or grants. The prototype tests grant only selected state/receipt writes,
registration/platform reads and the limited UPDATE capability PostgreSQL requires
for row locking. They deny registration configuration writes, state-identity
rewrites and receipt mutation. Production named roles remain unqualified.
The role remains trusted application SQL: its selected state/receipt INSERT and
phase UPDATE grants do not constitute a tenant or JWT-verification sandbox. The
application verifies provider signatures and Gateway authority; this database
never grants canonical Marty identity, verification or issuance authority.

The lifecycle reads a trusted registration, requires the unsigned login issuer to
match its server-selected profile, generates independent random state, nonce and
browser proof, and stores only state/proof hashes. The nonce is globally unique.
Its authorization redirect has a fixed trusted endpoint, registered client ID,
fixed connector callback, form-post response, and opaque bounded login hints.
The target resource is a fixed path on the connector's configured public origin.
Inputs and server network policy are captured before awaits.

A callback first validates its original token with fresh pinned HTTPS JWKS and
stages minimal protocol claims under the original token hash. Staging authenticates
no browser. Confirmation must prove possession of the original browser proof and
atomically transition the staged state plus immutable receipt. Row locks serialize
platform, registration and state changes in that order. Database clock checks and
both configuration revisions are revalidated after writes; disable/re-enable ABA,
expiry during commit and BEFORE-trigger postimage rewrites cannot turn into an
optimistic acknowledgment. Changed token intents conflict. Matching accepted
retries return the same historical receipt even after configuration closure.

Historical receipts are not active resource authority. Resource lookup separately
requires browser proof, unexpired state/claims and current enabled configuration
revisions. The returned provider subject is a Canvas identifier; it is never a
canonical Marty identity. Gateway authentication and association must be implemented
as a separate flow before any Marty action. No LTI role, email or unsigned
observation can authorize evidence verification, approval, signing or issuance.

`python scripts/test_lti_state.py` uses a uniquely owned, disposable pinned
PostgreSQL16 container with no network. It installs all connector migrations and
tests eight-way receipt replay, competing token intents, wrong proof/token,
configuration ABA, late expiry, trigger corruption, rollback and immutable
receipts. It runs the production repository and lifecycle against that database
through a test-only docker/psql adapter and a real loopback verified-TLS Canvas
JWKS/JWT peer. Lost begin/confirm replies reconcile original IDs and receipts.
This is not production PostgreSQL TLS-driver or browser qualification; those tests
must be added to the existing physical composition before activation.

The HTTP adapter uses a per-state __Host cookie with Secure, HttpOnly,
SameSite=None and Partitioned attributes. Cookie-free iframe launches use the
advertised SSO storage frame (or `_parent`) with exact HTTPS target/response
origin, WindowProxy, response subject, message ID and key checks. The initial
storage failure can attempt the cookie path; confirmation fails closed if neither
proof transport succeeds. No wildcard postMessage target or client success flag
is accepted. Reloads without cookies retrieve the same browser proof again before
server-side current resource checks. No provider subject or raw claims appear in
the resource page.

Handlers require bounded UTF-8 form bodies with strict percent decoding, unique
known fields and unambiguous headers. Limits are8192 URL bytes,20000 login body
bytes,98304 launch bytes and2048 confirmation/resource bytes, with a5second body
deadline. They consume the shared database-wide HTTP budget. Launch posts require
the registered Canvas/SSO Origin; confirmation and resource posts require the exact
connector Origin. A bridge page uses origin-only referrers: no-referrer made real
browser form submissions emit Origin:null. Origin-only policy preserves those
checks while excluding paths, state and proof from referrers; other replies use
no-referrer. Pages have nonce-only scripts, no-store and restrictive CSP.

The browser fixture and `test/lti-browser-contract.mjs` exercised nine Chromium
scenarios against these production handlers/lifecycle/repository and real PG16:
cross-site partitioned cookies; cookie-free storage; incorrect origin, frame,
message ID, key and storage error; missing proof transports; replay after config
closure; and lost acceptance reply recovery. Cookie-free cases suppress Set-Cookie
at the test edge; browser certificates are synthetic and ignored by the isolated
browser context, while the Node provider validates its peer CA. Database access
still uses the test-only docker/psql adapter. These tests do not qualify the
production TLS database driver, real Canvas, Gateway or OB3-wallet deployment.

References: [Canvas launch/storage flow](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_launch_overview),
[Canvas postMessage API](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_window_post_message),
and [normative platform storage messages](https://www.imsglobal.org/spec/lti-pm-s/v0p1).
