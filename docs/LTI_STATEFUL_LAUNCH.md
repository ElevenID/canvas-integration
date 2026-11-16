# Stateful Canvas launch implementation

This branch implements the connector-owned protocol state beneath a future LTI
HTTP endpoint. It is unfinished: registration administration, browser cookie and
platform-storage bridges, request parsing/rate limits, production runtime/CLI
composition, real browser tests and Gateway learner association remain required.
No new endpoint, session, credential or deployment is activated by these modules.

Migration012 adds globally identified local registrations and immutable revisions,
expiring launch state, and immutable acceptance receipts in the connector database.
No Core data, permissions, grants, applications or identity authority are copied.
A separate schema owner installs migrations and provisions roles; runtime installs
no schema or grants. The prototype tests grant only selected state/receipt writes,
registration/platform reads and the limited UPDATE capability PostgreSQL requires
for row locking. They deny registration configuration writes, state-identity
rewrites and receipt mutation. Production named roles remain unqualified.

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

Browser integration must follow the [Canvas launch/storage flow](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.lti_launch_overview).
The existing OAuth SameSite=Lax callback cookie does not establish binding for an
LTI cross-site form POST. Support an explicit secure cookie policy and the trusted
SSO-frame storage protocol with exact HTTPS target/response origin, WindowProxy,
message ID and key checks. Never trust a client-side success flag or use wildcard
postMessage targets. No resource may become available before server-side proof
confirmation and one-time state consumption.
