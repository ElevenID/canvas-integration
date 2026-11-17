# Connector-owned LTI service adapters

This larger local batch is in progress. The optional operator service now mounts
generated-key custody, public JWK discovery, durable credential exchange and recovery
through Gateway-authorized actions. LTI capture/scheduling/outbox composition,
remaining protocol services and deployed qualification are still required before
this can replace the retained Core LTI service flow. Internal secret-bearing
adapters are not package exports or public read APIs.

`lti-tool-key-store.mjs` and owner-only migration016 add generated-only encrypted
tool-key custody, immutable public JWK/operation history, revision-checked rotation
and deactivation, and original-operation reconciliation after a lost commit reply.
AES-GCM associated data includes tenant, platform, registration, their revisions,
client, tool origin, key ID, public JWK and wrapping-key ID. No private key is
accepted from administrator input or included in an operation receipt.

The internal `current()` accessor returns a versioned key-material snapshot. It
rechecks configuration after OpenBao lookup, including a disable during that read.
This is not dispatch authorization: the future durable signing-attempt admission
and send path must independently fence current revisions and disable status. The
returned private PEM is confined to internal server composition; JavaScript
strings cannot be reliably erased, so callers must minimize retention and never
log, serialize to operators, persist plaintext or return it over HTTP. Mutable
temporary key/plaintext buffers are erased on both success and failure.

Owner migration017 and the internal service store/lifecycle now persist a single
original client-credentials attempt, configuration/key snapshot and database-issued
assertion timestamps. Only the successful first dispatch claim may call Canvas.
After verified TLS, a read-only durable permit check fences that original claim,
expiry and current connector configuration before any HTTP credentials are sent.
Expiry and the total operation deadline are checked again after the permit query.
These are local admission/dispatch/publication fences; they cannot cancel an
external request that was already transmitted when configuration changes later.

An unknown exchange remains unresolved and blocks a replacement attempt for the
registration. Retrying the same operation inspects its original state; it never
regenerates the request UUID or repeats the provider exchange. Late successful
responses are encrypted and staged even after configuration drift, while current
revision and token expiry checks independently gate publication and later reads.
Token lifetime is conservatively measured from the original database assertion
issue time, including time spent in DNS, TLS and provider processing.

Token AES-GCM context binds the original attempt, dispatch, tenant/platform/
registration/client/origins/key revisions, exact granted scopes, token reference,
expiry and wrapping-key ID. A separate domain-derived HMAC rejects changed-token
or changed-scope/expiry staging replays. A lost staging/publication acknowledgment
is reconciled from the same attempt without repeating the provider call. Public
receipts contain references, versions, scopes and expiry; they contain no token.
Current token reads recheck configuration and expiry after OpenBao lookup.

The stores/lifecycle are mounted only when the boolean `lti.services` is true.
Capture/worker composition and deployment retention policy remain required. A staged
token or historical published receipt is not permission to read provider data or
submit evidence; Gateway's current canonical binding/application checks remain
mandatory in the later capture pipeline.

## Recovery and expiry disposition

Owner migration018 and `lti-service-recovery-store.mjs` provide actor-bound,
original-operation receipts for three explicit actions. `abandon_prepared` resolves
an unstarted attempt only while no dispatch or token exists. `retire_known` resolves
a staged or published token only after its accepted provider TTL has elapsed from
the later database ciphertext-custody timestamp. This retirement deadline is more
conservative than the earlier usable deadline. Resolving retains the original
ciphertext/reference and any published receipt; it never makes that token current.

`resolve_unknown` requires a recorded external confirmation reference plus current
version checks proving that the connector platform and registration are disabled
and the tool key is deactivated. Its receipt explicitly records an **operator
attestation**, not verified provider revocation. It does not reenable configuration.
If an original in-flight response arrives afterward, its token still enters
encrypted custody under the resolved attempt; that late custody cannot reopen
dispatch, publication or token use. A competing stage that wins first makes the
unknown-phase recovery CAS fail instead.

Do not use the Canvas logout DELETE endpoint as proof of LTI credential revocation.
At the reviewed [Canvas source checkpoint](https://github.com/instructure/canvas-lms/tree/1c9f0bb8013ed69c4f2efe11fd483025469b7e6c),
the [LTI client-credentials issuer](https://github.com/instructure/canvas-lms/blob/1c9f0bb8013ed69c4f2efe11fd483025469b7e6c/lib/canvas/oauth/client_credentials_provider.rb)
issues a token through the [developer key JWT signer](https://github.com/instructure/canvas-lms/blob/1c9f0bb8013ed69c4f2efe11fd483025469b7e6c/app/models/developer_key.rb),
whereas [the logout-delete handler](https://github.com/instructure/canvas-lms/blob/1c9f0bb8013ed69c4f2efe11fd483025469b7e6c/app/controllers/oauth2_provider_controller.rb)
destroys a user OAuth access-token object. This distinction supports the conservative
recovery design; it does not qualify revocation behavior of a particular deployed
Canvas version. No unknown-token expiry is inferred from a missing response.

All recovery audits, tokens and original attempt history remain retained. This
slice neither deletes operator data nor introduces an unattended purge. A deployed
retention policy and any irreversible cleanup require their own owner provisioning
and qualification within the remaining split work.

## Service role capability checks

`lti-service-preflight.mjs` is a read-only check for the role used by the service
adapters. The physical contract provisions a disposable restricted role as the
fixture owner, then runs the actual tool-key, token-store, TLS lifecycle and recovery
contracts through that role. It grants required column operations and invoker
functions without DDL, ownership, deletion, historical-field updates or access to
unrelated tables. The adapter never creates roles, grants or migrations at startup.

The check considers all MEMBER-reachable roles, including privileges available
through a membership whose [PostgreSQL16 INHERIT option is false](https://www.postgresql.org/docs/16/sql-grant.html).
It rejects elevated role flags, all MEMBER-reachable predefined PostgreSQL roles
(including server-file/program capabilities), schema creation, missing required operations,
unauthorized INSERT/UPDATE columns, disabled/malformed guards, definer functions,
unexpected function paths/ownership and nonordinary service tables. This is a
capability/guard check rather than complete owner-schema provenance verification
or a SQL sandbox deriving tenants from JWTs. The OAuth bootstrap invokes it before
listening when `lti.services` is true. Role and schema installation remain
owner-managed; startup never supplies missing grants.

## Operator and public routes

Enable `"services": true` inside the private configuration's existing `lti` object,
with the appropriate platform trust policy. Omission or `false` keeps the new routes
disabled. The CLI preserves the boolean and separates it from the launch verifier's
protocol policy. The selected runtime role must pass both launch and service checks.

The operator console adds tool-key inspection/provision/rotation/deactivation,
credential request/catalog/inspection/reconciliation, and service-attempt resolution.
Every administrator request uses the current public Gateway session and exact
`integration-connector:edit` permission. Organization and actor come from Gateway;
the body cannot supply them. Authorization is checked again after key encryption,
before a dispatch claim, after verified TLS before sending a client assertion, and
before publishing a staged token. Dispatch cancellation propagates to pending Gateway
reads. These checks do not create an atomic transaction across Gateway and PostgreSQL.

`GET /lti/registrations/{registrationId}/jwks` publishes only six-field RSA public
JWKs, without authenticating a browser session. Copy its inspected URL into the
Canvas tool configuration. Current keys remain published; rotated keys have a
ten-minute retirement grace. The set is bounded to eight: a ninth live key rotation
is rejected rather than truncating a still-live key. A deactivation withdraws the
whole set and creates a barrier, so later rotation cannot republish pre-deactivation
keys. Historical audit/key rows remain retained. Discovery reads at most the nine
latest immutable operation versions through an index; the mutation cap makes that
window sufficient to include every live key. Responses are no-store and rate-limited.

Administrator responses contain explicit public snapshots, references and receipts;
they omit private PEM, bearer tokens and internal dispatch IDs. Bounded attempt
catalog pages let an operator rediscover original IDs without repeating an exchange.
The browser saves a receipt pointer before each mutation. A fresh-tab staged-token
recovery saves/reuses its original attempt ID, never a replacement UUID. Unknown
responses and post-commit permission loss retain that pointer through reload.

Tool keys are newly generated connector-owned RSA keys. They are separate from
credential signing/issuance keys. The internal provisioning adapter encrypts
their private material under connector-owned OpenBao custody and returns only a
versioned public JWK and immutable operator receipt. A key must be bound to its
tenant/platform/registration/client and revisions. It must never call Core KMS or
consume a Core private key reference. Startup and request paths will create no
roles, migrations, grants or provider configuration.

The existing public Common Gateway remains the sole connector-to-Marty path.
LTI results and memberships will enter the existing durable unsigned-observation
pipeline only after current canonical binding/resource/application checks.
Provider subjects, Canvas numeric identifiers and roles do not establish Marty
identity, application ownership, membership, verification, approval or issuance.

## Internal primitives

`lti-tool-assertion.mjs` validates a PKCS8 RSA key and public-only JWK projection.
The narrow signer accepts an original durable attempt UUID and timestamps, fixes
RS256 and the Canvas token endpoint path, and limits assertions to120seconds. It
does not generate a replacement attempt ID or expose arbitrary payload signing.

`canvas-lti-service-client.mjs` signs a client-credentials request for the configured
Canvas account's `/login/oauth2/token`. It reports the returned subset of requested
read scopes and rejects escalation. AGS line-item/result reads and NRPS course
membership reads use constructed Canvas paths, verified TLS, validated/pinned DNS,
explicit private-address policy, one total deadline and cumulative response/page
budgets. Redirects, duplicate JSON keys/headers and pagination origin/path/filter
changes fail closed. The client performs no automatic exchange/read retry and
contains no persistence, identity linking or Core transport.

Result reads require the selected provider user and line item; membership reads
require the selected opaque provider user, LTI context and resource link. Complete
bounded pagination is necessary before absence can be reported. Duplicate matching
members/results are ambiguous and rejected. Names, email, comments and unselected
provider fields are discarded. AGS scores do not imply completion or verification;
NRPS roles remain provider data. Missing data is not a canonical negative assertion.

## Capture foundation

The internal keyless `createCanvasLtiServiceReader` exposes only GET operations.
It accepts no signing key and has no token-exchange API. Each verified-TLS send,
including each pagination page, requires a fresh read permit within the original
token expiry and operation deadline. The service store checks the original
published token reference and current platform/registration/key revisions without
decrypting the bearer again for each permit.

`lti-capture-contract.mjs` defines `canvas.ags_result` and
`canvas.nrps_membership` queries as provider data. A configuration must match a
fresh public Gateway binding's source, fact type, active application, revision,
Canvas origin, registration, course, opaque provider user and resource link; AGS
also names its line item, and NRPS its context. This validation produces query
configuration only. Gateway still authorizes each submitted observation using
its current canonical records.

The internal capture worker uses an original published credential attempt. AGS
reads first require the line-item metadata to match the configured resource link,
then read the selected learner result. Only selected numeric score fields are
projected, with no completion inference. NRPS projects the selected member's
explicit status and discards roles and personal fields. Missing observations and
transport failures produce no negative fact. Both APIs require explicit
`as_of_read` timing, since these read results contain no provider event time.
Lease and token permits are checked before every request. A lost completion
acknowledgement requires reconciliation of the original capture, with no retry
inside the worker.

Owner migration019 and `lti-capture-repository.mjs` add durable routes and jobs.
Scheduling binds an original capture UUID to the route version and published
credential attempt. Replays reconcile that original identity. Claims are ordered
within each route, use expiring leases and retain bounded exponential backoff.
Before sending, the read permit checks the lease and current route, platform,
registration, key, published token and required service scopes. Completion locks
the current configuration and original job, then atomically allocates the existing
outbox sequence, enqueues the unsigned observation and records the completed result.
An expired or replaced lease cannot complete or defer the current attempt.

Completed jobs retain the original lease/result as a receipt. Exact completion
replays return success even after later configuration changes; changed payloads
and other leases fail. A matching outbox row created by another pipeline is an
identity collision, not a completed LTI receipt. Jobs and completed observations
remain retained. Trigger postconditions detect changed schedule times, parking
state, completion results and later counter/outbox mutations, rolling back the
whole transaction.

The actual PostgreSQL/OpenBao contract uses a distinct capture role and real
keyless Canvas TLS reads. This role can read published-token ciphertext for
connector-owned custody but has only the key metadata columns required for
configuration checks; signing-key ciphertext, nonce, tag and wrapping-key ID
reads are denied. It has no signing-key generation or credential-exchange grants.
The service-role fixture separately provisions its synthetic key and credential.

## Capture route administration

Enable `lti.captures: true` together with `lti.services: true` to mount the capture
administration API. Owner migration020 adds immutable original actor/intent audits.
Startup checks the explicit capture INSERT/UPDATE columns, retained history,
enabled guards, invoker functions, sequence usage and absence of sequence-reset
privileges across MEMBER-reachable roles. The existing service check still applies.
This is a capability check, not complete schema provenance or a tenant SQL sandbox.

POST form routes live under
`/platforms/{platformId}/lti/registrations/{registrationId}/capture-routes/`.
Use `catalog` for a bounded page, or `{routeId}/inspect`, `receipt`, `capture`,
`create`, `replace`, `activate`, `deactivate` and `schedule`. Mutations require an
original operation UUID. Create/replace specify a published service attempt,
provider query, selected claims and current platform/registration/key revisions;
other changes also compare the route revision. Create/replace leave the route
disabled. Scheduling uses its original operation UUID as the durable capture ID.
Deactivation requires the route version and remains possible after parent disable
or token expiry. Inspect/receipt/catalog/status return explicit scoped metadata,
without bearer, signing-key, internal dispatch or Core subject/application fields.

The server derives tenant and actor from the current public Gateway session and
exact edit permission, reads the canonical binding itself, then checks its source,
resource scope, claim rules, revision and active application. The original transient
snapshot is rechecked after final asynchronous authorization. A separate bounded
deadline, limited by snapshot freshness and application expiry, is checked again
after SQL locks and writes. That deadline is not part of persisted intent or a
local authority mirror. Current Gateway admission still independently decides
whether each delivered observation is authorized.

Exact retries reconcile immutable original receipts before consulting changing
bindings or local versions. A concurrent original commit discovered during later
prechecks is reconciled without a write retry. Changed actor/intent replays conflict.
Audit faults roll back route changes, scheduling and receipt together, including
changes made by an audit trigger to a scheduled job or parent configuration.
Permission loss after commit returns403 and can leave an unknown outcome: retain
the original operation UUID and use its receipt endpoint after access is restored.
A403 response must not be treated as proof of rollback by a future browser control.

The operator console exposes capture forms only when the capture API is mounted.
Create/replace selects AGS scores or NRPS status, an opaque provider user/resource
and a published credential attempt. Separate controls inspect/catalog routes,
activate/deactivate, manually schedule a capture and inspect its original status.
Automatic cadence remains private worker configuration.

Capture mutations save only a scoped receipt pointer before sending. A lost response
or postcommit403 retains the original operation UUID through reload and blocks
another mutation from that form. Receipt reconciliation checks the registration,
route, action, expected receipt version, published attempt reference and capture ID,
in addition to the operation/platform. Mismatched receipts cannot clear the pointer.
Only the nonsecret published-attempt UUID and expected version accompany its receipt
path; no request body, claims, provider user or token is saved. Manual receipt inspection also supports
an original capture operation ID.

The local contract uses actual Gateway/connector HTTPS and restricted PostgreSQL
roles with synthetic data. The separate LTI-only worker composes keyless capture,
durable cadence and Gateway delivery; see [worker service](WORKER_SERVICE.md).

## Durable work still required in this batch

Finish deployed retention policy and LTI
deployed worker role/agent/network qualification and retained work disposition.
Worker mode, durable cadence and capture controls are composed locally; this does
not establish deployed production permissions or a live provider.
Operator receipt and unknown-provider resolution are mounted as described above.
An uncertain token exchange must
not silently regenerate its attempt or assertion. Current registration, tool-key,
token, capture and canonical binding revisions must be fenced at their respective
commit boundaries. Fresh service credentials alone confer no Marty authority.

Then qualify the exact composed runtime with actual PostgreSQL/OpenBao/TLS,
concurrent configuration changes and expiry, crash/replay/unknown replies, real
browser administration where applicable, and synthetic provider responses.
Existing-AWS actual public Gateway-to-OB3/wallet, production deployment/agents,
canonical learner association, remaining Deep Linking/mirror publication and
cross-repository retirement stay in the full goal beyond this local primitive work.

## Official protocol references

The implementation uses the [Canvas OAuth token endpoint](https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth_endpoints),
[Canvas results](https://developerdocs.instructure.com/services/canvas/resources/result),
[Canvas NRPS](https://developerdocs.instructure.com/services/canvas/resources/names_and_role),
[1EdTech Security1.0](https://www.imsglobal.org/spec/security/v1p0/) and
[AGS2.0](https://www.imsglobal.org/spec/lti-ags/v2p0/). The read scope URIs come from
the service specifications; illustrative older OAuth examples are not substituted
for the service's `scope/result.readonly` URI. These references define provider
protocol behavior, not canonical application/evidence authority or qualification.
