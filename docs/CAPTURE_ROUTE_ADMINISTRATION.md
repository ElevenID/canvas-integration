# Capture-route administration

The production connector HTTPS service now exposes capture configuration and
manual scheduling. It communicates with Marty only through the public Common
Gateway. It has no Core database, private service, issuer key or signing access.

Every request is a same-origin form POST with a fresh Gateway session and current
exact `integration-connector:edit` permission. Tenant and actor come from that
session, never form fields. New configuration, activation and scheduling also
require access to the canonical binding inspection operation, which separately
enforces Core's current `external-observation:manage` permission. The connector
reauthorizes the same actor/tenant before writing and validates snapshot freshness
after that final round trip. There is no owner, wildcard or API-key fallback.

The body limit is 8192 bytes. Unknown, duplicate, malformed-UTF8 and nested-duplicate
JSON fields are rejected. Responses are `no-store`, with no cross-origin grant.
Session cookies go only to the configured public Gateway. No Canvas credential,
producer API key, caller authority header or unrelated cookie enters binding
inspection. The reader uses verified TLS, fixed paths, bounded strict responses,
required no-store, no redirects, no retries and no authority cache.

## Routes and intent

`POST /platforms/{platform}/capture-routes/catalog` accepts optional `after_id`
and returns at most 20 routes plus a cursor. It is scoped to the session tenant
and platform. Other actions use
`/platforms/{platform}/capture-routes/{route}/{action}`:

| Action | Required fields | Result |
| --- | --- | --- |
| `inspect` | none | Local configuration snapshot or null |
| `receipt` | `operation_id` | Original durable operation receipt or null |
| `capture` | `capture_id` | Scoped capture progress without token references |
| `create` | `operation_id`, `expected_platform_version`, configuration fields below | New disabled route at version 1 |
| `replace` | Create fields plus `expected_route_version` | New definition/revision, disabled, next version |
| `activate` | `operation_id`, `expected_platform_version`, `expected_route_version` | Revalidated route, enabled, next version |
| `deactivate` | `operation_id`, `expected_route_version` | Disabled, next version |
| `schedule` | `operation_id`, `expected_platform_version`, `expected_route_version` | One pending capture, route version unchanged |

Configuration fields are `producer_ref`, `binding_id`, `binding_revision`,
`requirement`, `claim_names` and `effective_time_policy`. `requirement` and
`claim_names` contain JSON inside the form. Requirement resource IDs must be
canonical decimal strings, including values beyond JavaScript's safe integer
range. The existing REST reader supports assignment/quiz scores, module completion
and course completion. Claims select a nonempty subset of its seven normalized
fields; `effective_time_source` is always added by capture.

An operation ID is a lowercase UUID. Preserve it and the original intent until
reconciliation finishes. Configuration creation/replacement normalizes its
original fields before receipt lookup. Activation/scheduling use the locked local
definition; browsers cannot supply replacement queries with those actions.

## Canonical mapping and local fences

For the new API, local `producer_ref` must equal the binding's canonical source
ID, provider must be `canvas`, and fact type/revision must match exactly. The
binding must be active with a pending/under-review application that is unexpired
on both the connector clock and Gateway snapshot clock. A snapshot outside 30
seconds of the connector clock is rejected. Gateway calls have separate bounded
phase deadlines; slow authorization can make a snapshot stale and prevent a write.

The canonical binding scope must contain exactly `canvas_origin` plus the reader's
`course_id`, `user_id` and any `activity_id` or `module_id`. Canvas IDs are local to
an instance: matching numbers on another origin cannot authorize a remapping.
Core's provider-neutral observation admission treats those scope keys as data;
it does not call Canvas. Every selected claim must have a compatible canonical rule,
including nullable outputs. The binding must require a non-null text
`effective_time_source` rule large enough for both timestamp-provenance labels.
Other required claims that this projection cannot produce are rejected.

Only primitive query configuration and the binding reference/revision are stored.
Core application/subject identities, permissions, grants and authority snapshots
are discarded. This is compatible configuration, not a local authority mirror.
Core independently reloads current authority when admitting every observation.
No observation becomes VERIFIED or authorizes approval, signing or issuance here.

Route tenant, ID, platform, producer and binding identity are immutable. Replacement
may update the binding revision/query/claims/time policy and always disables the
route. Activation and scheduling require a current enabled/unarchived platform,
matching connected/unexpired OAuth metadata and exact reader capabilities/scopes.
Deactivation remains available when the Core binding is closed or unavailable,
provided the current Gateway integration permission can still be checked.

SQL compares platform/route versions and locks platform, route, connection, then
capture in worker-compatible order. Creation reserves an absent route with a
transaction advisory lock. Configuration/job and immutable actor receipt commit
together. Final checks compare postimages to explicit intent, including BEFORE
trigger rewrites, then recheck local state, timestamps and connection expiry after
audit insertion. Failure rolls back the entire operation.

Disabling/replacing fences new and staged reads through existing route-version
checks. It preserves already completed outbox observations; Core controls their
admission. It does not delete captures, cancel provider work, requeue parked jobs
or regenerate observations.

## Scheduling and uncertain replies

Manual scheduling uses the operation UUID itself as `capture_id`. The server does
not invent a second identity. A new operation conflicts with a preexisting capture
that lacks its matching actor/intent receipt; it never adopts or reattributes it.
The original route/query snapshot is inserted once. The separate worker performs
the Canvas read and durable outbox submission later.

A `completed` capture means its outbox input was created, not that Gateway admitted
it, Core verified it, or a credential was issued. Capture inspection exposes only
progress metadata. Delivery/issuance remain separate outcomes.

After a timeout, disconnect or 503, inspect the same operation receipt. Null is a
snapshot, not proof an in-flight COMMIT cannot occur. Never manufacture a new ID or
automatically retry a mutation. A deliberate exact retry returns the original
receipt without applying it again, even after disable, binding closure or later
configuration. Changed actor, action, versions or configuration conflicts. Current
session permission is still checked for every retry and historical read.

## Installation and qualification

The connector schema owner installs `schema/011_rest_route_administration.sql`
after 001–010. Runtime performs no DDL, role creation or grants. Its preflight
requires the new administration function, explicit column capabilities and enabled
route revision, capture immutability and operation-audit guards. The non-owner HTTP
role needs route SELECT, selected route INSERT/UPDATE columns, audit SELECT/INSERT,
selected pending-job INSERT and progress-metadata SELECT, and required function
EXECUTE. It receives no job UPDATE/DELETE, token-reference read, route-identity/
version UPDATE, or sequence privilege. See the actual constrained-role grants in
`test/connector-oauth-runtime-contract.mjs`; they are fixture evidence, not approval
of production role ownership or provisioning.

Local contracts use actual PostgreSQL16 TLS, production store/runtime/listener and
limited role with a synthetic public-Gateway protocol peer. They cover current
binding/Origin and capability checks, scoped history, concurrent replay, rollback,
late expiry, BEFORE-trigger corruption, uncertain replies and private-column
denial. POSIX CLI, exact frozen-candidate CI, production grants, deployed real Core,
Canvas authorization and end-to-end OB3/wallet/network qualification remain distinct
gates. Operator UI, automatic capture scheduling and recovery/retention automation
remain unfinished.
