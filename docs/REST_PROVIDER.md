# Canvas REST evidence provider

## Implemented boundary

`@elevenid/canvas-integration/canvas-rest` is a server-only, read-only provider.
It talks to Canvas, not Marty. It has no Gateway imports, core API key, database,
issuer key, signing grant, application approval or persistence capability.
The separate Gateway client remains the only connector-to-ElevenID transport.

This is an extracted candidate for the REST part of the old issuance provider,
not a live worker cutover. It accepts an already obtained Canvas access token.
OAuth authorization/refresh/revocation, LTI launch verification, AGS/NRPS,
connector storage, scheduling and public Gateway evidence admission remain
unimplemented here. Neither client silently falls back to the other's credentials.

## Server-side usage

```js
import { createCanvasRestReader, CanvasReadError } from '@elevenid/canvas-integration/canvas-rest';

// Values come from trusted connector-owned configuration/secret custody.
// Never build this configuration from browser request fields or LTI claims.
const reader = createCanvasRestReader({ canvasOrigin, accessToken });
const observation = await reader.readRequirement({
  factType: 'canvas.assignment_score',
  courseId: '17',
  activityId: '31', // Canvas assignment ID, including an assignment-backed quiz
  userId: '29',     // From a verified launch or server-owned identity mapping
});
```

Course/module/user identifiers must be canonical positive decimal strings
(or safe integer numbers). SIS aliases, `self`, email joins, arbitrary URLs and
per-request header/token overrides are intentionally unsupported. String IDs
are requested from Canvas to avoid JavaScript rounding of 64-bit identifiers.
Input IDs beyond JavaScript's safe integer range must be supplied as strings;
unsafe numeric response IDs are rejected rather than silently rebound.

Supported reads:

| Fact | Actual Canvas reads |
|---|---|
| `canvas.assignment_score`, `canvas.quiz_score` | Exact assignment submission for the learner, then exact assignment metadata for `points_possible` |
| `canvas.module_completion` | Exact module with `student_id`; uses learner `state`, not module `workflow_state` |
| `canvas.course_completion` | Exact learner's course progress; requires explicit nonnegative integer requirement counts |

The backend calling this reader must authorize the organization/platform,
requirement, course and learner mapping. Possession of an OAuth token is not
proof that a browser-supplied learner ID is authorized. Do not expose the reader
as an unrestricted authenticated proxy or public browser endpoint.

## Observation and failure contract

Success returns `elevenid.canvas-rest-observation/v1`: bound scope, fact type,
normalized assertion, allowlisted source fields, observed/effective timestamps,
and the descriptive verification method. The result and its nested records
are frozen. A successful unsubmitted/incomplete response is a negative
observation. A 404, 401, 403, rate limit, timeout, truncated response, malformed
payload or binding mismatch throws a redacted `CanvasReadError`; **it never
returns false evidence**. The caller must leave current core evidence unchanged
on any exception. This library does not have access to that persistence.

The result is an unsigned provider observation, NOT an admitted core EvidenceFact
or a policy permit. It contains no `verification.status = VERIFIED`, core fact
ID, organization authority, holder binding, issuance action or credential.
A future generic Gateway operation must authenticate the connector's key and
independently bind tenant, registered provider, allowed evidence types, subject,
resource ownership, freshness, idempotency and audit before admission. Do not
re-enable the legacy event-ingest endpoints to bypass that missing contract.

## Deliberate differences from the in-core implementation

The source baseline is recorded in `NOTICE.md`. This is not a claim of complete
legacy byte parity or permission to delete the old implementation.

- Module progress comes from `state`; `workflow_state = active` only describes
  module lifecycle. A completed student state is recognized even without a
  completion timestamp. Deleted modules and contradictory completion timestamps
  are rejected, not treated as negative evidence.
- Scores always use the separate, ID/course-bound assignment denominator. There
  is no assumed 100-point scale or trusted embedded assignment object.
- Excused, ungraded or stale submissions cannot supply a passing score.
  Zero-point assignments have no percentage; valid extra-credit percentages may
  exceed 100. Invalid/missing numeric fields are errors, not coerced zeroes.
- Response assignment/user identifiers must match the requested scope; empty or
  incomplete payloads are not negative evidence. Course/module optional identity
  fields are checked when present.
- Source fields are allowlisted. Submission text, names, emails, comments,
  provider URLs and raw response bodies are not returned or logged.
- One absolute deadline spans DNS, TLS and both score reads. This is stricter
  than the old provider's per-operation/inactivity timeout semantics.

Sequential submission/assignment reads are not a transaction or an atomic
Canvas snapshot. Cutover qualification must cover concurrent grading/configuration
changes and canonical core current-head semantics. Returned timestamps and
source fields are not a cryptographic proof of those properties.

## Transport and deployment

The operator fixes one HTTPS Canvas origin and token per reader. All operations
are GETs assembled from reviewed paths; responses cannot supply a next URL.
Redirects, compressed/non-UTF-8 responses, unexpected pagination and non-200
success statuses are rejected. Responses default to 1 MiB per request (bounded
configurable maximum 8 MiB). Error messages include fixed codes and optional
HTTP status/bounded Retry-After, never tokens, upstream bodies or configured URLs.
No automatic retries, token refresh or proxy-environment fallback occurs.

DNS is resolved once per complete observation. All answers must be allowed;
the connection uses the validated address without another DNS resolution,
while TLS still verifies the original hostname and certificate chain. Metadata,
link-local and non-global addresses are denied by default. An operator may
explicitly allow exact loopback/RFC1918/ULA addresses for self-managed Canvas
or isolated testing using `allowedPrivateAddresses`. This must not be supplied
by tenants and does not permit metadata, CIDR ranges or IPv4-mapped IPv6 aliases.
A configured private CA is public certificate material only; TLS verification
cannot be disabled.

This does not establish deployment network isolation. Keep the connector out
of core private networks; allow only reviewed Gateway and Canvas destinations
plus connector-owned services and DNS. The network policy is an unapplied
example, not evidence that a live CNI enforces anything. Dynamic Canvas IP ranges
require reviewed policy updates or an enforcing hostname-aware egress solution,
not a broad Internet/private-network exception.

## Validation and remaining acceptance

Tests use temporary certificates, synthetic IDs/tokens and actual local HTTPS
peers. They cover wire paths/headers, correct and negative evidence, exact
resource binding, module/grade semantics, TLS failures, redirects, malformed
responses, absolute timeouts, DNS/IP policy and cross-client credential isolation.
Mutation tests verify provider changes cannot quietly add a core import/key,
unpinned DNS, a write method, disabled TLS, removed deadline or browser export.

No hosted Canvas tenant, AWS deployment, real OAuth grant, production Gateway
admission, live network policy or complete OB3 flow is qualified by these tests.
The existing Marty-ui routes, worker, migrations and UI remain unchanged.

## Primary API references

- https://developerdocs.instructure.com/services/canvas (string IDs and OAuth headers)
- https://developerdocs.instructure.com/services/canvas/resources/submissions
- https://developerdocs.instructure.com/services/canvas/resources/assignments
- https://developerdocs.instructure.com/services/canvas/resources/modules
- https://developerdocs.instructure.com/services/canvas/resources/courses
