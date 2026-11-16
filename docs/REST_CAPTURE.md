# Durable Canvas REST capture

`./rest-capture` joins the existing Canvas-only REST reader, connector encrypted
vault and PostgreSQL capture/outbox records. The separate observation delivery
worker remains the only path to the public Common Gateway. Capture sends Canvas
access tokens only to Canvas; it never obtains a Gateway key or accesses a core
database, private service, approval, verification or signing operation.

Install reviewed candidate schema003 after001/002 using the connector migration
owner. Route configuration defaults disabled. No public route-administration API,
role provisioning or startup migration is added here. Provision routing only
through a reviewed administrative workflow before activation; never accept course,
learner, platform or binding references directly from an untrusted browser.

## Routing and capture identity

A route contains connector organization/producer/platform labels, an approved
core binding ID/revision, exact canonical Canvas requirement IDs and a selected
subset of the seven existing normalized assertion fields. It contains no core
member, grant, permission, application or subject authority. One route per
organization/binding prevents competing resource mappings. Any route update bumps
its version. Core independently reloads current canonical authority on delivery.

```js
import {
  createRestCaptureRepository,
  createCanvasRestCaptureWorker,
} from '@elevenid/canvas-integration/rest-capture';
const repository = createRestCaptureRepository(connectorPool);
// Reuse the same ID if this scheduling acknowledgment is uncertain.
await repository.schedule(organizationLabel, producerReference, routeId, durableCaptureId);
const capture = createCanvasRestCaptureWorker({
  repository,
  secretVault: connectorEncryptedVault,
  organizationId: organizationLabel,
  producerRef: producerReference,
  // canvasCa / allowedPrivateAddresses are explicit server-owned options only.
});
await capture.runOnce();
```

Scheduling persists an immutable route/query snapshot before any provider call.
Duplicate capture IDs reuse the existing job, not updated configuration. Capture
IDs must be unique in the organization's observation namespace. Ordinals order
captures per route. Claims are scoped to organization/producer and serialized
behind earlier unfinished reads; completed/parked captures do not prevent a
separate later capture intent. A fresh UUID three-minute lease fences each GET
attempt. GETs may be retried after lease expiry; token exchanges are not part of
this worker.

Claim and completion lock platform, route, connection and capture in that order.
They require enabled/current configuration and a connected, unexpired OAuth
connection. Completion checks connection revision AND opaque access-token
reference, preventing disconnect/recreate or rotation ABA. The worker requires
exact connector capability/scopes before reading the vault, then uses scoped
`oauth_access_token` custody and the reviewed pinned-DNS/verified-TLS Canvas reader.
No URL, token or header override comes from a capture request.

## Projection and honest timestamps

Only the requested normalized assertion subset enters the unsigned envelope.
Source payloads, user details, URLs and the descriptive OAuth read method are not
forwarded as evidence authority. Scope/fact/origin and primitive types are checked
again; resource mismatches, HTTP errors and malformed responses never become
negative learning facts. A successful incomplete/unsubmitted read may attest
`completed=false`.

The route's default `require_provider_time` policy parks a response with no
provider event timestamp. A deliberately configured `as_of_read` policy may
instead attest current state at the read time. Projection ALWAYS adds the
mandatory `effective_time_source` claim: `provider_event` when a real timestamp
exists, otherwise `observation_read`. It never describes a read timestamp as a
provider event. Effective time cannot exceed observed time, and both must be
positive canonical millisecond timestamps.

The candidate provider-neutral Gateway schema clarification in marty-ui commit
1b0c1abbf3962afa21c9e6ac68e4d2e79c794d23 documents this distinction. The core binding
must explicitly approve a required, non-null text provenance claim and the
selected assertion fields. Existing bindings without that field reject this
projection through the unchanged claim allowlist. A local route is not approval;
actual current-authority/provenance acceptance and denial remain qualification
requirements. Neither a timestamp nor provenance grants VERIFIED status, policy
permission, application approval or issuance.

## Atomic capture-to-outbox commit

Completion creates the immutable outbox input/sequence and marks capture complete
in the SAME transaction. It rechecks lease/token expiry after staged writes;
expiry, configuration change or an insertion failure rolls everything back.
Canonical byte sealing is subsequently recovered by the existing outbox worker
before delivery. If a commit reply is lost after success, the completed job is
not claimed again and the original outbox times/ID persist. If it did not commit,
a later leased GET can make a fresh read without conflicting with a hidden
partially committed capture. No scheduler invents a replacement identity for an
uncertain completed observation.

Failures use fixed categories only. Provider authorization/resource denial parks;
rate limits/outages back off with a database-clock cap of300seconds. Default8
attempts (configurable1?32) bound retries. Route/connection changes reject staged
results; obsolete pending jobs park when checked. Captures/provenance are retained
and completed/parked rows immutable. No automatic retirement, raw-error storage,
negative fallback, daemon or operator recovery API is installed.

## Validation and remaining activation gates

The local real contract composes pinned PostgreSQL16 TLS and OpenBao2.5.2,
scoped encrypted access tokens, actual Canvas HTTPS reads, durable capture,
outbox preparation and public Gateway HTTPS submission. It checks true graded
scores/denominators, incomplete false observations, explicit timestamp provenance,
HTTP403/429/503 no-observation behavior, duplicate scheduling/concurrent lease
claims, lost capture replies without re-read, disable/rotation fencing,
delayed-write expiry rollback, source immutability and credential separation.
The Gateway and Canvas endpoints use synthetic HTTPS fixtures; this is not live
Canvas authorization, live core admission or OB3/wallet acceptance.

Production route administration/least-privilege roles, mandatory core provenance
binding qualification, scheduler/server shutdown, credential acquisition,
LTI/AGS/NRPS capture, deployed network isolation/unknown-outcome operations,
actual Gateway-to-OB3/wallet flow and cross-repository retirement remain required.
No existing AWS or production resource is changed by these tests.
