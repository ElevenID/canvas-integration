# Durable unsigned-observation outbox

`./observation-outbox` combines connector-owned PostgreSQL delivery state and a
worker that calls only the reviewed public Gateway observation submitter. It
stores no Gateway key, Canvas credential, core grant, permission, subject,
application authority, verification status or issuance instruction. Organization
and producer references are connector routing labels; the Gateway still derives
identity from the real API key and core independently reauthorizes every attempt.

Install the reviewed candidate `schema/002_observation_outbox.sql` after001 in
the connector database using the migration owner. The module never creates a
schema or role, and requires an explicit autocommit pool. Deployment migration
registration and per-worker least-privilege grants remain separate review work;
do not treat the broad synthetic fixture role as a production grant template.

```js
import { createObservationOutbox, createObservationDeliveryWorker }
  from '@elevenid/canvas-integration/observation-outbox';

const repository = createObservationOutbox(connectorPostgresPool);
const capture = await repository.enqueue(organizationRoutingLabel, producerKeyReference, {
  binding_id: approvedBindingId,
  binding_revision: approvedBindingRevision,
  observation_id: durableCaptureId,
  observed_at_ms: originalObservedAtMs,
  effective_at_ms: originalProviderEventAtMs,
  claims: normalizedPrimitiveClaims,
});
const worker = createObservationDeliveryWorker({
  repository,
  submitter: publicGatewayObservationSubmitter,
  organizationId: organizationRoutingLabel,
  producerRef: producerKeyReference,
  maxAttempts: 8,
});
const outcome = await worker.runOnce();
```

The capture ID must already identify this source event/capture durably. If enqueue
has an uncertain acknowledgment, reuse that ID and identical input; never create
another ID to hide the uncertainty. Capture results contain identity, sequence
and stored body, not a delivery success or evidence verification result.

## Atomic allocation and immutable preparation

One SQL function locks the organization/binding counter, checks an existing
capture identity and inserts the next sequence plus immutable ledger input in
one transaction. Concurrent captures receive different monotonically increasing
safe-integer sequences. Exact repeated captures return the original row;
changed input under the same ID conflicts. Insert failure rolls back the counter
and ledger together. Changing a producer credential reference does not reset the
binding counter.

The initial row is `preparing`. JavaScript encodes its committed, immutable
columns into canonical original bytes, then seals those bytes in another single
autocommitted statement. No network call occurs before sealing commits. If the
process stops between allocation and sealing, `prepareNext` deterministically
recovers that row; an uncertain sealing acknowledgment preserves the original
body. A trigger verifies body/envelope semantic agreement, rejects any later
change to bytes or provenance, rejects deletion and protects terminal delivery
metadata. Canonical-byte validation is repeated by the worker and submitter.
No database-side hand-written JSON serializer or process-local sequence cache is
used. Production counter limits match core's positive safe-integer contract.

## Ordered delivery and uncertain outcomes

Claiming uses SKIP LOCKED and a fresh UUID lease for three minutes. It considers
only this worker's organization and producer reference. A lower-sequence row for
the same organization/binding blocks delivery unless acknowledged or explicitly
retired; this includes preparing, live-leased, retry and parked rows, even under
a different credential reference. Other bindings can progress independently.

The worker submits only the persisted body, never a newly captured timestamp,
sequence or replacement identity. An expired lease can be reclaimed, but stale
workers cannot acknowledge/defer the replacement lease. Acknowledgment/defer acquire the row lock before checking the database clock, then recheck expiry after staged writes; crossing expiry rolls the transaction back. Core idempotency/current
authorization is still mandatory: lease fencing cannot prevent a slow old HTTP
attempt from reaching the Gateway.

A valid unsigned Gateway receipt plus a successful current-lease SQL acknowledgment
marks local delivery acknowledged. An uncertain local acknowledgment returns
`reconciliation_required`; it does not schedule another send. If the commit did
succeed, the next poll sees the terminal row and makes no request. HTTP loss or
5xx retains the body for retry; core may return the original receipt with
`replayed=true`. No response cache or automatic HTTP-layer retry is introduced.

Retry delay is database-clock exponential backoff capped at300seconds. HTTP429
retries; other HTTP4xx parks the row. Invalid stored bytes park before network.
After the configured1?32attempt limit (default8), unresolved delivery parks with
its original input and error category. No raw error/response/credential is stored.
A parked row blocks newer items for that binding and is never silently deleted,
reissued under another ID, marked verified or converted into false evidence.

Core receipts also bind their original authenticated API-key ID. Replacing a key
can therefore make an old exact-body replay conflict. The ledger retains the
original credential reference; another slot cannot overtake it. Operator
reconciliation must use current core authority/audit, not change the old body or
reset its sequence. This module supplies no public retire/requeue/admin API;
those operations require an authenticated, audited workflow before activation.

## Validation and activation limits

The actual TLS PostgreSQL driver contract installs both candidate schemas with a
non-owner runtime fixture role. It exercises eight concurrent allocations,
eight duplicate captures, eight competing claims/one lease, stale-lease denial,
insert/counter rollback, delayed-write lease-expiry rollback, committed-but-lost enqueue/seal/ack replies, recoverable
preparation, real HTTPS lost-reply replay with byte equality, authorization
parking, credential-slot ordering, bounded outage attempts, trigger-enforced
immutability/retention and an actual database restart preserving ledger/counter.
Its Gateway fixture validates transport/idempotency only; it is not live core
admission or production network-denial evidence.

Still required: REST/LTI/provider capture and binding projection, production
credential/reference provisioning, audited operator recovery and migration roles,
full scheduler/server shutdown composition, actual Gateway current-authority and
journal/outage/concurrency qualification, network-denial tests, OB3/wallet flow
and cross-repository retirement. All local fixtures are synthetic and task-owned;
no production schema or AWS resource is changed by these tests.
