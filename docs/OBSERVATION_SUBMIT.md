# Public Gateway observation submission

The server-only `./observations` export is the connector's narrow producer
transport. It sends one unsigned observation to the public Common Gateway:
`POST /v1/evidence/observations`. It never uses a Canvas-specific Gateway route,
private core service, core database, authority snapshot, verification, approval,
signing or issuance operation. The legacy Canvas administration client is retired;
its package root fails without any network request. Production qualification of
this generic submission flow is deferred before activation, independently of
platform Canvas removal.

```js
import {
  encodeExternalObservation,
  createObservationSubmitter,
} from '@elevenid/canvas-integration/observations';

const submitter = createObservationSubmitter({
  gatewayOrigin: publicGatewayOrigin,
  apiKeyProvider: connectorOrganizationKeyProvider,
  ca: gatewayCaPem, // omit to use the system trust store for public certificates
});
const body = encodeExternalObservation({
  binding_id: approvedCoreBindingId,
  binding_revision: approvedCoreBindingRevision,
  observation_id: durableObservationId,
  sequence: durableBindingSequence,
  observed_at_ms: observedAtMs,
  effective_at_ms: providerEffectiveAtMs,
  claims: { completed: false, score: null },
});
// Persist these exact bytes in the connector outbox BEFORE attempting delivery.
// The same bytes, ID, sequence, binding revision and times belong to every retry.
const receipt = await submitter.submit(body);
```

`apiKeyProvider.getApiKey({signal})` supplies a fresh organization-scoped Gateway
API key for every attempt. That key must have exact `evidence:submit`; admin,
wildcard, signing and deployment-profile credentials are not substitutes. No key
or tenant is taken from the envelope, environment, cookie or arbitrary header.
The only credential header is `X-API-Key`. The Gateway derives tenant/key ID from
actual authentication and independently reloads canonical current organization,
key, approved producer grant/membership, binding and application authority.
Connector configuration never grants authority. Core remains responsible for
admission, verification, policy, approval, KMS signing and credential issuance.

The encoder allows only the seven documented fields and 1?32 primitive claims.
IDs are bounded ASCII; revision/sequence/times are positive safe integers and
provider time cannot exceed observation time. Text claims are valid Unicode,
control-free and at most512UTF-8 bytes; numbers are finite and safely bounded.
Reserved identity/authority/credential names and extra fields/accessors/symbols
are rejected. Claims are serialized deterministically. `submit` accepts only
that exact canonical representation, rejecting duplicate member names, alternate
number tokens and changed formatting before acquiring credentials. It sets
`Idempotency-Key` to the stored `observation_id`; it never manufactures a new ID,
sequence or timestamp while delivering. The core decoder still validates original
bytes independently and applies the administrator-approved claim rules/freshness.

A single deadline (default15seconds, configurable50?120000ms) covers credential
lookup, DNS, TCP, verified TLS1.2+, headers and the complete response. A late key
cannot start traffic after cancellation. Requests use one fixed HTTPS origin and
path, no proxy hook, redirects, automatic retries or response cache. Credentials
never go to the Canvas origin through this module. Deployment must independently
validate the genuine Gateway endpoint and deny access to core private networks;
origin checks are a regression backstop, not network isolation.

Success requires HTTP200, bounded strict UTF-8 JSON and exactly `receipt_id`
(bounded ID) plus boolean `replayed`. Both field orders are accepted; duplicate
names, extra authority fields, truncated, compressed, malformed or oversized
receipts fail closed. Return values contain no verified status, policy permit,
credential or provider token. Even a successful receipt is an unsigned producer
attestation acknowledgment, not a verified EvidenceFact or issuance instruction.

Errors contain a fixed code and optional numeric HTTP status, never a response
body, URL, key, claim or provider exception/cause. `invalid_observation` occurs
before network access; HTTP4xx is `submission_rejected`; transport failures,
HTTP5xx/redirects and malformed success receipts are `submission_outcome_unknown`.
No error produces false/incomplete evidence or a replacement observation. Preserve
the original outbox item on uncertain outcomes and reconcile/retry with its exact
identity under current authorization. Status-specific parking/backoff and conflict
handling belong in the durable outbox, not this transport.

## Evidence and remaining work

Local tests exercise real HTTPS fixtures, exact original bytes/headers, fresh key
lookup, explicit replay attempts, tenant-header absence, HTTP authorization/error
responses, loss/timeout/redirect/TLS failure, malformed receipts, secret redaction,
Unicode/number limits and package/source mutation gates. These fixtures do not
prove live Gateway authentication or production admission.

The core wire compatibility check in the existing demo audit compiles unchanged
production admission/wire source at marty-ui e50010370b4cc9b3ba67c561ec3dcf3542704453
using production-lock dependency identities. It checks emitted canonical bodies,
including false/null claims, decimal/subnormal/safe-boundary numbers and Unicode.
This proves decoding compatibility only, not current grants, transport or issuance.
The interface is documented in the core external-observation-v1 schema and public
Gateway OpenAPI candidate; activation remains gated in the core work.

Still required: durable sequence allocation and immutable transactional outbox,
REST/provider projection onto approved bindings, current grant/binding admin,
connector worker/server composition and credential acquisition, complete deployed
Gateway/journal/network-denial/outage/uncertain-commit qualification, OB3/wallet
flow and cross-repository retirement. This module creates no grant, migration,
producer loop, approval or production activation.
