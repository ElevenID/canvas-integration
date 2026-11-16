# Connector-owned LTI service adapters

This larger local batch is in progress. The internal tool-key codec and bounded
Canvas service client and internal key-custody adapter exist; durable token custody, administrator provisioning,
capture scheduling/outbox composition, recovery and production runtime wiring are
still required before this can replace the retained Core LTI service flow. These
primitives are not mounted in the public server or exported from the package.

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

## Durable work still required in this batch

Implement versioned operator key provisioning/rotation/deactivation and immutable
public key history; client-credentials attempt/ciphertext publication with uncertain
reply handling; current configuration/role preflight; least-privilege tests; LTI
capture configuration and worker composition through the existing Gateway outbox;
and operator receipt/unknown-provider resolution. An uncertain token exchange must
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
