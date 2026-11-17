# Connector-owned Canvas provider identity

The connector owns a provider-only opaque-to-numeric identity observation registry.
The old Core launch modules remain pending qualified retirement. Migration014, the signed
claim decoder, production repository and bounded HTTP adapter are composed by
the explicitly enabled LTI runtime. The owner must install the migration and
selected runtime grants; startup checks the additional capabilities and guards.
There is no runtime DDL, grants, in-memory fallback or replacement transport hook.
Canonical Gateway learner association and deployed replacement qualification
remain required before retiring the existing Core flow.

Only `canvas_user_id` inside the verified LTI custom claim can supply a numeric
Canvas identifier. It is normalized with the same unsigned64-bit identifier
rules as the REST reader. Missing substitution remains absent; `sub`, email,
roles, browser parameters and top-level lookalike fields cannot supply it.
The configured [Canvas substitution](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.tools_variable_substitutions)
is `$Canvas.user.id`. This is a provider assertion, not proof of Marty identity,
account ownership, evidence verification or issuance authority.

Owner migration022 additionally permits `canvas_course_id=$Canvas.course.id` in
the signed custom claim. It uses the same numeric identifier normalization and
is persisted only as `canvasCourseId` in the accepted protocol context. Missing
course substitution remains absent; the opaque LTI context ID, browser fields,
top-level lookalikes and user ID never supply it. Malformed or unexpanded course
substitutions reject the launch. This identifies provider query context and
confers no canonical identity, application, binding or capture authority.
The [Canvas substitution documentation](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.tools_variable_substitutions)
defines course availability; launch contexts without a course remain supported.

Observation requires an accepted launch receipt and its original browser proof.
New observations recheck current platform/registration revisions, expiry and
protocol claims inside the database transaction. Matching retries return the
original immutable receipt even after closure. Historical receipts never restore
current mapping authority. Tenant, platform, issuer, client and deployment scope
the provider mapping; no Marty user or application identifier is stored.

Each observed numeric claim is retained. A changed numeric identifier for one
opaque subject, or one numeric identifier claimed by another subject in the same
scope, permanently quarantines the affected mappings. The original numeric value
is retained; a conflicting new value is also remembered so later aliases cannot
escape quarantine. Different client/deployment scopes remain separate.
There is no automatic conflict recovery or overwrite.

Actual disposable PostgreSQL16 contracts currently cover accepted browser proof,
eight-way original receipt replay, absent numeric IDs, alias conflicts, concurrent
aliases, client/deployment isolation, trigger rollback, immutable history and
configuration closure. Roles are trusted application SQL, not a JWT/tenant
sandbox. Canonical learner/application association must be governed through the
public Common Gateway as separate work before replacing the existing Core flow.

`POST /lti/registrations/{id}/provider-identity` accepts only `state` and an optional
`browser_proof` form field. It requires the exact connector Origin and the
original proof from that field or the secure per-state cookie. Conflicting
proofs, ambiguous cookies and caller-supplied identity/authority fields fail
before writes. The shared database budget and HTTPS concurrency/drain controls
remain in effect. The response contains an immutable local receipt and a
separately checked current status. Numeric Canvas IDs never reach the browser.
After closure, an existing receipt can replay with `current:null`; a new
observation is denied. A lost write reply is not retried automatically; repeat
the original launch/proof to reconcile its original receipt.

The current repository accessor returns a numeric provider ID internally only
while the accepted launch is current and the mapping remains `numeric_linked`.
Quarantine suppresses that ID even when the historical receipt said linked.
This accessor does not authorize a REST read, a Core binding or a Marty action.
Current Gateway authority and the existing approved capture scope remain required.

Validation includes pinned Node22 tests, actual PostgreSQL16 with all required
migrations and a constrained role, final expiry/configuration rollback and lost
reply recovery. The separate physical driver suite exercises the actual TLS
PostgreSQL runtime, synthetic Gateway session and signed Canvas JWT through the
new endpoint, including private response fields and closure. The Windows run
uses explicit synthetic credential providers. Linux CLI and Chromium protocol
checks passed for merged PR27; these remain separate from live deployment
qualification. Core provider retirement is not claimed.
