# Connector-owned Canvas provider identity

This branch is implementing the provider-only opaque-to-numeric identity mapping
currently retained in Core's Canvas launch modules. Migration014 and the signed
claim decoder are a persistence foundation; production repository, lifecycle,
HTTP/runtime/preflight and TLS-driver integration are still unfinished.

Only `canvas_user_id` inside the verified LTI custom claim can supply a numeric
Canvas identifier. It is normalized with the same unsigned64-bit identifier
rules as the REST reader. Missing substitution remains absent; `sub`, email,
roles, browser parameters and top-level lookalike fields cannot supply it.
The configured [Canvas substitution](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.tools_variable_substitutions)
is `$Canvas.user.id`. This is a provider assertion, not proof of Marty identity,
account ownership, evidence verification or issuance authority.

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
