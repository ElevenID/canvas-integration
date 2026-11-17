# Learner association through the public Gateway

## Current state

The connector validates a signed Canvas launch and records provider identifiers.
It does not yet associate that browser with a canonical Marty learner or create
an application for that learner. The accepted provider receipt, numeric Canvas
user ID, email and NRPS roles are not Marty ownership proofs.

The public Gateway's external-observation binding administration is available.
Core creates each binding from a locked current issuance application and derives
its subject from that application. Capture administration reads that canonical
binding through Gateway and checks its resource scope and current revisions.
This supports an administrator-attested capture configuration. It does not prove
that the person launching Canvas owns the application named in that binding.

Source inspection at `ElevenID/marty-ui` main
`9ff6e9779a020839ebeafc60095370725e9fb694` found a separate applicant service
behind `/v1/me/applications`. Its authenticated ownership check concerns its
applicant store. External-observation bindings lock
`issuance_service.applications`. The existing reconciliation path checks issuance
transactions; it does not establish an ownership link between those application
stores. Matching application IDs, names or `applicant_identifier` strings is not
an acceptable replacement for that missing contract.

## Required canonical ownership contract

The next Core implementation must establish ownership of the canonical issuance
application independently of Canvas. It must remain provider-neutral and expose
its supported operations only through the public Common Gateway.

An authorized Core administrator can explicitly assign an existing canonical
application to an existing canonical authenticated user. Core must validate both
records and the administrator's current organization authority, lock the current
application at its expected revision, and persist the assignment and actor audit
atomically. A user ID in a connector request or signed provider claim cannot make
that assignment. Reassignment must advance a revision and invalidate pending
association confirmations. Existing ownership that a canonical Core workflow
already proves may be reused only through that workflow's explicit contract.

The learner then authenticates to Marty and explicitly confirms the association
for an exact application, provider-neutral producer source and binding. Core
must derive learner identity from the authenticated session and require a current
matching ownership assignment. A connector organization API key cannot stand in
for the learner or approve the ownership assignment.

Core also needs an explicit provider-proof trust contract for an approved
connector source. A connector-local identity UUID alone proves nothing to Core.
An authenticated producer attestation must bind the one-use challenge to the
exact current provider observation and revision under independently approved
source permissions. Core must reject unapproved sources, changed proof payloads,
stale/revoked source authority and cross-challenge reuse. The existing
`evidence:submit` permission is not an association permission. The proof only
attests a provider observation; it never establishes the canonical learner,
application ownership or consent. Core must not fetch caller-selected URLs to
validate the proof.

Application creation remains a Core operation with canonical templates,
validation and lifecycle policy. The connector must not recreate the legacy
Canvas bootstrap's application/subject generation. Creating a provider registry
entry or selecting an existing binding does not create a Marty application.

## Required browser and receipt flow

1. The connector verifies the Canvas launch, original browser proof and current
   registration, then creates a short-lived, single-use association challenge.
   It binds that challenge to the original launch and exact requested binding.
2. The browser visits a fixed public Gateway confirmation destination. The
   Gateway authenticates the actual Marty session and obtains explicit learner
   consent. Provider email, roles and subject never select the Marty account.
3. Core checks current ownership, tenant, application eligibility, binding,
   producer and all relevant revisions. Confirmation and its immutable original
   receipt commit atomically. The challenge cannot authorize another binding,
   user, source, application, organization or connector destination.
4. The connector reconciles the same challenge through the public Gateway and
   checks the original Canvas browser proof again. Local durable data retains
   only provider identity and opaque canonical references/revisions. It must not
   retain a Core subject/application/permission mirror as current authority.
5. Capture still requires the current canonical binding and independently
   approved producer grant. Association grants neither `evidence:submit` nor
   verification, application approval, signing or issuance authority.

The exact wire schema, routes and storage for this flow are not implemented yet.
The browser must not carry an organization API key, Canvas token or private key.
Redirect destinations must be fixed configuration with no arbitrary return URL.
Codes and proofs must not appear in application logs, referrers or durable
browser journals. Tenant changes require a fresh canonical check.

Expired, abandoned, denied and superseded challenges require explicit durable
states and bounded retention. Exact retries return original receipts; conflicting
operation reuse fails. A lost reply must reconcile the same operation without
silently creating a new challenge, ownership assignment or application. Historical
receipts do not restore current ownership or binding authority.

## Qualification before replacing the legacy flow

Use actual local PostgreSQL and HTTPS peers, then the existing authorized AWS
development deployment. Cover wrong learner/browser/tenant/source/binding,
forged provider identity, stale or changed ownership/application/binding/grant,
permission loss, expiry during authorization and lock waits, concurrent confirms,
conflicting operation reuse, lost committed replies, rollback, restart and
network denial. Verify original receipts and no duplicate application or grant.

Real browser checks must cover explicit consent, tenant switching, rejected and
expired challenges, recovery after reload and private data absence. Finally
qualify the resulting unsigned observation through the actual public Gateway
and OB3 wallet flow before removing the legacy Core Canvas bootstrap/claim paths.
