# Connection administration

The standalone connector HTTPS process provides these same-origin POST routes:

| Route | Form fields | Result |
|---|---|---|
| `/platforms/{platform}/connection/inspect` | Empty body | Current connection generation, revision and status; pending cleanup/refresh flags |
| `/platforms/{platform}/connection/receipt` | `operation_id` | Original disconnect receipt or null |
| `/platforms/{platform}/connection/disconnect` | `connection_id`, `expected_revision`, `operation_id` | Durable disconnect receipt; stale generation/revision returns409 |

Every request requires the existing browser session and a fresh public Common
Gateway check of the canonical `integration-connector:edit` permission. Organization
and actor come from that session. No caller tenant/actor/API-key field is accepted.
The request must have exactly one matching Origin and form Content-Type, bounded
UTF-8 input (2048 bytes), and the shared distributed rate budget. Mutation rechecks
the same actor, tenant and permission after reading input. Responses are no-store
and contain no provider token, secret reference, ciphertext or provider response.
These administrator operations do not create evidence, grants or issuance authority.

Inspect before disconnecting. Persist a UUID operation ID and the returned
connection UUID/revision for the logical action. A disconnect atomically locks
the platform and exact connection, retains its original token references in the
revocation queue, removes the local connection, changes local OAuth status and
inserts an immutable actor-attributed operation receipt. No Canvas request happens
in that transaction. A disconnected local session does not mean the provider has
confirmed revocation or that token cleanup has completed.

If the response is lost, inspect that exact operation receipt. No automatic write
retry or new operation ID is generated. The same operation, actor and expected
generation/revision returns its original receipt even after a newer connection
exists. A different logical operation carrying the old connection UUID fails;
revision1 on a replacement connection cannot revive an old disconnect request.
The receipt proves only that disconnect and queue insertion committed.

The normal database-wide revocation worker confirms provider revocation and then
removes scoped token material. A new OAuth exchange is fenced while a platform has
unfinished revocation or an exchanging/reconciliation-required refresh, including
expired uncertain refreshes. A live never-started refresh claim also fences it.
An expired never-started claim no longer blocks: its expired lease cannot begin an
old exchange, and its durable record is retained. Unknown refresh outcomes still
need operator disposition; this API never guesses that an exchange failed.

Install owner migrations001–008 before starting the updated HTTP process. Startup
requires the new operation table/function, connection DELETE, four refresh metadata
SELECT columns (organization_id/platform_id/phase/lease_until), and the enabled
connection-identity, cleanup-fence and audit-immutability triggers. HTTP cannot
complete revocation jobs or delete secrets. Runtime never creates roles or grants.
The worker keeps its separate role; it receives no connection-administration right.
Trigger-shape and privilege readiness checks are not complete schema provenance or
production role qualification. Provision and review actual roles separately.

Tests cover concurrent disconnect, atomic audit rollback, unknown acknowledgments,
cross-tenant reads, stale revisions/generations, replay after reconnection, immutable
identity/audit, cleanup and uncertain-refresh fencing, and actual Gateway session
authorization through the production HTTPS listener and constrained HTTP role.
Production deployment, operator UI, unknown-provider resolution, retention and the
full deployed Canvas-to-Core-Gateway-to-wallet flow remain open.
