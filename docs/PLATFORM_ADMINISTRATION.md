# Connector platform administration

Platform metadata now belongs to the connector database and HTTPS service.
These same-origin POST routes use the existing browser session and fresh public
Common Gateway `integration-connector:edit` permission. Tenant and actor come
from Gateway; request forms cannot select them. Configuration changes do not
create producer grants, evidence bindings, policy approvals or issuance authority.

| Route | Form fields | Behavior |
|---|---|---|
| `/platforms/catalog` | Optional `after_id` | Up to20 tenant-owned platform summaries and a next cursor |
| `/platforms/{id}/configuration/inspect` | Empty body | Platform summary or null |
| `/platforms/{id}/configuration/receipt` | `operation_id` | Original operation receipt or null |
| `/platforms/{id}/configuration/create` | `operation_id`, `canvas_origin` | Create disabled platform at version1 |
| `/platforms/{id}/configuration/change` | `operation_id`, `expected_version`, `enabled`, `archived` | Compare-and-set flags and advance version |

Boolean fields are exactly `true` or `false`. IDs use the connector's existing
bounded identifier grammar; operation IDs are UUIDs. Bodies are strictly decoded
UTF-8 forms, at most4096 bytes, with no unknown or duplicate decoded fields.
Requests require exactly one matching Origin and form Content-Type, plus the
existing distributed rate budget. Mutations recheck the same actor, tenant and
permission after reading the body. No CORS grants are emitted; responses are
no-store and contain only fixed public platform metadata and operation receipts.

A platform's canonical HTTPS Canvas origin is selected at creation and cannot
change through this API. Use a separate platform ID for another Canvas origin;
existing credential references remain bound to their original platform. Creation
does not perform DNS/provider requests or store credentials. Actual provider calls
still require the existing verified-TLS, vetted-address and DNS-pinning transport.
Creating a URL does not approve its network destination or establish a connection.

New platforms are disabled. Enable advances the version and permits the existing
OAuth workflow. Disable advances the version immediately, invalidating current
configuration snapshots for new/staged OAuth, refresh and capture work. A provider
request already admitted may still finish; its durable custody/reconciliation
rules remain in force. Captured immutable outbox observations are not cancelled
by platform disablement: delivery still needs current canonical Gateway authority.
Use canonical grant revocation when observation admission must stop.

Re-enabling or archiving requires no local connection, incomplete revocation,
live refresh claim, uncertain refresh or unresolved initial OAuth exchange.
Disconnect explicitly through the connection administration API and let cleanup
finish first. An expired never-started refresh claim does not permanently block
configuration; an expired uncertain exchange does. Archive is terminal through
this API and requires disabled state in the requested result. No-op and stale
version requests return409 instead of silently advancing state.

Persist the operation ID and exact intent before writing. Platform mutation and
immutable actor-attributed receipt commit together. Exact retries return the
original receipt without reapplying a later state change. Reusing an operation
ID with another actor/platform/action/intent is rejected. On an unknown response,
inspect that operation receipt rather than generate another operation ID. Catalog
pagination is an ordinary metadata snapshot, not an authority token; concurrent
changes may require a fresh query. Origins, versions and flags contain no token,
client secret, encrypted reference or raw provider response.

Install owner migrations001–009. The HTTP role additionally needs platform INSERT,
UPDATE only on enabled/archived, SELECT/INSERT on platform_operation_audit and
EXECUTE on administer_platform. It gains no origin/ID UPDATE or platform DELETE
right. Existing platform revision and new audit-immutability guards must be enabled;
startup checks their shape with the three connection-administration guards.
Runtime performs no DDL or grants. These checks do not qualify actual production
ownership, membership, schema provenance or deployment/network isolation.

The tests exercise concurrent create and retry, version races, tenant pagination,
provider-work gates, audit rollback, immutable history and unknown acknowledgments,
plus Gateway authorization through the concrete HTTPS listener/constrained role.
Credential provisioning and the operator UI remain separate work; the existing
OAuth start still requires an already provisioned, scoped client-secret reference.
Production deployment and the complete deployed Core Gateway-to-wallet flow
remain unqualified.
