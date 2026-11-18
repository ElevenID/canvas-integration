# Boundary and remaining migration

## Enforced in these slices

The public Common Gateway is the sole connector-to-platform integration point.
The connector cannot import platform source packages, query platform databases,
call private services, or receive signing/approval credentials.

| Responsibility | Owner |
| --- | --- |
| Canvas credentials, OAuth/LTI protocol state, provider identities, capture schedules and outbox | This connector and its separate database/vault |
| Canonical identity, application ownership, learner consent and association authority | Platform/Core, exposed through generic public Gateway contracts |
| Evidence source/binding approval, observation policy, canonical credential creation and signing | Platform/Core |
| HTTPS authentication, tenant/resource/scope enforcement and public contract routing | Common Gateway |

The implemented adapters address these generic contract paths only:

| Adapter | Public Gateway contract | Authority |
| --- | --- | --- |
| `observation-submit.mjs` | `POST /v1/evidence/observations` | Dedicated organization API key, exact `evidence:submit` scope |
| `gateway-admin-auth.mjs` | `/v1/auth/me`, `/v1/organizations/{id}/members/me/permissions` | Configured browser session cookie |
| `gateway-binding-reader.mjs` | `/v1/organizations/{id}/external-observation-bindings/{binding}/inspect` | Authenticated administrator session |
| `gateway-ownership-client.mjs` | `/v1/auth/me`, `/v1/organizations/{id}/application-ownerships/{application}/{action}` | Session-bound current platform authority |
| `gateway-association-client.mjs` | `/v1/identity/association-challenges/{challenge}/{action}` | Producer API key, Core-owned source grant and launch-bound challenge capability |

Paths, actions, identity binding and response validation are fixed by each adapter;
none accepts an arbitrary destination or falls back to a private service. These
are implemented code contracts, not a claim of deployed or production-qualified
support. Paired platform changes must be integrated before dependent flows activate.

The old Canvas-specific Marty administration registry, key-file loader and probe
are removed. `createGatewayClient` remains only as an explicit migration error:
`retired_gateway_api`, before reading configuration or issuing any network request.
It cannot be opted back in. Canvas platform/job administration belongs here; no
compatibility path may keep provider logic in the platform.

The independent `src/canvas-rest-reader.mjs` owns **Canvas-side** GET requests.
Its import graph cannot reach the Gateway client, core configuration or storage.
It accepts only a fixed Canvas origin and Canvas access token, resolves and
validates addresses before pinning each observation's connections, and uses
verified TLS. It returns provider observations without core persistence or
trust/approval authority. Cross-client HTTPS tests prove neither credential is
sent to the other peer, including through malicious redirects. See
`REST_PROVIDER.md` for the exact supported scope and unqualified behavior.

The new `src/canvas-oauth.mjs` owns the service-level authorization-code
lifecycle; `src/canvas-oauth-provider.mjs` owns the Canvas token-endpoint HTTPS
transport. Both are server-only and have no Gateway imports. OAuth state is
random, hash-only at rest, ten-minute and one-time. Platform configuration
version checks prevent callbacks from completing against changed Canvas
configuration. Client/access/refresh secrets are stored only through an
injected connector-owned vault; durable records contain opaque references.
Token exchange is pinned to a vetted Canvas address with verified TLS, no
redirects, bounded response bytes and one absolute deadline.

The standalone HTTPS service composes concrete PostgreSQL, OpenBao, encrypted
vault, Gateway session authentication, OAuth start/callback and operator recovery
adapters. Refresh/revocation workers, capture and observation outbox are implemented
and physically tested. The separate worker process adds serialized scheduling;
production deployment remains open.
There is no in-memory or plaintext production fallback. See `OAUTH_PROVIDER.md`,
`SERVICE_BOOTSTRAP.md` and `OAUTH_ATTEMPT_RECOVERY.md`.

Connector-owned storage uses distinct configuration, database roles and credentials,
never Marty's database, Redis, service keys or signer authority. The Canvas reader
takes explicit server-side configuration and cannot read inherited service secrets.

The only direct runtime dependencies are exact-pinned `pg@8.23.1` and `pg-pool@3.14.0`; the complete transitive registry/integrity graph is locked and checked. Optional transports and lifecycle scripts are omitted during installation. There are no development dependencies. CI verifies its runtime
file/import inventory, server-only exports, lockfile and Gateway, Canvas REST and OAuth transport invariants.
These checks are regression guards, not a sandbox against malicious source code.
They require review and must be protected by repository rules before release.

## Network backstop, not yet deployed

An origin allowlist cannot prove that an operator configured the genuine Gateway
or Canvas tenant. The operator must verify endpoints and certificates. Deploy
the connector outside core private networks. Allow only separately reviewed
Gateway/Canvas OAuth and REST destinations and connector-owned services; prohibit core databases,
internal services, metadata endpoints and shared Docker sockets.

The Kubernetes example defaults to no ingress and only DNS plus separate
explicit documentation-address Gateway and Canvas destinations. It grants no
Internet-wide 443 access. Replace each destination only with reviewed addresses.
A CNI that enforces NetworkPolicy is required; the example has not been applied
or verified against the user's cluster. Standard NetworkPolicy is IP/port-based,
not a complete HTTPS hostname policy. Do not claim live isolation from YAML alone.

## Authentication and scope limits

Gateway independently validates the API key, resolves resource ownership and
enforces organization/scopes. Local HTTPS fixtures validate wire behavior, not
the production Gateway's authentication, audit, policies or data semantics.
Do not grant routine workers platform management or approval permissions. Provider
observations are unsigned inputs; source registration and canonical policy determine
what the platform may accept, never a trusted/approved flag supplied by Canvas.

Canvas-facing LTI/OIDC callbacks eventually terminate in the connector. Their
protocol authentication is separate from, and never substitutes for, the API
key on every connector-to-platform operation through the public Common Gateway. No long-lived key belongs in React,
localStorage, Canvas launch claims or browser requests. The REST reader's
caller must bind course/learner identifiers from verified server-side identity
mapping; OAuth token possession alone does not authorize arbitrary browser IDs.

## Split acceptance

Removal of Canvas UI, provider-specific routes, worker/runtime wiring, dependencies
and current architecture coupling from Marty is independent of production connector
readiness. Preserve generic identity, ownership and credential safeguards. Required
protected reviews/checks and merge queues still apply to integration; local tests
drive development. Historical immutable evidence may retain provider names as
provenance; active runtime must not use it to restore retired APIs.

## Deferred work

These TODOs are owned by the Canvas connector maintainers unless stated otherwise.
They do not block the repository split. Keep affected flows disabled until their
specific authority and operational requirements are implemented and verified.

- Complete learner consent/browser composition and source-attested association.
  Platform maintainers own canonical identity/ownership and public Gateway contracts;
  the connector must never infer canonical identity from a Canvas learner ID.
- Complete AGS/NRPS, deep linking, missing administration/learner pages, unknown OAuth
  outcome recovery and any unsupported mirror/retention behavior in the connector.
  Do not retain Canvas code or signing origins in Marty to support them.
- Qualify deployment roles, ingress/egress enforcement, agent credentials and worker
  scheduling before production activation. Existing sample NetworkPolicy is unverified.
- Verify generic Gateway tenant/scope/revocation/audit/idempotency behavior using
  synthetic organizations before activating dependent delivery or association flows.
- Perform synthetic end-to-end qualification, cutover and rollback planning when a
  deployment is requested. No AWS deployment or production cutover is required now.

This scope supersedes the original production-before-retirement sequence. The
Marty UI removal is consolidated in ElevenID/marty-ui PR #1987, with paired Core
PR #444 and common Gateway PR #158. All three are merged. Their accepted source
checkpoints are UI `958615920f7b9d10829e175f1e275cf2ea579e22`, Core
`1f3c1258297556804de76762141f66eb5fcd7dfd` and Common
`4f28691f4985fe84a7b1421b2d00dc33f5dcaacf`. This records source integration,
not production activation, deployment qualification or data migration.
