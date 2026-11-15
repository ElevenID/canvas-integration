# Boundary and remaining migration

## Enforced in this slice

Only `src/gateway-client.mjs` owns network requests. A caller selects a named,
reviewed operation, not an arbitrary URL. The configured HTTPS Gateway origin
and organization are fixed for the client lifetime. Incoming request headers,
Gateway keys, URL overrides and organization substitutions are not accepted.
Every request carries the server-side key; no session-cookie fallback exists.
The registry exposes neither internal APIs nor signing/approval operations.

Configuration rejects inherited core database/service credentials. Future
connector-owned storage must use distinct configuration and credentials, not
Marty's `DATABASE_URL`, Redis, service keys or signer authority.

The package has no runtime or development dependencies. CI verifies its runtime
file/import inventory, server-only exports, lockfile and transport invariants.
These checks are regression guards, not a sandbox against malicious source code.
They require review and must be protected by repository rules before release.

## Network backstop, not yet deployed

A URL allowlist cannot prove that an operator configured the genuine Gateway.
The caller must use the installation's public Gateway and verify its certificate.
Deploy the connector outside core private networks. Allow only the Gateway's
approved address and connector-owned provider/storage destinations; prohibit
core databases, internal services, metadata services and shared Docker sockets.

The provided Kubernetes example defaults to no ingress and only DNS plus an
explicit documentation-address Gateway destination. It grants no Internet-wide
443 access. Replace that destination only with the reviewed Gateway address.
A CNI that enforces NetworkPolicy is required; the example has not been applied
or verified against the user's cluster. Standard NetworkPolicy is IP/port-based,
not a complete HTTPS hostname policy. Do not claim live isolation from YAML alone.

## Authentication and scope limits

Gateway independently validates the API key, resolves resource ownership and
enforces organization/scopes. Our local HTTPS fixture validates wire behavior,
not the production Gateway's authentication, audit, policies or data semantics.
A read-only integration key must remain read-only even when stolen or used
outside this client. The `integrations:write` scope is broader in the existing
Gateway than this client's management allowlist. Do not grant it to routine
workers until server-side least privilege is resolved.

Canvas-facing LTI/OIDC callbacks eventually terminate in the connector. Their
protocol authentication is separate from, and never substitutes for, the API
key on every connector-to-core operation. No long-lived key belongs in React,
localStorage, Canvas launch claims or browser requests.

## Required next implementation and acceptance gates

1. Replace existing Canvas-specific core management with connector-owned
   platform/OAuth/job state. This compatibility API client is not the final
   architecture and must not permanently retain provider logic in core.
2. Provide missing generic, public Gateway operations for evidence ingestion,
   application/subject linking, result/status reads and delivery acknowledgments.
   Never expose internal endpoints or simply assert that external facts are
   trusted. Bind sources, evidence types and tenant authority through policy.
3. Extract LTI/OAuth/AGS/NRPS/REST adapters and Rust workers without importing
   core crates or accessing core persistence. Keep secret custody and tool
   signing distinct from canonical credential signing.
4. Extract the Canvas administration and learner interfaces. Their own backend
   authenticates users and authorizes actions before using scoped Gateway keys.
   A broad API-key-backed proxy accessible to learners is prohibited.
5. Prove tenant/scope/revocation/audit/idempotency behavior against the real
   Common Gateway using synthetic organizations and customer-created keys.
6. Run OB3 evidence-to-wallet acceptance in an isolated existing development
   environment; prove direct-service/database access fails at the network layer.
   Preserve rootless Docker, OpenBao and current workloads/automatic-stop guards.
7. Transfer or replace all remaining source/test/deployment ownership before
   removing the original implementation, then cut over with rollback evidence.

The merged Marty-ui architecture decision is PR #1950. This slice does not
alter its production routes, worker, database migrations or existing UI imports.
