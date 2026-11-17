# ElevenID Canvas Integration

This repository treats Canvas as an **external customer of ElevenID**.
Connector-to-core requests use the public Common Gateway and a dedicated,
organization-scoped API key. Direct access to Marty databases, internal APIs,
service credentials, signing grants or private source packages is unsupported.

## Implemented slices

The connector owns Canvas administration, credentials, OAuth/LTI state, REST
capture and delivery scheduling. Canonical identities, application ownership,
approval, evidence policy and credential signing remain platform-owned.
The public Gateway adapters use provider-neutral operations; see the
[contract and responsibility map](docs/BOUNDARY.md).

The former Canvas administration compatibility client is retired. Its package
root throws `retired_gateway_api` before reading credentials or making requests.
The operation registry, configuration export and `npm run probe` are removed.
Use the explicit `./observations` export for unsigned evidence submission and
the connector service for local administration. There is no direct-service fallback.

The separate **Canvas REST evidence reader** supports assignment/assignment-backed
quiz scores, module completion and course progress. Its token can only reach a
fixed Canvas HTTPS origin, using reviewed read-only paths and DNS-pinned
connections. It validates learner/resource identity and returns an unsigned,
allowlisted observation. It cannot call Marty, write evidence, approve or sign.
See `docs/REST_PROVIDER.md` for usage, failure behavior and intentional differences
from the original in-core provider.

The server-only Canvas OAuth modules now provide a service-level authorization
code flow and pinned token exchange. They hash and consume one-time state,
bind callbacks to the initiating browser, a fixed connector URI and platform configuration version,
and store client/access/refresh secrets only through an injected
connector-owned vault adapter. See `docs/OAUTH_PROVIDER.md`.

The server-only HTTPS service mounts OAuth administration and callback handlers.
The [OAuth runtime](docs/OAUTH_RUNTIME.md) composes connector-owned PostgreSQL,
encrypted vault, OpenBao, Canvas token exchange and Gateway session authentication.
Durable delivery and REST capture have separate contracts. See
[HTTPS service](docs/HTTPS_SERVICE.md) for listener configuration and shutdown.

**The repository split does not require production-ready integration.**
Provider UI and runtime removal in Marty is proceeding independently of connector
production qualification. Incomplete flows stay disabled; deployment, AGS/NRPS,
unknown OAuth recovery and cutover remain owned TODOs in
[the boundary document](docs/BOUNDARY.md#deferred-work).
No production cutover is claimed.

## Test

Use Node.js 22.16 or later, Python 3 and OpenSSL. Install the pinned npm
dependencies below. Tests need no Marty checkout, cloud services or real credentials.

```sh
npm ci --ignore-scripts --omit=optional --no-audit --no-fund
npm run check
```

Tests use actual local HTTPS peers and freshly generated temporary certificates.
They cover generic Gateway operations, tenant/session binding, retired API rejection, Canvas
resource identity, score/module/course normalization, OAuth state/tenant binding,
one-time callback consumption, connector-owned secret references, token exchange,
redirection, TLS failures, DNS/IP policies, bounded responses/deadlines and
cross-client credential isolation. Mutation tests reject internal imports, core
credentials in provider modules, alternate transports, browser exports, TLS
bypass, removed DNS pinning and weakened OAuth state handling.

## Gateway use

All connector-to-platform requests go to one explicitly configured public Common
Gateway HTTPS origin. API-key submissions use the dedicated `evidence:submit`
scope; browser administration uses the authenticated user's Gateway session.
Neither credential authorizes direct Core access. Gateway enforces tenant,
resource, scope and policy checks independently of this connector.

See [observation submission](docs/OBSERVATION_SUBMIT.md) for the supported producer
API and [the boundary map](docs/BOUNDARY.md) for other generic contracts.
Source provenance is in `NOTICE.md`; licensing is in `LICENSE`.

The server-only `./postgres-pool` adapter supplies verified-TLS, bounded autocommit transport for the connector database. See [PostgreSQL driver](docs/POSTGRES_DRIVER.md) for explicit credential wiring, failure semantics and actual PostgreSQL/OpenBao/vault qualification.

Unsigned producer delivery uses the server-only `./observations` export and only the public Common Gateway. See [Observation submission](docs/OBSERVATION_SUBMIT.md) for canonical durable bytes, exact API-key scope, idempotency and uncertain outcomes.

The server-only `./observation-outbox` export supplies transactional sequence allocation, immutable original-byte retention and ordered leased delivery. See [Observation outbox](docs/OBSERVATION_OUTBOX.md) for recovery, parking and activation limits.

The server-only `./rest-capture` worker reads scoped Canvas data into durable capture and outbox records. See [REST capture](docs/REST_CAPTURE.md) for configuration fences, honest timestamp provenance and activation limits.

The [agent-file providers](docs/FILE_CREDENTIALS.md) acquire connector database
passwords and OpenBao tokens from private rotating POSIX files without caches or
ambient credential fallback. They do not provision agents or rotate TLS material.

The [standalone OAuth entry point](docs/SERVICE_BOOTSTRAP.md) loads private,
versioned configuration and TLS files, then drains on termination signals.
Positive Linux CLI and signal-drain contracts passed; deployment qualification
remains open.

The [initial OAuth custody adapters](docs/INITIAL_OAUTH_CUSTODY.md) persist
exchange attempts and atomically stage encrypted token references in the actual
callback. The [operator recovery API](docs/OAUTH_ATTEMPT_RECOVERY.md) adds bounded
inspection, immutable operation receipts and staged-token revocation disposition.
Unknown-provider resolution and production qualification remain activation TODOs;
see the [current operator console](docs/OPERATOR_CONSOLE.md) for implemented UI.

The [connection administration API](docs/CONNECTION_ADMINISTRATION.md) provides
Gateway-authorized status, generation/revision-fenced disconnect and durable
operation receipts. Provider revocation and token cleanup remain worker operations.

The [platform administration API](docs/PLATFORM_ADMINISTRATION.md) owns the
tenant catalog, disabled creation and audited version-fenced enable/disable/archive
workflow in the connector. Origin replacement and credential provisioning are not
part of platform flag changes.

The [OAuth client provisioning API](docs/OAUTH_CLIENT_PROVISIONING.md) atomically
stores encrypted client credentials, current configuration and immutable operation
receipts. Production OAuth start resolves that configuration, so callers can send
capabilities without supplying client IDs or secret references.

The separate [worker process](docs/WORKER_SERVICE.md) composes refresh, revocation,
REST capture and public Gateway delivery with serialized polling, private-file
credential interfaces and graceful drain. It uses its own connector database role.
