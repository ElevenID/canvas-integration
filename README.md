# ElevenID Canvas Integration

This repository treats Canvas as an **external customer of ElevenID**.
Connector-to-core requests use the public Common Gateway and a dedicated,
organization-scoped API key. Direct access to Marty databases, internal APIs,
service credentials, signing grants or private source packages is unsupported.

## Implemented slices

The dependency-free, server-only Gateway client adapts Marty-ui's Canvas
administration API module: twelve reads and ten explicitly opted-in management
operations. Its HTTP owner fixes the Gateway origin and organization, requires
`X-API-Key`, verifies TLS, refuses redirects and bounds responses and time.
Application approval, signing, secret export, correction-review writes and bulk
mirror processing are absent. Browser imports fail. The read-only CLI loads its
key from a private file and emits a count rather than returned records.

The separate **Canvas REST evidence reader** supports assignment/assignment-backed
quiz scores, module completion and course progress. Its token can only reach a
fixed Canvas HTTPS origin, using reviewed read-only paths and DNS-pinned
connections. It validates learner/resource identity and returns an unsigned,
allowlisted observation. It cannot call Marty, write evidence, approve or sign.
See `docs/REST_PROVIDER.md` for usage, failure behavior and intentional differences
from the original in-core provider.

**This is not yet a standalone Canvas LTI service or a completed extraction.**
The Gateway compatibility client still addresses existing Canvas APIs. The REST
reader is not wired into the live worker. LTI/OAuth, AGS/NRPS, connector storage,
scheduling and administration pages still need extraction. No deployment is cut
over, and the original Marty-ui implementation is retained for qualification.

## Test

Use Node.js 22.16 or later, Python 3 and OpenSSL. No npm dependencies, Marty
checkout, cloud services or real credentials are needed.

```sh
npm ci --ignore-scripts --offline --no-audit --no-fund
npm run check
```

Tests use actual local HTTPS peers and freshly generated temporary certificates.
They cover Gateway operations, tenant/header binding, read-only defaults, Canvas
resource identity, score/module/course normalization, redirection, TLS failures,
DNS/IP policies, bounded responses/deadlines and cross-client credential isolation.
Mutation tests reject internal imports, core credentials in provider modules,
alternate transports, browser exports, TLS bypass and removed DNS/deadline guards.

## Read-only Gateway probe

Create a dedicated organization API key with **only `integrations:read`** in the
normal ElevenID console. Store it outside the repository in a regular file
readable only by its owner (mode 0600 on POSIX). Do not place it in argv or a
browser bundle. Supply your installation's public Gateway origin, not an
issuance/signing service URL.

```sh
export MARTY_GATEWAY_ORIGIN=https://gateway.example.org
export MARTY_ORGANIZATION_ID=YOUR_ORGANIZATION_ID
export MARTY_GATEWAY_API_KEY_FILE=/run/secrets/canvas-gateway-key
# Only for a Gateway using your explicitly approved private CA:
# export MARTY_GATEWAY_CA_FILE=/run/config/gateway-ca.pem
npm run probe
```

The probe performs one `listCanvasPlatforms` request. It does not seed, approve,
issue, sign, migrate or change any deployment. Error messages never include the
key, upstream response body or configured URL.

## Server-side use

```js
import { createGatewayClient } from '@elevenid/canvas-integration';
import { loadConfiguration } from '@elevenid/canvas-integration/configuration';
const client = createGatewayClient(await loadConfiguration());
const platforms = await client.execute('listCanvasPlatforms');
```

Management operations require explicitly replacing `allowedOperations` with
reviewed operation names. Creates additionally require a caller-persisted
`idempotencyKey` (16–128 safe characters), reused for the same logical request.
There are **no automatic write retries**. A network failure can leave the result
unknown: reconcile through a read before retrying. Header preservation is
covered here; actual Gateway idempotency remains an integration acceptance gate.

The operation allowlist does not narrow an overprivileged key on the server.
Gateway key scope/tenant checks and deployment network policy remain independent
security boundaries. Do not use `integrations:write` for the normal reader.

See `docs/BOUNDARY.md` for restrictions, migration gates and unverified work.
Source provenance is in `NOTICE.md`; licensing is in `LICENSE`.
