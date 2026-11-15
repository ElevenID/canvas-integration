# ElevenID Canvas Integration

This repository treats Canvas as an **external customer of ElevenID**.
Connector-to-core requests use the public Common Gateway and a dedicated,
organization-scoped API key. Direct access to Marty databases, internal APIs,
service credentials, signing grants or private source packages is unsupported.

## Implemented slice

A dependency-free, server-only Node.js client adapted from Marty-ui's Canvas
administration API module: twelve reads and ten explicitly opted-in management
operations. The sole HTTP owner fixes the Gateway origin and organization,
requires `X-API-Key`, validates operation inputs, verifies TLS, refuses redirects,
bounds responses and applies an absolute request deadline. It never accepts a
caller-provided URL, header map, cookie, bearer token or internal transport.

Default access is read-only. Application approval, credential signing, secret
export, correction-review actions and bulk mirror processing are absent from
the operation registry. Browser imports fail. The CLI reads its API key from a
private regular file and emits only a count, not returned records.

**This is not yet a standalone Canvas LTI service or a completed extraction.**
The compatibility operations still address existing Gateway Canvas APIs.
Provider logic, LTI/OAuth, connector storage, workers and administration pages
have not moved. No deployment is cut over by this repository.

## Test

Use Node.js 22.16 or later, Python 3 and OpenSSL. No npm dependencies, Marty
checkout, cloud services or real credentials are needed.

```sh
npm ci --ignore-scripts --offline --no-audit --no-fund
npm run check
```

The suite uses an actual local HTTPS server with a newly generated, temporary
certificate. It covers the complete operation registry, header/tenant binding,
read-only defaults, forbidden authority, TLS verification, redirection, request
validation, bounded responses, absolute deadlines and key-file permissions.
Mutation tests verify that the architecture gate rejects introduced internal
packages, alternate transports, dynamic imports and browser credential exports.

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
