# Connector HTTPS service

The server-only `./connector-https-service` export mounts the existing OAuth
administration and callback handlers on an actual HTTPS listener. It owns incoming
transport only. Canvas calls remain in the provider adapters, and all Marty calls
remain through the public Common Gateway. No core database or private-service
credential is accepted by this module.

```js
const service = createConnectorHttpsService({
  publicOrigin: 'https://canvas-connector.example.org',
  completionUrl: 'https://canvas-connector.example.org/complete',
  tls: { key: connectorTlsPrivateKey, cert: connectorTlsCertificateChain },
  lifecycle: canvasOAuthLifecycle,
  authenticateAndAuthorize: gatewayAdminAuthenticator,
  rateLimiter: connectorRateLimiter,
  // Loopback is the default. Expose a container interface only explicitly:
  host: '0.0.0.0', port: 8443,
});
await service.listen();
// On shutdown, stop schedulers and await their workers as well.
await service.close();
// Close shared database/vault adapters only after all their users have stopped.
```

The authenticator must be the canonical Gateway session/permission adapter;
the lifecycle must use connector-owned durable storage and encrypted custody.
The constructor requires both and a `rateLimiter.consume(remoteAddress)` adapter,
with no fallback authorization, rate policy or storage. The remote address is the
actual socket peer; forwarding headers do not establish identity or rate-limit keys.
The listener does not provide a proxy-trust mode. A proxy deployment must preserve
the fixed public Host and enforce its own client rate limits; it must not substitute
request-body organization IDs for the Gateway session's organization.

Routes are only `POST /platforms/{platform_id}/oauth/start` and
`GET /oauth/callback`. Callback browser proof, one-time lifecycle state,
same-origin administration, current Gateway permission and bounded form/query
decoding remain in the existing adapters. No health endpoint claims database
readiness. Unknown paths, authority-bearing absolute targets and alternate Host
values are rejected. No request URL, header, provider response or secret is logged.

TLS 1.2 is the minimum, with an explicit private key and certificate chain and no
TLS option passthrough. Clients must validate that certificate normally. There is
no plaintext listener. Header bytes are capped at 16384; more than 64 raw header
pairs are rejected rather than truncating parsed security headers. Only one
request is served per connection. Handshake/header/request-receipt deadlines are
5/10/15 seconds, and inactive sockets are destroyed after 30 seconds. At most 64
connections and eight actual handlers are admitted by default; the handler bound
is explicitly configurable from one to 32.

A peer disconnect does not free handler capacity until its actual operation
settles. Closing the server stops admission, closes idle connections and awaits
the actual handlers, including those whose clients disconnected. Socket closure
does not cancel a token exchange or prove a durable write rolled back. No write
is retried automatically. Shared storage must remain available until `close()`
resolves. An embedding adapter that never settles can keep shutdown pending;
production adapters and the token/credential agents must retain bounded deadlines.
Process termination still requires uncertain outcomes to be reconciled durably.

These shutdown and timeout choices use the Node.js 22
[HTTP server APIs](https://nodejs.org/docs/latest-v22.x/api/http.html#class-httpserver)
inherited by HTTPS. A request-receipt timeout is not a transaction-cancellation
mechanism.

The focused tests use real local HTTPS peers and the actual Gateway session
authenticator. Their lifecycle is a fixture: they do not qualify actual token
exchange, storage or issuance through this listener. Existing storage/provider
contracts remain separate evidence. Still required are production credential/TLS
loading and rotation, a durable rate-limiter, full server/storage/provider
composition, worker scheduling/shutdown, operator UI, deployed network policy and
Canvas-to-Gateway-to-OB3-wallet qualification. No production activation is claimed.

The [OAuth runtime](OAUTH_RUNTIME.md) now provides concrete adapter composition
and a shared database budget. Its real-storage contract additionally tests actual
token exchange, ciphertext publication after client disconnect and constrained-role
startup. The raw service tests above retain their focused fixture scope; production
credential agents, ingress controls, deployment and worker scheduling remain open.
