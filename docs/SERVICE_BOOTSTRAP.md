# Standalone OAuth entry point

The POSIX entry point starts the concrete OAuth runtime without a caller-written
JavaScript bootstrap:

```sh
CANVAS_CONNECTOR_CONFIG_FILE=/run/canvas-connector/service.json node bin/serve-oauth.mjs
```

Start from [the configuration example](../deploy/oauth-service.example.json).
It contains routing/settings and file paths, never inline credentials. Replace
the documentation endpoints with the installation's approved connector database,
connector OpenBao and public Common Gateway endpoints. Run the owner migrations
and approve the runtime role separately. Startup creates no schema, users, grants
or platforms. No deployment or credential agent is installed by this command.

The config, TLS and explicit CA files use the same private owner-only file checks
as [credential files](FILE_CREDENTIALS.md), with a 64KiB size bound. Paths must be
absolute. Config/password/token/TLS-key paths must identify distinct files after
canonical parent resolution and device/inode checks. Providers retain canonical
paths. Parent directories and renewing agents remain trusted; the snapshot does
not prevent a trusted writer from later misconfiguring custody.

Version1 rejects unknown fields, inline credentials, duplicate decoded JSON keys,
deep nesting and malformed strings. Optional CA files use the installation's
private trust roots; otherwise the HTTPS adapters retain normal system trust.
The database CA remains explicit. TLS key/certificate are loaded once; reload or
TLS rotation requires an orderly restart. Password/token acquisition continues
through the separate renewing file providers.

The optional `lti.services` boolean enables connector-owned tool-key/JWK,
service-credential and recovery routes and their operator controls. It requires
owner-installed migrations016–018 and the restricted service capabilities in
addition to launch permissions. Startup runs both read-only capability checks
before listening. Omission or `false` preserves the existing route set; strings
are rejected. This option is separate from the verifier's LTI trust policy and
does not introduce a credential, transport or canonical-authority override.

Only `CANVAS_CONNECTOR_CONFIG_FILE` is consumed for configuration. Argv overrides,
legacy core/database/Gateway credentials, libpq defaults and TLS-bypass environment
settings are rejected. Process output contains only lifecycle state, the actual
listener port, or fixed error codes. Never print the loaded configuration: it
contains the TLS private key in the trusted bootstrap process.

Set the advertised origin and browser routing so the authorized Gateway session
cookie actually reaches the connector start endpoint. A host-only cookie on a
different host is not copied or weakened by this service. The example names do
not qualify that browser routing; real UI/session integration remains required.

SIGINT/SIGTERM stop admission and drain actual runtime work before closing the
pool; repeated signals share one shutdown operation. The process sets an exit
code instead of forcing exit. Configure a supervisor grace period for the chosen
adapter deadlines; a forced process kill can still leave uncertain outcomes.
These choices follow Node22 [signal and exit behavior](https://nodejs.org/docs/latest-v22.x/api/process.html#signal-events).

Private-file/config/negative-CLI tests and security review cover this implementation.
Positive physical CLI startup and signal draining, exact candidate CI, deployment
agents/TLS rotation, rootless/automatic-stop safeguards, worker scheduling and
actual Canvas-to-Gateway-to-wallet/network-denial qualification remain open.
