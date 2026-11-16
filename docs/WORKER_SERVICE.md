# Connector worker process

Run `node bin/serve-workers.mjs` with `CANVAS_CONNECTOR_WORKER_CONFIG_FILE` pointing
to a private absolute JSON path. See `deploy/worker-service.example.json`. The
standalone worker process is separate from the OAuth HTTP process and uses its
own connector database login. It opens no inbound listener and has no Core
database, private service, session, signer or issuance integration.

The concrete runtime composes the connector PostgreSQL pool, read-only OpenBao
key provider, encrypted vault and existing refresh/revocation/capture/delivery
workers. It never accepts repository, transport or task replacements in its
configuration. The public Common Gateway observation submitter is its only
connector-to-Marty transport. It sends a fresh organization API key per delivery;
Canvas receives only Canvas credentials. Gateway derives tenant and current
authority from the credential and binding, not a tenant header or local role copy.

The JSON schema is version 1. Raw passwords, tokens, API keys and JavaScript
providers are rejected. Database password, OpenBao token and Gateway API-key
providers expose separate methods and reread private POSIX files after atomic
agent replacement. Gateway keys use the submitter's exact 32–512-character grammar;
OpenBao keeps its separate 16–4096 grammar. Windows file acquisition fails closed.
JSON rejects duplicate decoded keys, malformed UTF-8/strings and excessive depth.
The configuration and credential files must satisfy the shared owner/mode,
regular-file, single-link, final-no-follow and bounded-read checks. Parent paths
are canonicalized. Cross-purpose and cross-organization canonical-path/inode
aliases are denied; producers in the same Gateway organization may intentionally
share a key file. This protects the loaded custody mapping, not malicious future
writes by the trusted owner/agent. CA files are loaded once; live CA rotation is
not implemented. No credential is read from ambient service environment variables.

One revocation task, up to 32 configured refresh targets and up to 32 configured
producer slots form a fixed round-robin schedule. Each producer has capture and
delivery tasks. The loop admits one actual adapter operation at a time, waits for
settlement and then delays `pollIntervalMs` (100–60000, default 1000). There is no
overlapping interval, backlog of timer callbacks, immediate retry or raw-error log.
Errors advance the schedule. Existing database leases, backoff, attempt limits,
parking and uncertain-exchange fences remain authoritative; a scheduler tick
does not regenerate observation IDs, bytes, timestamps or sequence numbers.

Refresh targets restrict refresh selection, and producer slots restrict capture
and delivery. **Revocation is database-wide:** it claims ready jobs from the
connector database independently of those lists. Only use a database/login whose
entire revocation queue this process is authorized to operate. Multiple processes
still use database lease/fencing rules. Polling does not create capture jobs,
platforms, bindings or schedules; owner/operator workflows must enqueue them.
Large schedules or slow providers delay revisit times. Configure shards and
provider/lease budgets for the required refresh and cleanup latency; this loop
does not promise fairness between organizations or automatic scaling.

SIGINT/SIGTERM stops admission and clears the next timer. The process emits only
fixed `running`, `draining`, `stopped` or redacted failure states. It waits for the
actual current worker, including provider exchange or Gateway acknowledgment and
database publication, before closing the pool. Give the supervisor sufficient
stop grace for adapter deadlines and cleanup. A forced process kill can leave
durable uncertain work; it never authorizes repeating an OAuth exchange.

Startup checks selected table/function privileges and row-lock capabilities and
reads the current connector encryption key before scheduling. It performs no
DDL, grants, queue claims or provider calls before that preflight succeeds.
Full installation uses owner migrations 001–010; revocation uses 001, refresh
also requires the secret timestamp lock guard 006, and capture/delivery use 002–003.
The HTTP process also requires connection and platform administration migrations.

The physical synthetic worker role has only selected connector tables/functions,
token-column updates and immutable-ID/timestamp row-lock grants. It cannot create
schema objects, edit platform/route definitions, delete connections or read the
HTTP recovery audit. The HTTP role cannot complete worker jobs or delete secrets.
These tests do not establish production grants, ownership, schema provenance or
full least privilege. Provision and approve actual roles separately; no role is
created by startup. Keep encryption keys for all retained tokens, attempts and
backups until their reviewed retention/disposition is complete.

Qualification includes actual TLS PostgreSQL/OpenBao/Canvas/Gateway fixtures,
refresh/revocation/capture/delivery, configured-scope isolation and drain/restart
without repeated refresh. POSIX CI additionally runs the actual CLI with private
configuration, fresh Gateway file rotation, and observed SIGTERM draining during
paused Canvas refresh and Gateway delivery. Windows uses explicit synthetic
providers and cannot qualify the POSIX process path.

Production deployment/network isolation/automatic-stop safeguards, managed agents,
provider grant independence, operator UI/unknown-provider resolution, retention,
actual deployed Core Gateway-to-OB3/wallet acceptance and cross-repository Canvas
retirement remain open. Local HTTPS peers are not a live customer Canvas tenant
or the deployed Core authority service.
