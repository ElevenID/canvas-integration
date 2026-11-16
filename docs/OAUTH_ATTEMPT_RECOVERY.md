# OAuth attempt recovery

The standalone OAuth service exposes three same-origin POST endpoints beneath
`/platforms/{platformId}/oauth/attempts/`: `inspect`, `receipt`, and `recover`.
They use the public Gateway session and current `integration-connector:edit`
permission. Organization and actor come from Gateway, including a second check
immediately before mutation; neither is accepted in form fields or tenant headers.
These checks are authorization snapshots, not a transaction with Gateway's
organization database. No connector role or membership mirror is maintained.

The schema owner applies `007_oauth_attempt_recovery.sql` after migrations 001–006
and provisions the runtime role separately. Startup performs no DDL or grants.
The HTTP role needs SELECT/INSERT on recovery audit and revocation jobs plus its
existing attempt privileges and EXECUTE on the recovery function. It needs no
audit UPDATE/DELETE, revocation-job UPDATE/DELETE or secret DELETE. The separate
worker role performs revocation and secret cleanup. These are adapter requirements,
not proof of production role approval or schema provenance.

All endpoints accept `application/x-www-form-urlencoded`, reject duplicate or
unknown decoded fields, require one exact Origin and Content-Type header, bound
the body to 2048 bytes, and use the aggregate database limiter. Responses are
no-store/no-referrer and emit no CORS headers. The enclosing HTTPS listener's
Host, TLS, header, connection and handler-capacity limits still apply.

`inspect` accepts only `authorization_id`, the state hash of 64 lowercase hex digits. It
returns a tenant/platform-scoped attempt snapshot or null: phase, revision,
whether references are known, revocation/cleanup status, connection presence and
at most eight recent recovery receipts. Reference-presence flags do not establish
that token material remains available. No token, ciphertext, key ID, raw secret
reference, browser proof, authorization code or provider response is returned.
Unknown or malformed stored receipt fields fail closed rather than being exported.

`receipt` additionally requires `operation_id`, a lowercase canonical UUID. It
reads the exact durable operation result or null at the read snapshot. Null is
not proof that a concurrent transaction cannot later commit.

`recover` requires `authorization_id`, `operation_id`, `expected_revision` and
`action`. The caller first inspects the attempt and explicitly chooses one action:

* `abandon_unstarted`: only a consumed attempt that never began exchange and has
  no staged access reference or recovery job can become abandoned.
* `queue_staged_revocation`: staged or reconciliation-required attempts with
  known access references can enqueue durable cleanup. This preserves ciphertext
  and blocks publication. An existing current connection blocks the operation.
* `finish_staged_revocation`: only after the scoped worker has durably confirmed
  provider revocation, deleted both token secrets, and completed the exact job
  can the attempt become abandoned and permit another exchange.

Each mutation locks platform then attempt, checks the exact revision, and writes
an immutable actor/action/operation receipt in the same transaction as state and
job changes. Audit failure rolls everything back. The same operation, actor,
action, attempt and expected revision returns its original receipt; changed
meaning conflicts. A stale revision or ineligible state returns 409 without
mutation. After 503 or a lost reply, keep the operation ID and inspect its exact
receipt and attempt. Do not create another operation or repeat Canvas exchange
automatically. Receipts describe the committed historical operation, not current
eligibility or permission.

An exchanging/unknown attempt with no staged tokens cannot be abandoned through
this API. A published attempt or current connection cannot be revoked through
this path. Resolving unknown provider outcomes needs an additional reviewed
operator/process workflow; ordinary connection disconnect is separate. Recovery
does not claim that Canvas grants cannot be shared across separately configured
platforms. Verify the provider grant's scope before requesting revocation.

The existing revocation worker can execute queued jobs, including recovery after
partial secret deletion. Worker scheduling, browser operator UI, production
deployment/roles, full retention policy and actual Canvas/Gateway/OB3/wallet
qualification remain unfinished. Do not purge unresolved attempts, jobs or audit
receipts. Synthetic tests use actual PostgreSQL, encrypted custody and local HTTPS
peers; they do not establish production readiness.
