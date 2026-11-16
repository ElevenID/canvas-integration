# Durable connector revocation

The server-only `./revocation-worker` export processes one durable job per
`runOnce()` call. Supply the PostgreSQL repository, encrypted vault and an
explicit Canvas provider with `revoke({ canvasOrigin, accessToken })`. The
provider must return true only after confirmed revocation. Transport failures,
unsupported responses and unknown outcomes must throw or return a non-true
value. `createCanvasOAuthProvider` now implements this method using the fixed
DELETE `/login/oauth2/token` endpoint and a Bearer header, with pinned DNS,
verified TLS, response bounds, redirect denial and an absolute deadline.
No token is placed in a URL or sent to the Gateway. Only a complete HTTP 200
with an empty body or valid JSON object confirms success; unauthorized responses
remain unconfirmed. See the official [Canvas OAuth endpoints](https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth_endpoints).

Disconnect atomically enqueues both access and refresh references before
deleting the connection. A claim commits its expiring lease before external
work. After provider confirmation, the worker durably records that confirmation
using the exact live lease, then idempotently deletes both vault records and
completes the job. Completion is rejected while either vault record exists.
Cleanup failures retain the job and use capped backoff. A replacement worker
can resume cleanup from durable confirmation even if the access-token secret
was already deleted. Stale leases cannot acknowledge or reschedule another
worker's claim.

Polling/scheduling, process shutdown, deployment-specific provider qualification
and operational dead-letter handling remain deployment work. Repeated provider
revocation after an uncertain acknowledgment must be safe and explicitly
qualified. Vault deletion follows durable confirmation only. Network failures
never mean successful revocation or negative learning observations. All
connector-to-Marty traffic remains restricted to the public Common Gateway;
this worker has no Gateway or core database capability.

If Canvas revoked a token but its success response was lost, a later 401 is
insufficient proof of revocation: it can also represent another authorization
failure. The job retains secrets and requires explicit reconciliation if no
subsequent confirmed response is available. No unsafe already-revoked shortcut
is implemented. Local acceptance uses a synthetic HTTPS fixture, not a live
Canvas tenant; it does not establish behavior for every deployed Canvas version.
