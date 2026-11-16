# Durable connector revocation

The server-only `./revocation-worker` export processes one durable job per
`runOnce()` call. Supply the PostgreSQL repository, encrypted vault and an
explicit Canvas provider with `revoke({ canvasOrigin, accessToken })`. The
provider must return true only after confirmed revocation. Transport failures,
unsupported responses and unknown outcomes must throw or return a non-true
value. The current token-exchange provider does not yet implement this method.

Disconnect atomically enqueues both access and refresh references before
deleting the connection. A claim commits its expiring lease before external
work. After provider confirmation, the worker durably records that confirmation
using the exact live lease, then idempotently deletes both vault records and
completes the job. Completion is rejected while either vault record exists.
Cleanup failures retain the job and use capped backoff. A replacement worker
can resume cleanup from durable confirmation even if the access-token secret
was already deleted. Stale leases cannot acknowledge or reschedule another
worker's claim.

Polling/scheduling, process shutdown, provider HTTP revocation semantics and
operational dead-letter handling remain deployment work. Repeated provider
revocation after an uncertain acknowledgment must be safe and explicitly
qualified. Vault deletion follows durable confirmation only. Network failures
never mean successful revocation or negative learning observations. All
connector-to-Marty traffic remains restricted to the public Common Gateway;
this worker has no Gateway or core database capability.
