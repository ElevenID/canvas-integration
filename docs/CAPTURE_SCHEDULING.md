# Durable automatic capture scheduling

The worker can allocate captures for explicitly configured local routes. This
does not create a Core application, binding, grant or verification decision.
Normal Canvas token custody, capture validation and public Gateway admission
remain in effect. The default is no automatic schedules.

Add a `captureSchedules` array to the private worker configuration. Every entry
must match a configured `producers` organization/producer slot. At most 32 entries
are accepted; route and configuration identities must be unique within an
organization. No credentials, transport replacements or authority snapshots are
accepted in schedule entries.

```json
{
  "organizationId": "synthetic-org",
  "producerRef": "synthetic-producer",
  "routeId": "synthetic-route",
  "configurationId": "10000000-0000-4000-8000-000000000015",
  "expectedRevision": 0,
  "routeVersion": 1,
  "intervalMs": 60000,
  "enabled": true
}
```

This is a private deployment-owner directive, not a browser request or a copied
Core permission. The local route must separately be configured and enabled by
the Gateway-authorized administrator workflow. Gateway still derives current
tenant, key, grant, binding and application authority when an observation arrives.

Keep `configurationId` stable across restarts. Its exact original intent has an
immutable receipt. To change or disable a schedule, use a new configuration UUID
and the current local schedule revision as `expectedRevision`. Initial revision
is 0. A competing stale update fails; an old configuration can read its original
receipt but cannot reactivate or overwrite its successor. Removal from one
process configuration alone is not a global revocation: first commit a disabled
successor and reconcile all replicas before retiring the entry.

Migration 015 is installed by a separate schema owner. The first eligible tick
atomically records configuration, allocates one capture and advances the durable
cursor. Cadence is 1000–86400000ms, measured by the database clock after row locks.
Each successful allocation sets the next due time from that tick; missed periods
do not create a catch-up backlog. Polling and provider latency can delay a revisit.

Capture IDs use a stable SHA256 namespace plus organization, producer, route,
configuration UUID and ordinal. The adapter verifies the returned ID against that
exact input. See PostgreSQL16's [binary hash functions](https://www.postgresql.org/docs/16/functions-binarystring.html).
Unknown write replies are not retried inside the adapter; the durable cursor
retains its original capture receipt and pending work.

There is one unresolved capture per route version. Pending, leased, retry and
parked captures block new automatic captures. An unacknowledged outbox item for
the binding revision also blocks allocation, including parked or retired items.
Provider/Gateway outages therefore retain the original work and backoff rather
than generating replacement observation IDs or false completion observations.
Operator recovery or an explicitly reviewed route/binding revision is needed
after terminal failures. Scheduling never resets outbox counters or audit history.

Platform/route revision drift, missing/expired connections and insufficient
Canvas scopes block capture. Database postimage, audit and final connection
expiry checks roll back late changes. A changed route version requires an
explicit successor policy. Current configuration status is only local cadence
state; it is not canonical Marty authority.

The authenticated route `capture` inspection accepts opaque automatic IDs as
well as manual UUIDs. Organization, platform and route predicates remain
server-derived. Manual scheduling operation IDs remain UUID-bound.

Startup checks selected grants, guard triggers, ownership and forbidden
capabilities across reachable memberships, including NOINHERIT membership. It
performs no DDL, grants, configuration writes, queue claims or provider calls.
These credentials remain trusted application SQL, not a tenant/JWT sandbox or
a complete schema-provenance attestation. Production roles require separate
provisioning and qualification.

Local qualification uses `python scripts/test_capture_scheduling.py` for real,
uniquely owned network-isolated PostgreSQL, CAS/concurrency, backpressure,
supersession, lost-reply recovery and unsafe-role denials. The separate physical
driver suite runs actual automatic cadence through TLS PostgreSQL, OpenBao,
Canvas capture and public Gateway HTTPS fixtures, including drain/restart.
Synthetic peers do not qualify a live Canvas tenant or deployed Core/wallet.
