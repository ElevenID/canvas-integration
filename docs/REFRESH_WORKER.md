# Durable connector token refresh

`./refresh-worker` provides `runOnce(organizationId, platformId)` for one due
connection. The repository claims only enabled, current-configuration connected
records with a refresh reference and access expiry within five minutes. It
locks the platform, connection and attempt in that order. A partial unique index
permits only one active attempt per organization/platform. Claims carry an
expiring lease and exact connection/configuration revisions.

The worker loads client/refresh secrets from the connector vault, then commits
an `exchanging` marker before invoking the existing pinned Canvas HTTPS refresh
provider. A claimed attempt may be reclaimed after expiry only if no exchange
started. Exchanging and reconciliation-required attempts are never reclaimed
automatically, even after lease expiry. Process death, network failure, invalid
provider output, secret-storage errors or uncertain acknowledgments require
reconciliation rather than an automatic repeat exchange.

Successful output is encrypted under fresh access/optional-refresh references.
If Canvas omits a new refresh token, the previous refresh reference is retained,
as described in the official [Canvas OAuth overview](https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth).
Expiry is conservatively measured from exchange start. Publication atomically
checks the lease, current configuration and original connection revision, then
stores new references/expiry and marks the attempt published. Disabled, changed
or disconnected platforms cannot receive the refreshed connection.

Only a confirmed publication permits obsolete local ciphertext deletion.
Do not revoke the old access token during refresh: revocation may affect the
same authorization that produced the new token. Old/new references remain in
the published attempt for cleanup reconciliation. An uncertain publication
preserves all references; reread the durable attempt/connection before cleanup.
Failed vault publication can leave encrypted orphan records identified by
platform/purpose/creation metadata; do not guess which records are disposable.

Provision explicit query/provider deadlines, external key custody and
least-privilege roles. A scheduler/poller, reconciliation administration,
orphan/attempt retention policy, operator alerts and deployed fresh-login/refresh
qualification remain required. This module does not install unattended work.
No connector-to-core database access or private service calls are introduced.
Transport errors never become negative learning observations.

PostgreSQL contracts exercise claim exclusion, expired unstarted replacement,
stale leases, concrete local HTTPS refresh, reusable refresh tokens, configuration
changes, provider failure and a lost acknowledgment after actual publication.
They use synthetic Canvas responses and keys, not a live Canvas tenant.
