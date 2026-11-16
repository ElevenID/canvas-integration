# Agent-managed credential files

The server-only `./file-credentials` export supplies two separate acquisition
interfaces for the OAuth runtime:

```js
import { createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile }
  from '@elevenid/canvas-integration/file-credentials';

const connectorDatabaseCredentialProvider = createConnectorDatabasePasswordFile({
  path: '/run/canvas-connector/database-password', timeoutMs: 1000,
});
const connectorVaultTokenProvider = createConnectorOpenBaoTokenFile({
  path: '/run/canvas-connector/openbao-token', timeoutMs: 1000,
});
```

The first object exposes only `getPassword({signal})`; the second only
`getToken({signal})`. Wire them to the connector database and connector-owned
OpenBao key provider respectively. These files must contain those dedicated
credentials, never Canvas tokens, Gateway API keys or core service credentials.
No environment variables, argv, network, secret cache or fallback are consulted.
Provisioning/renewal remains the credential agent's job.

Acquisition supports POSIX owner/mode enforcement. It requires an absolute path,
a regular single-link file owned by the runtime's effective UID, mode 0400 or 0600,
and no special or executable bits. Windows acquisition fails closed because this
module does not verify Windows ACLs. Use a POSIX deployment with an agent that
writes files as the runtime UID and shares only the intended credential directory.
The parent directory and same-UID actors are trusted; make that directory private
and mount it read-only into the application where deployment supports it.

The final component is opened with no-follow and nonblocking flags. Symlinks,
hardlinks, directories, devices and FIFOs are rejected. At most 4099 bytes are
read, independently of the initial file size. Before/after descriptor metadata
and the currently named file must agree, including inode, owner, mode, size and
modification/change timestamps. Observed replacement or mutation during a read
fails closed. These checks do not prove immunity to adversarial same-UID writes
or compensate for an untrusted parent directory.

Use atomic replacement with a new private regular file in the same trusted
directory, not in-place writes or symlink switching. Every acquisition reopens
the path, so replacement is seen on the next database physical connection or
OpenBao operation. Existing database connections retain the transport's bounded
connection lifetime; changing a password does not revoke an established session.

Contents are strict UTF-8, at most 4096 bytes, with one optional terminal LF/CRLF.
Other controls and embedded newlines are rejected. Database-password whitespace
and a leading UTF-8 BOM are preserved; tokens reject a BOM. OpenBao tokens additionally use the key adapter's bounded token
alphabet. Raw read buffers are cleared; JavaScript strings cannot be reliably
erased. Errors contain no path, contents or original filesystem cause.

The configurable acquisition deadline is 100–10000ms, default 1000ms; caller
cancellation is also honored. Four actual filesystem operations may be pending
per provider. A timed-out or aborted operation retains its slot until its actual
I/O and handle cleanup settle. A late result cannot be returned to the caller.
Timeout does not cancel an operating-system filesystem operation. Keep agent
files on an appropriate local filesystem; excess acquisitions fail rather than
queue without a bound.

Node22 Linux tests cover private files, atomic replacement, unsafe modes, malformed
contents, symlinks/hardlinks/directories/FIFOs, aborts and concurrency. Controlled
filesystem-dependency probes separately exercise delayed opens/reads, deadline
slot retention, late-handle cleanup and cleared buffers. They establish state-machine
behavior, not operating-system cancellation. The Linux PostgreSQL/OpenBao contract
also exercises actual password/token file rotation and denied stale credentials;
Windows physical fixtures retain explicit synthetic in-process providers and do
not qualify this POSIX layer. Exact Linux CI remains the published-candidate gate.

Implementation follows the Node22 [filehandle APIs and filesystem flags](https://nodejs.org/docs/latest-v22.x/api/fs.html#fspromisesopenpath-flags-mode).
Deployment agents, renewal/revocation policy, TLS loading/rotation, least-privilege
ownership, service bootstrap and worker scheduling still need qualification.
