// SPDX-License-Identifier: AGPL-3.0-only
import { open, lstat, constants } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

const unavailable = () => new Error('connector_file_credential_unavailable');
const maximum = 4098; // 4096 UTF-8 bytes plus one optional CRLF.
function provider(configuration, purpose) {
  if (typeof globalThis.window !== 'undefined' || configuration === null || typeof configuration !== 'object'
      || Array.isArray(configuration) || Object.keys(configuration).some(key => !['path', 'timeoutMs'].includes(key))) throw unavailable();
  const { path, timeoutMs = 1000 } = configuration;
  if (typeof path !== 'string' || !isAbsolute(path) || path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)
      || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw unavailable();
  let active = 0;
  const same = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
    .every(name => a[name] === b[name]);
  const privateFile = stat => stat.isFile() && stat.nlink === 1n && stat.uid === BigInt(process.geteuid())
    && (stat.mode & 0o7177n) === 0n && (stat.mode & 0o400n) !== 0n && stat.size > 0n && stat.size <= BigInt(maximum);
  async function acquire(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)
        || Object.keys(options).some(key => key !== 'signal')) throw unavailable();
    const { signal } = options;
    // POSIX permission/owner and no-follow enforcement have no Windows ACL
    // equivalent here. Do not silently weaken those checks on that platform.
    if (process.platform === 'win32' || typeof process.geteuid !== 'function'
        || !Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW <= 0
        || !Number.isInteger(constants.O_NONBLOCK) || constants.O_NONBLOCK <= 0
        || (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted || active >= 4) throw unavailable();
    active++;
    let expired = false, timer, aborted;
    const check = () => { if (expired || signal?.aborted) throw unavailable(); };
    const read = (async () => {
      let handle;
      const buffer = Buffer.alloc(maximum + 1);
      try {
        check();
        handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        check();
        const before = await handle.stat({ bigint: true });
        if (!privateFile(before)) throw unavailable();
        let count = 0;
        while (count < buffer.length) {
          check();
          const { bytesRead } = await handle.read(buffer, count, buffer.length - count, count);
          if (bytesRead === 0) break;
          count += bytesRead;
        }
        check();
        const after = await handle.stat({ bigint: true });
        const named = await lstat(path, { bigint: true });
        if (!privateFile(after) || !privateFile(named) || !same(before, after) || !same(after, named)
            || BigInt(count) !== before.size || count > maximum) throw unavailable();
        check();
        let value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, count));
        if (value.endsWith('\r\n')) value = value.slice(0, -2);
        else if (value.endsWith('\n')) value = value.slice(0, -1);
        if (!value || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f-\u009f]/.test(value)
            || (purpose === 'openbao' && !/^[A-Za-z0-9._~-]{16,4096}$/.test(value))) throw unavailable();
        check();
        return value;
      } finally {
        buffer.fill(0);
        await handle?.close();
      }
    })().finally(() => { active--; });
    const deadline = new Promise((_, reject) => {
      aborted = () => { expired = true; reject(unavailable()); };
      timer = setTimeout(aborted, timeoutMs);
      signal?.addEventListener('abort', aborted, { once: true });
    });
    try { const value = await Promise.race([read, deadline]); check(); return value; }
    catch { throw unavailable(); }
    finally { clearTimeout(timer); signal?.removeEventListener('abort', aborted); }
  }
  return Object.freeze(purpose === 'database' ? { getPassword: acquire } : { getToken: acquire });
}

export function createConnectorDatabasePasswordFile(configuration) { return provider(configuration, 'database'); }
export function createConnectorOpenBaoTokenFile(configuration) { return provider(configuration, 'openbao'); }
