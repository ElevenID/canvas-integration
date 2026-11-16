// SPDX-License-Identifier: AGPL-3.0-only
import { open, lstat, realpath, constants } from 'node:fs/promises';
import { isAbsolute, dirname, basename, join } from 'node:path';

const unavailable = () => new Error('connector_private_file_unavailable');
export function createPrivateTextFile(configuration = {}) {
  if (typeof globalThis.window !== 'undefined' || configuration === null || typeof configuration !== 'object'
      || Array.isArray(configuration) || Object.keys(configuration).some(key => !['path', 'timeoutMs', 'maxBytes'].includes(key))) throw unavailable();
  const { path, timeoutMs = 1000, maxBytes = 65536 } = configuration;
  const maximum = maxBytes;
  if (typeof path !== 'string' || !isAbsolute(path) || path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)
      || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 65536
      || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw unavailable();
  let active = 0;
  const same = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
    .every(name => a[name] === b[name]);
  const privateFile = stat => stat.isFile() && stat.nlink === 1n && stat.uid === BigInt(process.geteuid())
    && (stat.mode & 0o7177n) === 0n && (stat.mode & 0o400n) !== 0n && stat.size > 0n && stat.size <= BigInt(maximum);
  async function acquire(options = {}, readContents = true) {
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
      const buffer = Buffer.alloc(readContents ? maximum + 1 : 0);
      try {
        check();
        const canonicalPath = join(await realpath(dirname(path)), basename(path));
        check();
        handle = await open(canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        check();
        const before = await handle.stat({ bigint: true });
        if (!privateFile(before)) throw unavailable();
        let count = 0;
        while (readContents && count < buffer.length) {
          check();
          const { bytesRead } = await handle.read(buffer, count, buffer.length - count, count);
          if (bytesRead === 0) break;
          count += bytesRead;
        }
        check();
        const after = await handle.stat({ bigint: true });
        const named = await lstat(canonicalPath, { bigint: true });
        if (!privateFile(after) || !privateFile(named) || !same(before, after) || !same(after, named)
            || (readContents && BigInt(count) !== before.size) || count > maximum) throw unavailable();
        check();
        if (!readContents) return Object.freeze({ path: canonicalPath, dev: before.dev, ino: before.ino });
        const value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, count));
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
  return Object.freeze({ readText: options => acquire(options, true), inspect: options => acquire(options, false) });
}
