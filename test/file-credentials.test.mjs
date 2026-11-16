// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rename, rm, chmod, symlink, link, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile } from '../src/file-credentials.mjs';
const run = promisify(execFile);
const TOKEN = 'hvs.synthetic_agent_token_000000001';
const denied = { message: 'connector_file_credential_unavailable' };
async function fixture(t) {
  const root = resolve(tmpdir());
  const dir = await mkdtemp(join(root, 'canvas-private-agent-'));
  t.after(async () => {
    assert.equal(dirname(resolve(dir)), root); assert.ok(basename(dir).startsWith('canvas-private-agent-'));
    await rm(dir, { recursive: true, force: true });
  });
  const path = join(dir, 'credential');
  await writeFile(path, TOKEN + '\n', { mode: 0o600 });
  return { dir, path };
}

test('credential providers expose separate custody interfaces and reject ambiguous configuration', async t => {
  const { path } = await fixture(t);
  const database = createConnectorDatabasePasswordFile({ path });
  const vault = createConnectorOpenBaoTokenFile({ path });
  assert.deepEqual(Object.keys(database), ['getPassword']); assert.deepEqual(Object.keys(vault), ['getToken']);
  assert.equal(JSON.stringify(database), '{}'); assert.ok(Object.isFrozen(vault));
  for (const create of [createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile]) {
    for (const value of [undefined, null, [], {}, { path: 'relative' }, { path, token: TOKEN },
      { path, timeoutMs: 0 }, { path, timeoutMs: 10001 }]) assert.throws(() => create(value), denied);
  }
  if (process.platform === 'win32') {
    await assert.rejects(database.getPassword(), denied); await assert.rejects(vault.getToken(), denied);
  }
});

// The deployment contract is POSIX owner/mode/no-follow enforcement. Windows
// explicitly denies acquisition above; its ACLs are not treated as POSIX modes.
const posix = process.platform !== 'win32';
test('private files are reread after atomic agent replacement; password whitespace is preserved', { skip: !posix }, async t => {
  const { dir, path } = await fixture(t);
  const database = createConnectorDatabasePasswordFile({ path });
  assert.equal(await database.getPassword(), TOKEN);
  const replacement = join(dir, 'replacement');
  await writeFile(replacement, '  rotated synthetic password  \r\n', { mode: 0o400 }); await rename(replacement, path);
  assert.equal(await database.getPassword(), '  rotated synthetic password  ');
  await assert.rejects(createConnectorOpenBaoTokenFile({ path }).getToken(), denied);
  await writeFile(replacement, TOKEN + '-rotated', { mode: 0o600 }); await rename(replacement, path);
  assert.equal(await createConnectorOpenBaoTokenFile({ path }).getToken(), TOKEN + '-rotated');
  await writeFile(replacement, '\ufeff' + TOKEN, { mode: 0o600 }); await rename(replacement, path);
  assert.equal(await database.getPassword(), '\ufeff' + TOKEN);
  await assert.rejects(createConnectorOpenBaoTokenFile({ path }).getToken(), denied);
});

test('unsafe permissions, executable files and malformed or oversized contents fail without secret details', { skip: !posix }, async t => {
  const { path } = await fixture(t);
  const provider = createConnectorDatabasePasswordFile({ path });
  for (const mode of [0o644, 0o640, 0o700, 0o000]) {
    await chmod(path, mode); await assert.rejects(provider.getPassword(), denied);
  }
  await chmod(path, 0o600);
  for (const value of ['', 'x'.repeat(4099), 'synthetic\nsecret', TOKEN + '\n\n', Buffer.from([0xff]), 'secret\0value']) {
    await writeFile(path, value); await assert.rejects(provider.getPassword(), denied);
  }
  await rm(path);
  await assert.rejects(provider.getPassword(), error => {
    assert.equal(error.message, denied.message); assert.equal(error.cause, undefined);
    assert.ok(!String(error).includes(path)); return true;
  });
});

test('symlinks, hardlinks, directories and FIFOs are denied without blocking or following them', { skip: !posix }, async t => {
  const { dir, path } = await fixture(t);
  const alias = join(dir, 'alias');
  await symlink(path, alias);
  await assert.rejects(createConnectorDatabasePasswordFile({ path: alias }).getPassword(), denied);
  await rm(alias); await link(path, alias);
  await assert.rejects(createConnectorDatabasePasswordFile({ path }).getPassword(), denied);
  await rm(alias); await mkdir(alias);
  await assert.rejects(createConnectorDatabasePasswordFile({ path: alias }).getPassword(), denied);
  await rm(alias, { recursive: true }); await run('mkfifo', [alias]);
  await assert.rejects(createConnectorDatabasePasswordFile({ path: alias }).getPassword(), denied);
  assert.equal(await createConnectorOpenBaoTokenFile({ path }).getToken(), TOKEN);
});

test('aborted acquisitions fail closed and bounded concurrent readers recover normally', { skip: !posix }, async t => {
  const { path } = await fixture(t);
  const provider = createConnectorOpenBaoTokenFile({ path });
  const already = AbortSignal.abort(); await assert.rejects(provider.getToken({ signal: already }), denied);
  const controller = new AbortController(); const pending = provider.getToken({ signal: controller.signal });
  controller.abort(); await assert.rejects(pending, denied);
  // Allow the aborted open's finally block to release its real filesystem slot.
  await new Promise(resolve => setImmediate(resolve));
  const group = createConnectorOpenBaoTokenFile({ path });
  const outcomes = await Promise.allSettled(Array.from({ length: 5 }, () => group.getToken()));
  assert.equal(outcomes.filter(v => v.status === 'fulfilled').length, 4);
  assert.equal(outcomes.filter(v => v.status === 'rejected').length, 1);
  assert.equal(await group.getToken(), TOKEN);
  await assert.rejects(provider.getToken({ organizationId: 'untrusted' }), denied);
});

// Exercise the actual provider state machine with controlled filesystem
// dependencies. These probes establish deadline/cleanup flow, not OS cancellation.
async function delayedFilesystem(mode) {
  const source = await readFile(new URL('../src/private-file.mjs', import.meta.url), 'utf8');
  const credentials = await readFile(new URL('../src/file-credentials.mjs', import.meta.url), 'utf8');
  const fakeSource = `
    const mode=${JSON.stringify(mode)};
    let openRelease,readRelease,entered,closed;
    const openWait=new Promise(r=>{openRelease=r;});
    const readWait=new Promise(r=>{readRelease=r;});
    export const state={opens:0,closes:0,buffers:[],releaseOpen:()=>openRelease(),releaseRead:()=>readRelease(),
      readEntered:new Promise(r=>{entered=r;}),closedAll:new Promise(r=>{closed=r;})};
    export const constants={O_RDONLY:0,O_NOFOLLOW:1,O_NONBLOCK:2};
    export const realpath=async path=>path;
    const payload=Buffer.from(${JSON.stringify(TOKEN)});
    const stat={isFile:()=>true,nlink:1n,uid:BigInt(process.geteuid()),gid:1n,mode:0o100600n,
      size:BigInt(payload.length),dev:1n,ino:1n,mtimeNs:1n,ctimeNs:1n};
    export const lstat=async()=>stat;
    export async function open(){
      state.opens++; if(mode==='open')await openWait;
      return {stat:async()=>stat,async read(buffer,offset,length,position){
        state.buffers.push(buffer);entered();if(mode==='read')await readWait;
        const n=Math.min(length,payload.length-position);payload.copy(buffer,offset,position,position+n);return {bytesRead:n};
      },async close(){state.closes++;if(state.closes===(mode==='open'?4:1))closed();}};
    }
  `;
  const fakeUrl = 'data:text/javascript,' + encodeURIComponent(fakeSource);
  const dependency = await import(fakeUrl);
  const changed = source.replace("from 'node:fs/promises'", 'from ' + JSON.stringify(fakeUrl));
  assert.notEqual(changed, source);
  const readerUrl = 'data:text/javascript,' + encodeURIComponent(changed);
  const wrapped = credentials.replace("from './private-file.mjs'", 'from ' + JSON.stringify(readerUrl));
  assert.notEqual(wrapped, credentials);
  const actual = await import('data:text/javascript,' + encodeURIComponent(wrapped));
  return { actual, state: dependency.state };
}

test('deadline retains abandoned filesystem slots and closes late handles before recovery', { skip: !posix }, async () => {
  const { actual, state } = await delayedFilesystem('open');
  const provider = actual.createConnectorDatabasePasswordFile({ path: '/synthetic/credential', timeoutMs: 100 });
  const pending = await Promise.allSettled(Array.from({ length: 4 }, () => provider.getPassword()));
  assert.ok(pending.every(v => v.status === 'rejected' && v.reason.message === denied.message));
  await assert.rejects(provider.getPassword(), denied); assert.equal(state.opens, 4);
  state.releaseOpen(); await state.closedAll;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(state.closes, 4); assert.equal(await provider.getPassword(), TOKEN);
});

test('aborted delayed read cannot return a late secret and clears its actual read buffer', { skip: !posix }, async () => {
  const { actual, state } = await delayedFilesystem('read');
  const provider = actual.createConnectorOpenBaoTokenFile({ path: '/synthetic/credential' });
  const controller = new AbortController(); const pending = provider.getToken({ signal: controller.signal });
  await state.readEntered; controller.abort(); await assert.rejects(pending, denied);
  assert.equal(state.closes, 0);
  state.releaseRead(); await state.closedAll;
  assert.ok(state.buffers.length > 0); assert.ok(state.buffers.every(buffer => buffer.every(byte => byte === 0)));
  assert.equal(await provider.getToken(), TOKEN);
});
