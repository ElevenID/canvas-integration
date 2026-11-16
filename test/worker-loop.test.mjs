// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {setImmediate,setTimeout as pause} from 'node:timers/promises';
import {createWorkerLoop} from '../src/worker-loop.mjs';
test('worker loop holds capacity and drains actual work before closing',async()=>{
  let entered,release,calls=0;
  const started=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
  const loop=createWorkerLoop([async()=>{calls++;entered();await held;}],1);
  loop.start();await started;
  let closed=false;const closing=loop.close().then(()=>{closed=true;});
  await setImmediate();assert.equal(closed,false);assert.equal(calls,1);
  release();await closing;await pause(5);assert.equal(calls,1);
  await loop.close();assert.throws(()=>loop.start(),/connector_worker_loop_unavailable/);
});
test('worker loop rotates tasks after errors without an immediate retry',async()=>{
  const seen=[];let entered,release;
  const started=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
  const loop=createWorkerLoop([async()=>{seen.push('first');throw Error('sensitive provider exception');},
    async()=>{seen.push('second');},async()=>{seen.push('third');entered();await held;}],1);
  loop.start();await started;const closing=loop.close();assert.deepEqual(seen,['first','second','third']);release();await closing;
});
test('closing before the first timer prevents admission',async()=>{
  let calls=0;const loop=createWorkerLoop([async()=>{calls++;}],1);loop.start();await loop.close();await pause(5);assert.equal(calls,0);
  for(const [tasks,interval] of [[[],1],[[null],1],[[()=>{}],0],[[()=>{}],60001],[Array.from({length:98},()=>()=>{}),1]])
    assert.throws(()=>createWorkerLoop(tasks,interval),/invalid_connector_worker_loop/);
});
