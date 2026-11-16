// SPDX-License-Identifier: AGPL-3.0-only
// Internal scheduler only: production composition supplies concrete adapters.
// A timer never releases the capacity held by unfinished adapter work.
export function createWorkerLoop(tasks,intervalMs) {
  if(typeof globalThis.window!=='undefined' || !Array.isArray(tasks) || !tasks.length || tasks.length>97
    || tasks.some(task=>typeof task!=='function') || !Number.isSafeInteger(intervalMs) || intervalMs<1 || intervalMs>60000)
    throw new Error('invalid_connector_worker_loop');
  const selected=tasks.slice();
  let state='created',timer,running,closing,cursor=0;
  function schedule(delay) {
    timer=setTimeout(()=>{
      timer=undefined;
      if(state!=='running') return;
      const task=selected[cursor];cursor=(cursor+1)%selected.length;
      running=Promise.resolve().then(()=>state==='running'?task():undefined).catch(()=>{
        // Adapters persist their own retry/unknown outcomes. No immediate retry
        // or raw exception logging is introduced by the process scheduler.
      }).finally(()=>{
        running=undefined;
        if(state==='running') schedule(intervalMs);
      });
    },delay);
  }
  return Object.freeze({
    start() {
      if(state!=='created') throw new Error('connector_worker_loop_unavailable');
      state='running';schedule(0);
    },
    close() {
      if(closing) return closing;
      state='closing';clearTimeout(timer);
      closing=(async()=>{await running;state='closed';})();
      return closing;
    },
  });
}
