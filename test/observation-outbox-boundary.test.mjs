// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,cp,readFile,writeFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const run=promisify(execFile);
for(const [name,replace] of [
 ['tenant',s=>s.replace('item?.organizationId!==organizationId','false')],
 ['credential-slot',s=>s.replace('item.producerRef!==producerRef','false')],
 ['regenerated-body',s=>s.replace('submitter.submit(item.body)','submitter.submit(bodyFor(item))')],
 ['malformed-ack',s=>s.replace('receipt=undefined','receipt=receipt')],
 ['unbounded-attempts',s=>s.replace('item.attempts>=maxAttempts','false')],
 ['alternate-transport',s=>s+"\nimport { request } from 'node:http';\n"],
]) test('outbox boundary rejects '+name,async()=>{
  const path=await mkdtemp(join(tmpdir(),'canvas-outbox-boundary-'));
  try {
    for(const name of ['src','bin','scripts','.github','package.json','package-lock.json']) await cp(name,join(path,name),{recursive:true});
    const file=join(path,'src/observation-outbox.mjs');await writeFile(file,replace(await readFile(file,'utf8')));
    await assert.rejects(run('python3',['scripts/check_boundary.py'],{cwd:path}),error=>{assert.match(error.stderr,/Boundary check failed/);return true;});
  } finally {await rm(path,{recursive:true,force:true});}
});
