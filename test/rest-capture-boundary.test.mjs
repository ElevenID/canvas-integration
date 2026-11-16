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
 ['tenant',s=>s.replace('job?.organizationId!==organizationId','false')],
 ['key-slot',s=>s.replace('job.producerRef!==producerRef','false')],
 ['timestamp-fallback',s=>s.replace("job.effective_time_policy!=='as_of_read'",'false')],
 ['missing-provenance',s=>s.replace('effective_time_source=source','effective_time_source=undefined')],
 ['wrong-secret-purpose',s=>s.replace("purpose:'oauth_access_token'","purpose:'oauth_client_secret'")],
 ['alternate-http',s=>s+"\nimport { request } from 'node:http';\n"],
]) test('REST capture boundary rejects '+name,async()=>{
  const path=await mkdtemp(join(tmpdir(),'canvas-capture-boundary-'));
  try {
    for(const name of ['src','bin','scripts','.github','package.json','package-lock.json']) await cp(name,join(path,name),{recursive:true});
    const file=join(path,'src/rest-capture.mjs');await writeFile(file,replace(await readFile(file,'utf8')));
    await assert.rejects(run('python3',['scripts/check_boundary.py'],{cwd:path}),error=>{assert.match(error.stderr,/Boundary check failed/);return true;});
  } finally {await rm(path,{recursive:true,force:true});}
});
