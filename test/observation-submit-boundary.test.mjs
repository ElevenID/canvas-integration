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
  ['tls',s=>s.replace('rejectUnauthorized:true','rejectUnauthorized:false')],
  ['private-path',s=>s.replace('/v1/evidence/observations','/internal/evidence')],
  ['tenant-header',s=>s+"\nconst forged='X-Organization-ID';\n"],
  ['body-rewrite',s=>s.replace('encodeExternalObservation(envelope)!==body','false')],
  ['idempotency',s=>s.replace("'Idempotency-Key':envelope.observation_id","'Idempotency-Key':'new-random-id'")],
  ['alternate-transport',s=>s+"\nimport { request } from 'node:http';\n"],
]) test('observation submission boundary rejects '+name,async()=>{
  const path=await mkdtemp(join(tmpdir(),'canvas-observation-boundary-'));
  try {
    for(const name of ['src','bin','scripts','.github','package.json','package-lock.json']) await cp(name,join(path,name),{recursive:true});
    const file=join(path,'src/observation-submit.mjs');await writeFile(file,replace(await readFile(file,'utf8')));
    await assert.rejects(run('python3',['scripts/check_boundary.py'],{cwd:path}),error=>{assert.match(error.stderr,/Boundary check failed/);return true;});
  } finally {await rm(path,{recursive:true,force:true});}
});
