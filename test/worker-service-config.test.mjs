// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rename,rm,mkdir,symlink} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {loadConnectorWorkerConfiguration} from '../src/worker-service-config.mjs';
import {createConnectorGatewayApiKeyFile} from '../src/file-credentials.mjs';
const run=promisify(execFile),posix=process.platform!=='win32';
const denied={message:'connector_worker_configuration_unavailable'},FILE_KEY='synthetic_gateway_organization_key_000001';
async function fixture(t) {
  const dir=resolve(await mkdtemp(join(tmpdir(),'canvas-worker-config-')));t.after(async()=>{
    assert.equal(dirname(dir),resolve(tmpdir()));assert.ok(basename(dir).startsWith('canvas-worker-config-'));await rm(dir,{recursive:true,force:true});
  });
  const paths={};for(const [name,value] of Object.entries({password:'database-only',token:'synthetic_bao_token_000001',api:FILE_KEY,ca:'synthetic-public-ca'})) {
    paths[name]=join(dir,name);await writeFile(paths[name],value+'\n',{mode:0o600});
  }
  const configuration={schemaVersion:1,database:{host:'database.example.test',port:5432,database:'connector',user:'worker',caFile:paths.ca,passwordFile:paths.password},
    keyCustody:{openbaoOrigin:'https://keys.example.test',mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',tokenFile:paths.token},
    canvas:{},gateway:{gatewayOrigin:'https://gateway.example.test'},refreshTargets:[{organizationId:'org',platformId:'platform'}],
    producers:[{organizationId:'org',producerRef:'producer',apiKeyFile:paths.api}],pollIntervalMs:1000};
  const path=join(dir,'configuration.json');
  const save=async(value=configuration)=>writeFile(path,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
  await save();return {dir,path,paths,configuration,save};
}
test('Gateway file provider has only its purpose interface and rejects Windows acquisition',async t=>{
  const f=await fixture(t),provider=createConnectorGatewayApiKeyFile({path:f.paths.api});
  assert.deepEqual(Object.keys(provider),['getApiKey']);assert.ok(Object.isFrozen(provider));assert.equal(JSON.stringify(provider),'{}');
  if(!posix) await assert.rejects(provider.getApiKey(),{message:'connector_file_credential_unavailable'});
});
test('private worker config binds distinct custody, maps CA and refresh slots without secret values',{skip:!posix},async t=>{
  const f=await fixture(t),value=await loadConnectorWorkerConfiguration({path:f.path});
  assert.equal(value.database.ca,'synthetic-public-ca\n');assert.deepEqual(value.refreshTargets,[{organizationId:'org',platformId:'platform'}]);
  assert.equal(await value.database.credentialProvider.getPassword(),'database-only');
  assert.equal(await value.keyCustody.tokenProvider.getToken(),'synthetic_bao_token_000001');
  assert.equal(await value.producers[0].apiKeyProvider.getApiKey(),FILE_KEY);
  assert.equal(JSON.stringify(value).includes(FILE_KEY),false);assert.equal(value.producers[0].apiKeyFile,undefined);
  await writeFile(f.paths.api+'.next','synthetic_gateway_rotated_key_000001\n',{mode:0o600});await rename(f.paths.api+'.next',f.paths.api);
  assert.equal(await value.producers[0].apiKeyProvider.getApiKey(),'synthetic_gateway_rotated_key_000001');
});
test('private capture schedule policies match an explicitly configured producer and reject ambiguous identities',{skip:!posix},async t=>{
  const f=await fixture(t),schedule={organizationId:'org',producerRef:'producer',routeId:'route',configurationId:'10000000-0000-4000-8000-000000000001',expectedRevision:0,routeVersion:1,intervalMs:60000,enabled:true};
  f.configuration.captureSchedules=[schedule];await f.save();
  assert.deepEqual((await loadConnectorWorkerConfiguration({path:f.path})).captureSchedules,[schedule]);
  for(const change of [v=>v.captureSchedules=null,v=>v.captureSchedules[0].organizationId='other',v=>v.captureSchedules[0].producerRef='other',
    v=>v.captureSchedules[0].apiKey='forbidden',v=>v.captureSchedules[0].intervalMs=0,
    v=>v.captureSchedules.push({...v.captureSchedules[0]}),v=>v.captureSchedules.push({...v.captureSchedules[0],routeId:'other-route'})]) {
    const value=structuredClone(f.configuration);change(value);await f.save(value);await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
  }
});

test('worker config rejects raw credentials, unknown fields, malformed targets and unbounded slots',{skip:!posix},async t=>{
  const f=await fixture(t),copy=()=>JSON.parse(JSON.stringify(f.configuration));
  for(const mutate of [v=>{v.database.password='raw';},v=>{v.keyCustody.token='raw';},v=>{v.producers[0].apiKey='raw';},
    v=>{v.producers[0].apiKeyProvider={};},v=>{v.schemaVersion=2;},v=>{v.refreshTargets[0].organizationId='../foreign';},
    v=>{v.producers=Array(33).fill(v.producers[0]);},v=>{v.gateway.route='/internal';}]) {
    const v=copy();mutate(v);await f.save(v);await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
  }
});
test('strict JSON shared decoder rejects duplicate aliases, malformed strings and depth',{skip:!posix},async t=>{
  const f=await fixture(t),source=await readFile(f.path,'utf8');
  for(const text of [source.replace('"schemaVersion":1','"schemaVersion":1,"schemaVersion":1'),
    source.replace('"schemaVersion":1','"schemaVersion":1,"schema\\u0056ersion":1'),source.replace('"worker"','"\\ud800"'),
    '['.repeat(17)+'0'+']'.repeat(17),'\ufeff'+source]) {
    await f.save(text);await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
  }
});
test('worker config denies cross-purpose and cross-tenant aliases but permits same-org key sharing',{skip:!posix},async t=>{
  const f=await fixture(t),original=JSON.parse(JSON.stringify(f.configuration));
  f.configuration.producers.push({...f.configuration.producers[0],producerRef:'second'});await f.save();
  assert.equal((await loadConnectorWorkerConfiguration({path:f.path})).producers.length,2);
  f.configuration.producers[1].organizationId='foreign';await f.save();await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
  await f.save({...original,producers:[{...original.producers[0],apiKeyFile:f.paths.token}]});
  await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
  await mkdir(join(f.dir,'real'));await symlink(f.dir,join(f.dir,'real','alias'),'dir');
  await f.save({...original,producers:[{...original.producers[0],apiKeyFile:join(f.dir,'real','alias','token')}]});
  await assert.rejects(loadConnectorWorkerConfiguration({path:f.path}),denied);
});
test('worker CLI rejects legacy environment and extra arguments with fixed redacted output',async()=>{
  for(const {args=[],env={}} of [{args:['sensitive']},{env:{DATABASE_URL:'sensitive'}},{env:{MARTY_GATEWAY_API_KEY:FILE_KEY}},{}]) {
    await assert.rejects(run(process.execPath,['bin/serve-workers.mjs',...args],{env:{...process.env,...env,CANVAS_CONNECTOR_WORKER_CONFIG_FILE:'/nonexistent-sensitive-path'}}),error=>{
      assert.equal(error.code,1);assert.equal(error.stdout,'');
      assert.deepEqual(JSON.parse(error.stderr),{state:'failed',code:'connector_worker_startup_failed'});return true;
    });
  }
});
test('Gateway file grammar exactly matches the submission adapter key range',{skip:!posix},async t=>{
  const f=await fixture(t),provider=createConnectorGatewayApiKeyFile({path:f.paths.api});
  for(const length of [31,32,512,513]) {
    await writeFile(f.paths.api,'a'.repeat(length),{mode:0o600});
    if(length===32||length===512) assert.equal((await provider.getApiKey()).length,length);
    else await assert.rejects(provider.getApiKey(),{message:'connector_file_credential_unavailable'});
  }
});
test('worker configuration and runtime exports fail closed under browser conditions',async()=>{
  for(const name of ['connector-worker-runtime','worker-service-config'])
    await assert.rejects(run(process.execPath,['--conditions=browser','--input-type=module','-e',`await import('@elevenid/canvas-integration/${name}')`]),error=>{
      assert.match(error.stderr,/server-only/);return true;
    });
});
