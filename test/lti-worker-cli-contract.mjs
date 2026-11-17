// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rename,rm} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export async function ltiWorkerCliContract(configuration,{configurationId,expectedRevision,key,held,release,wait,pool,organizationId,producerRef,count,setKey}) {
 const directory=resolve(await mkdtemp(join(tmpdir(),'canvas-lti-worker-cli-'))),children=[];
 assert.equal(dirname(directory),resolve(tmpdir()));assert.match(basename(directory),/^canvas-lti-worker-cli-/);
 const save=async(name,value)=>{const path=join(directory,name);await writeFile(path+'.next',value+'\n',{mode:0o600});await rename(path+'.next',path);return path;};
 try {
  const {ca:databaseCa,credentialProvider,...database}=configuration.database;
  const {ca:baoCa,tokenProvider,...keyCustody}=configuration.keyCustody;
  const {ca:canvasCa,...canvas}=configuration.canvas,{ca:gatewayCa,...gateway}=configuration.gateway;
  const password=await credentialProvider.getPassword(),baoToken=await tokenProvider.getToken();
  const apiFile=await save('gateway-key',key),configFile=join(directory,'worker.json');
  const privateConfig={schemaVersion:1,captureMode:'lti',database:{...database,caFile:await save('database-ca',databaseCa),passwordFile:await save('database-password',password)},
   keyCustody:{...keyCustody,caFile:await save('bao-ca',baoCa),tokenFile:await save('bao-token',baoToken)},
   canvas:{...canvas,caFile:await save('canvas-ca',canvasCa)},gateway:{...gateway,caFile:await save('gateway-ca',gatewayCa)},
   refreshTargets:[],producers:[{organizationId,producerRef,apiKeyFile:apiFile}],pollIntervalMs:100,
   captureSchedules:[{...configuration.captureSchedules[0],configurationId,expectedRevision}]};
  await save('worker.json',JSON.stringify(privateConfig));
  const rotated='synthetic_lti_worker_gateway_rotated_000001';
  async function start(){
   const child=spawn(process.execPath,[fileURLToPath(new URL('../bin/serve-workers.mjs',import.meta.url))],{
    env:{PATH:process.env.PATH,CANVAS_CONNECTOR_WORKER_CONFIG_FILE:configFile},stdio:['ignore','pipe','pipe']});
   let stdout='',stderr='',closing;
   child.stdout.on('data',c=>{stdout+=c;if(stdout.length>8192)child.kill('SIGKILL');});child.stderr.on('data',c=>{stderr+=c;if(stderr.length>8192)child.kill('SIGKILL');});
   const exited=new Promise((r,j)=>{child.on('error',j);child.on('close',(code,signal)=>r({code,signal}));});
   const timer=setTimeout(()=>child.kill('SIGKILL'),20000);
   const close=()=>closing??=(async()=>{
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    const outcome=await exited;clearTimeout(timer);assert.deepEqual(outcome,{code:0,signal:null});assert.equal(stderr,'');
    assert.ok(stdout.includes('"state":"stopped"'));
    for(const secret of [key,rotated,password,baoToken])assert.equal(stdout.includes(secret)||stderr.includes(secret),false);
   })();
   const handle={close,draining:()=>stdout.includes('"state":"draining"'),stopped:()=>stdout.includes('"state":"stopped"'),child};children.push(handle);
   await wait(async()=>{if(child.exitCode!==null||child.signalCode!==null)assert.fail('LTI CLI startup failed');return stdout.includes('"state":"running"');});return handle;
  }
  const first=await start();let deadlineTimer;
  try{await Promise.race([held,new Promise((_,j)=>{deadlineTimer=setTimeout(()=>j(Error('LTI CLI held delivery timeout')),6000);})]);}
  finally{clearTimeout(deadlineTimer);}
  await save('gateway-key',rotated);const closing=first.close();await wait(async()=>first.draining());
  assert.equal(first.stopped(),false);assert.equal(first.child.exitCode,null);assert.equal(first.child.signalCode,null);release();await closing;
  assert.equal(count(),3);setKey(rotated);
  const second=await start();await wait(async()=>count()>=4&&(await pool.query("SELECT count(*)::float8 AS n FROM canvas_connector.observation_outbox WHERE organization_id=$1 AND producer_ref=$2 AND phase='acknowledged'",[organizationId,producerRef])).rows[0].n===4);
  await second.close();assert.equal(count(),4);
  console.log('Actual POSIX LTI-only worker CLI private configuration, rotated Gateway key, original cadence restart and SIGTERM delivery drain PASS');
 }finally{release();for(const c of children)await c.close();assert.equal(dirname(directory),resolve(tmpdir()));assert.match(basename(directory),/^canvas-lti-worker-cli-/);await rm(directory,{recursive:true});}
}
