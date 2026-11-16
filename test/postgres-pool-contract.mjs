// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFile,writeFile } from 'node:fs/promises';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { execFileSync } from 'node:child_process';
import { initialOAuthCustodyContract } from './initial-oauth-custody-contract.mjs';
import { initialOAuthLifecycleContract } from './initial-oauth-lifecycle-contract.mjs';
import { oauthAttemptRecoveryContract } from './oauth-attempt-recovery-contract.mjs';
import { connectionAdministrationContract } from './connection-admin-contract.mjs';
import { platformAdministrationContract } from './platform-admin-contract.mjs';
import { oauthClientProvisioningContract } from './oauth-client-provisioning-contract.mjs';

const file=process.argv[2];const stage=process.argv[3];
assert.match(file??'',/canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);
const f=JSON.parse(await readFile(file,'utf8'));
const configuration={host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_runtime',ca:f.ca,
  credentialProvider:{getPassword:async()=> 'synthetic-driver-runtime'},connectTimeoutMs:1000,queryTimeoutMs:2000,maxConnections:16};
const pool=createConnectorPostgresPool(configuration);
const keyProvider=createOpenBaoKeyProvider({openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',
  keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}});
const vault=createEncryptedVault({pool,keyProvider});
const denied=operation=>assert.rejects(operation,error=>{
  assert.equal(error.message,'connector_database_unavailable');assert.equal(error.cause,undefined);return true;
});
const scoped={platformId:'driver-platform',provider:'canvas',purpose:'oauth_access_token'};
try {
 if(stage==='initial') {
  const container=process.argv[4];
  assert.match(container??'',/^canvas-pg-driver-[a-f0-9]{32}$/);
  await initialOAuthCustodyContract(pool,{keyProvider,ownerQuery:async sql=>{
    execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,encoding:'utf8'});
  }});
  await initialOAuthLifecycleContract(pool,{keyProvider});
  await connectionAdministrationContract(pool,{ownerQuery:async sql=>{
    execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,encoding:'utf8'});
  }});
  await platformAdministrationContract(pool,{ownerQuery:async sql=>{
    execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,encoding:'utf8'});
  }});
  await oauthClientProvisioningContract(pool,{keyProvider,ownerQuery:async sql=>{
    execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,encoding:'utf8'});
  }});
  await oauthAttemptRecoveryContract(pool,{keyProvider,ownerQuery:async sql=>{
    execFileSync('docker',['exec','-i',container,'psql','-X','-q','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'],{input:sql,encoding:'utf8'});
  }});
  const [identity]=(await pool.query(`SELECT current_user AS identity,pg_has_role(current_user,'postgres','MEMBER') AS privileged,
    (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS encrypted`)).rows;
  assert.deepEqual(identity,{identity:'canvas_runtime',privileged:false,encrypted:true});
  assert.deepEqual((await pool.query('SELECT $1::text AS value,$2::float8 AS number,$3::bytea AS bytes,$4::text[] AS items',
    ["quoted'; SELECT 1; --",2.5,Buffer.from([0,255]),['one','two']])).rows,
    [{value:"quoted'; SELECT 1; --",number:2.5,bytes:Buffer.from([0,255]),items:['one','two']}]);
  await denied(()=>pool.query('SELECT * FROM unrelated_private.denied'));
  await denied(()=>pool.query('SELECT 1; SELECT 2'));
  await denied(()=>pool.query('BEGIN'));
  const repository=createPostgresRepository(pool);
  assert.equal((await repository.getPlatform('driver-org','driver-platform')).configVersion,1);
  const now=Date.now();const authorization={stateHash:'a'.repeat(64),browserBindingHash:'b'.repeat(64),
    organizationId:'driver-org',platformId:'driver-platform',platformConfigVersion:1,canvasOrigin:'https://canvas.example.test',
    clientId:'synthetic-client',clientSecretRef:'synthetic-client-ref',capabilities:['catalog'],scopes:['read'],
    redirectUri:'https://connector.example.test/oauth/callback',createdAt:now,expiresAt:now+60000};
  assert.equal(await repository.saveAuthorization(authorization),true);
  assert.equal(await repository.consumeAuthorization(authorization.stateHash,now,'c'.repeat(64)),null);
  const winners=await Promise.all(Array.from({length:8},()=>repository.consumeAuthorization(authorization.stateHash,now,authorization.browserBindingHash)));
  assert.equal(winners.filter(Boolean).length,1);
  f.oldRef=await vault.put('driver-org',scoped,'canvas-synthetic-access-one');
  assert.equal(await vault.get('driver-org',f.oldRef,scoped),'canvas-synthetic-access-one');
  const stored=(await pool.query('SELECT key_id,ciphertext,nonce,tag FROM canvas_connector.secrets WHERE reference=$1',[f.oldRef])).rows[0];
  assert.equal(stored.key_id,'canvas-key-one');assert.ok(Buffer.isBuffer(stored.ciphertext));
  // Exercise actual repository CTE writes through this production transport,
  // not only through the older psql bridge used for fault injection.
  const connection={...authorization,accessTokenRef:f.oldRef,refreshTokenRef:null,tokenExpiresAt:now+3600000};
  assert.equal(await repository.publishConnection(connection,1),true);
  assert.equal(await repository.markConnected('driver-org','driver-platform',1,'synthetic-client',['catalog'],['read']),true);
  await repository.markReauthorizationRequired('driver-org','driver-platform');
  assert.equal((await repository.connection('driver-org','driver-platform')).status,'reauthorization_required');
  assert.equal(await repository.markConnected('driver-org','driver-platform',1,'synthetic-client',['catalog'],['read']),false);
  assert.equal(await repository.disconnect('driver-org','driver-platform'),true);
  assert.equal(await repository.connection('driver-org','driver-platform'),null);

  assert.equal(stored.ciphertext.includes(Buffer.from('canvas-synthetic-access-one')),false);
  await assert.rejects(()=>vault.get('driver-org',f.oldRef,{...scoped,platformId:'foreign-platform'}),/connector_vault_unavailable/);
  await writeFile(file,JSON.stringify(f));
  for(const overrides of [{host:'127.0.0.1'},{ca:f.untrustedCa},{credentialProvider:{getPassword:async()=> 'synthetic-wrong-password'}},
    {credentialProvider:{getPassword:async()=> ''}}, {credentialProvider:{getPassword:()=>new Promise(()=>{})},connectTimeoutMs:300}]) {
    const negative=createConnectorPostgresPool({...configuration,...overrides});
    try {await denied(()=>negative.query('SELECT 1'));} finally {await negative.close();}
  }
  const bounded=createConnectorPostgresPool({...configuration,queryTimeoutMs:250,maxConnections:1});
  try {
    await denied(()=>bounded.query('SELECT pg_sleep(2)'));
    assert.equal((await bounded.query('SELECT 1 AS ok')).rows[0].ok,1);
    const running=bounded.query('SELECT pg_sleep(0.05)');
    await denied(()=>bounded.query('SELECT 1'));await running;
  } finally {await bounded.close();}
  // Explicit parameters prevail over hostile ambient libpq defaults; no pg-native entrypoint.
  const previous={};for(const [name,value] of Object.entries({PGHOST:'unreachable.invalid',PGPORT:'1',PGUSER:'postgres',
    PGDATABASE:'unrelated',PGPASSWORD:'ambient-wrong',PGSSLMODE:'disable',PGOPTIONS:'-c search_path=unrelated_private',
    PGBINARY:'1',PGREPLICATION:'database',PGSSLNEGOTIATION:'direct',NODE_PG_FORCE_NATIVE:'1'})) {
    previous[name]=process.env[name];process.env[name]=value;
  }
  const explicit=createConnectorPostgresPool(configuration);
  try {
    assert.equal((await explicit.query('SELECT current_user AS identity')).rows[0].identity,'canvas_runtime');
    assert.equal((await explicit.query('SELECT $1::bytea AS bytes',[Buffer.from([0,255])])).rows[0].bytes.toString('hex'),'00ff');
  } finally {
    await explicit.close();for(const [name,value] of Object.entries(previous)){if(value===undefined)delete process.env[name];else process.env[name]=value;}
  }
 } else if(stage==='rotated') {
  assert.equal(await vault.get('driver-org',f.oldRef,scoped),'canvas-synthetic-access-one');
  f.newRef=await vault.put('driver-org',scoped,'canvas-synthetic-access-two');
  assert.equal(await vault.get('driver-org',f.newRef,scoped),'canvas-synthetic-access-two');
  const records=(await pool.query('SELECT key_id FROM canvas_connector.secrets WHERE organization_id=\'driver-org\' ORDER BY key_id')).rows;
  assert.deepEqual(records,[{key_id:'canvas-key-one'},{key_id:'canvas-key-two'}]);await writeFile(file,JSON.stringify(f));
 } else if(stage==='key-denied') {
  await assert.rejects(()=>vault.get('driver-org',f.oldRef,scoped),/connector_vault_unavailable/);
  await assert.rejects(()=>vault.put('driver-org',scoped,'must-not-persist'),/connector_vault_unavailable/);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM canvas_connector.secrets WHERE organization_id=\'driver-org\'')).rows[0].n,2);
 } else if(stage==='trust-custody') {
  let calls=0;
  const trusted=createConnectorPostgresPool({...configuration,credentialProvider:{getPassword:async()=>{calls++;return 'synthetic-explicit-password';}}});
  try {assert.equal((await trusted.query('SELECT current_user AS identity')).rows[0].identity,'canvas_runtime');assert.equal(calls,1);}
  finally {await trusted.close();}
  for(const getPassword of [async()=>{throw new Error('must-remain-private');},async()=>'',()=>new Promise(()=>{})]) {
    const rejected=createConnectorPostgresPool({...configuration,connectTimeoutMs:150,credentialProvider:{getPassword}});
    try {await denied(()=>rejected.query('SELECT 1'));} finally {await rejected.close();}
  }
  let aborted=false;
  const late=createConnectorPostgresPool({...configuration,connectTimeoutMs:100,credentialProvider:{getPassword:({signal})=>new Promise(resolve=>{
    signal.addEventListener('abort',()=>{aborted=true;},{once:true});setTimeout(()=>resolve('synthetic-late-password'),200);
  })}});
  try {await denied(()=>late.query('SELECT 1'));assert.equal(aborted,true);await new Promise(resolve=>setTimeout(resolve,250));}
  finally {await late.close();}
 } else if(stage==='database-denied') {
  await denied(()=>pool.query('SELECT 1'));
 } else throw new Error('unknown_fixture_stage');
} finally {await pool.close();await pool.close();}
await denied(()=>pool.query('SELECT 1'));
console.log('Real PostgreSQL/OpenBao/vault '+stage+' contracts passed');
