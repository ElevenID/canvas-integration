// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
const valid={host:'db.connector.example',port:5432,database:'canvas',user:'canvas_runtime',ca:'-----BEGIN CERTIFICATE-----',
  credentialProvider:{getPassword:async()=> 'synthetic-only'}};
for(const change of [{host:undefined},{host:'/tmp/postgres'},{host:'db.example.'},{host:'db..example'},
  {port:0},{port:'5432'},{database:''},{user:undefined},{ca:undefined},{ca:'-----BEGIN CERTIFICATE----- PRIVATE KEY'},
  {credentialProvider:null},{maxConnections:0},{maxConnections:17},{queryTimeoutMs:0},{connectTimeoutMs:Infinity},
  {connectionString:'postgres://ambient'}, {ssl:false}, {password:'plaintext-extra'}]) {
 test('PostgreSQL pool rejects incomplete or alternate configuration '+JSON.stringify(change),()=>{
  assert.throws(()=>createConnectorPostgresPool({...valid,...change}),/connector_database_unavailable/);
 });
}
test('PostgreSQL transport is denied under browser package condition',async()=>{
 await assert.rejects(promisify(execFile)(process.execPath,['--conditions=browser','--input-type=module','-e',
  "await import('@elevenid/canvas-integration/postgres-pool')"]),error=>{assert.match(error.stderr,/server-only/);return true;});
});
test('Closed pool never obtains credentials or starts a connection',async()=>{
 let calls=0;const pool=createConnectorPostgresPool({...valid,credentialProvider:{getPassword:async()=>{calls++;return 'synthetic-only';}}});
 await pool.close();await assert.rejects(()=>pool.query('SELECT 1'),/connector_database_unavailable/);assert.equal(calls,0);
});

test('Pure JS driver import bypasses ambient native-driver selection',async()=>{
 await promisify(execFile)(process.execPath,['--input-type=module','-e',
  "await import('@elevenid/canvas-integration/postgres-pool')"],{env:{...process.env,NODE_PG_FORCE_NATIVE:'1'}});
});
