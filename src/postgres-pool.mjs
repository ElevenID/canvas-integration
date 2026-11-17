// SPDX-License-Identifier: AGPL-3.0-only
import PgClient from 'pg/lib/client.js';
import PgPool from 'pg-pool';

const unavailable=()=>new Error('connector_database_unavailable');
const identifier=value=>typeof value==='string' && /^[A-Za-z_][A-Za-z0-9_-]{0,62}$/.test(value);
const duration=value=>Number.isSafeInteger(value) && value>=100 && value<=30000;
// A provider can be shared by multiple pools. Keep fresh password acquisitions
// within the private-file reader's four-I/O budget without caching/coalescing
// credentials. Waiting is bounded and consumes the original connect deadline.
const credentialGates=new WeakMap();
function credentialSlot(provider,signal) {
  let gate=credentialGates.get(provider);
  if(!gate){gate={active:0,waiting:[]};credentialGates.set(provider,gate);}
  return new Promise((resolve,reject)=>{
    if(signal.aborted||gate.waiting.length>=16)return reject(unavailable());
    const waiter={grant:null,abort:null};
    waiter.abort=()=>{
      const index=gate.waiting.indexOf(waiter);
      if(index>=0)gate.waiting.splice(index,1);
      signal.removeEventListener('abort',waiter.abort);reject(unavailable());
    };
    waiter.grant=()=>{
      signal.removeEventListener('abort',waiter.abort);
      if(signal.aborted){reject(unavailable());return;}
      gate.active++;let released=false;
      resolve(()=>{
        if(released)return;released=true;gate.active--;
        while(gate.active<4&&gate.waiting.length)gate.waiting.shift().grant();
      });
    };
    if(gate.active<4)waiter.grant();
    else {gate.waiting.push(waiter);signal.addEventListener('abort',waiter.abort,{once:true});}
  });
}
/** Connector-owned autocommit transport only. No URI/environment defaults,
 * transaction handles, migrations, retry, credentials in errors or core calls.
 * Only trusted repository/vault SQL belongs here; this is not a public SQL API.
 */
export function createConnectorPostgresPool(configuration={}) {
  if(configuration===null || typeof configuration!=='object' || Array.isArray(configuration)) throw unavailable();
  const {host,port,database,user,ca,credentialProvider,maxConnections=4,connectTimeoutMs=5000,queryTimeoutMs=10000}=configuration;
  if(typeof globalThis.window!=='undefined' || Object.keys(configuration).some(key=>![
    'host','port','database','user','ca','credentialProvider','maxConnections','connectTimeoutMs','queryTimeoutMs'].includes(key))
      || typeof host!=='string' || host.length>253 || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(host)
      || host.includes('..') || !Number.isSafeInteger(port) || port<1 || port>65535
      || !identifier(database) || !identifier(user) || typeof credentialProvider?.getPassword!=='function'
      || typeof ca!=='string' || ca.length>65536 || !ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(ca)
      || !Number.isSafeInteger(maxConnections) || maxConnections<1 || maxConnections>16
      || !duration(connectTimeoutMs) || !duration(queryTimeoutMs)) throw unavailable();
  // Explicit pure-JS Client import bypasses pg's environment-selected native entry.
  // Every connection parameter with an environment fallback is explicit/truthy.
  // binary=false is enforced on the resulting parameters because pg's val()
  // treats a false config value as absent (and otherwise consults PGBINARY).
  class ConnectorClient extends PgClient {
    constructor(options) {
      super(options);
      this.connectionParameters.binary=false;
      this.binary=false;
    }
    connect(callback) {
      const controller=new AbortController();let completed=false;let timer;
      const stream=this.connection.stream;
      const closed=()=>finish(unavailable());
      const finish=error=>{
        if(completed)return;completed=true;clearTimeout(timer);
        stream.removeListener('close',closed);controller.abort();
        // Pool error removal alone can leave failed authentication sockets open.
        if(error) this.connection.stream.destroy();
        callback(error);
      };
      stream.once('close',closed);
      timer=setTimeout(()=>finish(unavailable()),connectTimeoutMs);
      // Fetch even when the server requests no password (e.g. HBA trust).
      // The same deadline covers credential acquisition and the TLS handshake.
      credentialSlot(credentialProvider,controller.signal).then(async release=>{
        try {
          if(completed||controller.signal.aborted)throw unavailable();
          return await credentialProvider.getPassword({signal:controller.signal});
        }finally{release();}
      }).then(secret=>{
        if(completed || controller.signal.aborted || stream.destroyed) return finish(unavailable());
        if(typeof secret!=='string' || !secret.length || secret.length>4096 || /[\x00-\x1f\x7f]/.test(secret)) return finish(unavailable());
        this.connectionParameters.password=this.password=secret;
        super.connect(finish);
      }).catch(()=>finish(unavailable()));
    }
  }
  const pool=new PgPool({Client:ConnectorClient,host,port,database,user,password:()=>{throw unavailable();},
    ssl:{ca,rejectUnauthorized:true,minVersion:'TLSv1.2'},sslnegotiation:'postgres',
    options:'-c search_path=pg_catalog,canvas_connector',replication:'false',client_encoding:'UTF8',
    application_name:'elevenid-canvas-connector',fallback_application_name:'elevenid-canvas-connector',
    connectionTimeoutMillis:connectTimeoutMs,query_timeout:queryTimeoutMs,
    statement_timeout:Math.max(50,Math.floor(queryTimeoutMs*0.8)),lock_timeout:Math.min(5000,Math.max(25,Math.floor(queryTimeoutMs*0.5))),
    idle_in_transaction_session_timeout:queryTimeoutMs,max:maxConnections,min:0,
    idleTimeoutMillis:10000,maxLifetimeSeconds:300,allowExitOnIdle:false});
  // pg removes failed idle clients itself. Never log raw errors or credentials.
  pool.on('error',()=>{});
  pool.on('connect',client=>client.on('error',()=>{}));
  let closed=false;let active=0;let ending;
  return Object.freeze({
    async query(text,values=[]) {
      if(closed || active>=maxConnections || typeof text!=='string' || Buffer.byteLength(text)>32768
          || !/^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(text) || !Array.isArray(values) || values.length>64) throw unavailable();
      active++;let client;let failed=true;
      try {
        client=await pool.connect();
        if(closed || client.getTransactionStatus()!=='I') throw unavailable();
        const result=await client.query({text,values,queryMode:'extended'});
        if(client.getTransactionStatus()!=='I' || !Array.isArray(result?.rows)) throw unavailable();
        failed=false;return result;
      } catch {throw unavailable();} finally {client?.release(failed);active--;}
    },
    async close() {
      closed=true;
      try {ending??=pool.end();await ending;} catch {throw unavailable();}
    },
  });
}
