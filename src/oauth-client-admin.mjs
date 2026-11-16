// SPDX-License-Identifier: AGPL-3.0-only
import {clientId,clientSecret,clientProvisioningInput,clientProvisioningReceipt} from './oauth-client-contract.mjs';
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const unavailable=()=>new Error('connector_oauth_client_unavailable');
export function createOAuthClientStore(pool,vault) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function' || typeof vault?.stageClientConfiguration!=='function') throw unavailable();
  const scope=value=>{if(!id(value?.organizationId) || !id(value?.platformId)) throw unavailable();};
  async function execute(sql,values) {
    try {
      const result=await pool.query(sql,values);
      if(result.rows.length!==1 || !Object.hasOwn(result.rows[0],'result')) throw unavailable();
      return result.rows[0].result;
    } catch {throw unavailable();}
  }
  return Object.freeze({
    async inspect(value) {
      scope(value);
      const result=await execute(`SELECT (SELECT jsonb_build_object('clientId',c.client_id,'clientSecretRef',c.client_secret_ref,
        'configVersion',c.platform_config_version) FROM canvas_connector.oauth_client_configurations c
        JOIN canvas_connector.platforms p ON p.organization_id=c.organization_id AND p.id=c.platform_id
        AND p.config_version=c.platform_config_version AND p.enabled AND NOT p.archived
        WHERE c.organization_id=$1 AND c.platform_id=$2) AS result`,[value.organizationId,value.platformId]);
      if(result!==null && (typeof result!=='object' || Array.isArray(result)
        || Object.keys(result).sort().join(',')!=='clientId,clientSecretRef,configVersion' || !clientId(result.clientId)
        || !uuid(result.clientSecretRef) || !Number.isSafeInteger(result.configVersion) || result.configVersion<2)) throw unavailable();
      return result;
    },
    async receipt(value) {
      scope(value);if(!uuid(value.operationId)) throw unavailable();
      const result=await execute(`SELECT (SELECT receipt FROM canvas_connector.oauth_client_provisioning_audit
        WHERE organization_id=$1 AND platform_id=$2 AND operation_id=$3) AS result`,[value.organizationId,value.platformId,value.operationId]);
      if(result!==null && (!clientProvisioningReceipt(result) || result.platformId!==value.platformId || result.operationId!==value.operationId)) throw unavailable();
      return result;
    },
    async provision(value,secret) {
      if(!clientProvisioningInput(value) || !clientSecret(secret)) throw unavailable();
      try {
        const result=await vault.stageClientConfiguration(value,secret);
        if(result!==null && !clientProvisioningReceipt(result,value)) throw unavailable();
        return result;
      } catch {throw unavailable();}
    },
  });
}
export function createOAuthClientHandler({store,authenticateAndAuthorize,rateLimiter,adminOrigin}={}) {
  let origin;try {origin=new URL(adminOrigin);} catch {throw unavailable();}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==adminOrigin
    || ['inspect','receipt','provision'].some(name=>typeof store?.[name]!=='function')
    || typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function') throw unavailable();
  return async(request,response)=>{
    const finish=(status,value)=>{
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
    };
    const path=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/oauth\/client\/(inspect|receipt|provision)$/.exec(request.url??'');
    if(!path) return finish(404);
    if(request.method!=='POST') return finish(405);
    const count=name=>request.rawHeaders.filter((_,i)=>i%2===0 && request.rawHeaders[i].toLowerCase()===name).length;
    if(count('origin')!==1 || request.headers.origin!==adminOrigin) return finish(403);
    if(count('content-type')!==1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type']??'')) return finish(415);
    let allowed,identity;
    try {allowed=await rateLimiter.consume(request.socket.remoteAddress);} catch {return finish(503);}
    if(allowed!==true) return finish(429);
    const operation={platformId:path[1],action:'integration-connector:edit'};
    try {identity=await authenticateAndAuthorize(request,operation);} catch {return finish(503);}
    if(!identity) return finish(401);
    if(identity.authorized!==true || !id(identity.organizationId) || !id(identity.actorId)) return finish(403);
    const chunks=[];let size=0;
    try {for await(const chunk of request) {size+=chunk.length;if(size>65536) return finish(413);chunks.push(chunk);}}
    catch {return finish(400);}
    const fields=Object.create(null),names={inspect:[],receipt:['operation_id'],provision:['operation_id','expected_version','client_id','client_secret']}[path[2]];
    try {
      const body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));decodeURIComponent(body.replaceAll('+',' '));
      for(const [key,value] of new URLSearchParams(body)) {
        if(!names.includes(key) || Object.hasOwn(fields,key) || !value) return finish(400);fields[key]=value;
      }
    } catch {return finish(400);}
    if(Object.keys(fields).length!==names.length) return finish(400);
    const value={organizationId:identity.organizationId,platformId:path[1]};
    try {
      if(path[2]==='inspect') return finish(200,{client:await store.inspect(value)});
      if(!uuid(fields.operation_id)) return finish(400);value.operationId=fields.operation_id;
      if(path[2]==='receipt') return finish(200,{receipt:await store.receipt(value)});
      if(!/^[1-9][0-9]{0,15}$/.test(fields.expected_version) || !clientId(fields.client_id) || !clientSecret(fields.client_secret)) return finish(400);
      Object.assign(value,{actorId:identity.actorId,expectedVersion:Number(fields.expected_version),clientId:fields.client_id});
      if(!clientProvisioningInput(value)) return finish(400);
      const current=await authenticateAndAuthorize(request,operation);
      if(!current || current.authorized!==true || current.organizationId!==identity.organizationId || current.actorId!==identity.actorId) return finish(403);
      const receipt=await store.provision(value,fields.client_secret);
      return receipt===null?finish(409):finish(200,{receipt});
    } catch {return finish(503);}
  };
}
