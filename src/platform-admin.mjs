// SPDX-License-Identifier: AGPL-3.0-only
import {canvasOrigin} from './canvas-rest-network.mjs';
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const version=value=>Number.isSafeInteger(value) && value>=1;
const keys=(value,names)=>value!==null && typeof value==='object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const unavailable=()=>new Error('connector_platform_admin_unavailable');
function origin(value) {
  try {if(typeof value!=='string' || Buffer.byteLength(value)>2048 || canvasOrigin(value)!==value) throw unavailable();}
  catch {throw unavailable();}
  return value;
}
const platformFields=['platformId','canvasOrigin','configVersion','enabled','archived'];
function platformShape(value) {
  return id(value.platformId) && origin(value.canvasOrigin)===value.canvasOrigin && version(value.configVersion)
    && typeof value.enabled==='boolean' && typeof value.archived==='boolean';
}
function receiptShape(value) {
  return keys(value,[...platformFields,'operationId','actorId','action']) && platformShape(value)
    && uuid(value.operationId) && id(value.actorId) && ['create','change'].includes(value.action);
}
export function createPlatformAdminStore(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') throw unavailable();
  const scope=value=>{if(!id(value?.organizationId) || !id(value?.platformId)) throw unavailable();};
  async function execute(sql,values) {
    try {
      const result=await pool.query(sql,values);
      if(result.rows.length!==1 || !Object.hasOwn(result.rows[0],'result')) throw unavailable();
      return result.rows[0].result;
    } catch {throw unavailable();}
  }
  const selected="jsonb_build_object('platformId',id,'canvasOrigin',canvas_origin,'configVersion',config_version,'enabled',enabled,'archived',archived)";
  return Object.freeze({
    async catalog(value) {
      if(!id(value?.organizationId) || (value.afterId!==undefined && !id(value.afterId))) throw unavailable();
      const rows=await execute(`SELECT COALESCE(jsonb_agg(item ORDER BY id COLLATE "C"),'[]'::jsonb) AS result FROM
        (SELECT id,${selected} AS item FROM canvas_connector.platforms WHERE organization_id=$1
          AND ($2::text IS NULL OR id COLLATE "C">$2 COLLATE "C") ORDER BY id COLLATE "C" LIMIT 21) page`,
        [value.organizationId,value.afterId??null]);
      if(!Array.isArray(rows) || rows.length>21 || rows.some(row=>!keys(row,platformFields) || !platformShape(row))) throw unavailable();
      return {platforms:rows.slice(0,20),nextCursor:rows.length>20?rows[19].platformId:null};
    },
    async inspect(value) {
      scope(value);
      const result=await execute(`SELECT (SELECT ${selected} FROM canvas_connector.platforms WHERE organization_id=$1 AND id=$2) AS result`,[value.organizationId,value.platformId]);
      if(result!==null && (!keys(result,platformFields) || !platformShape(result) || result.platformId!==value.platformId)) throw unavailable();
      return result;
    },
    async receipt(value) {
      scope(value);if(!uuid(value.operationId)) throw unavailable();
      const result=await execute(`SELECT (SELECT receipt FROM canvas_connector.platform_operation_audit WHERE organization_id=$1
        AND platform_id=$2 AND operation_id=$3) AS result`,[value.organizationId,value.platformId,value.operationId]);
      if(result!==null && (!receiptShape(result) || result.operationId!==value.operationId || result.platformId!==value.platformId)) throw unavailable();
      return result;
    },
    async apply(value) {
      scope(value);
      if(!uuid(value.operationId) || !id(value.actorId) || !['create','change'].includes(value.action)) throw unavailable();
      let canvas=null,expected=null,enabled=false,archived=false;
      if(value.action==='create') canvas=origin(value.canvasOrigin);
      else {
        if(!version(value.expectedVersion) || typeof value.enabled!=='boolean' || typeof value.archived!=='boolean'
          || (value.enabled && value.archived)) throw unavailable();
        expected=value.expectedVersion;enabled=value.enabled;archived=value.archived;
      }
      const result=await execute('SELECT canvas_connector.administer_platform($1,$2,$3,$4,$5,$6,$7,$8,$9) AS result',
        [value.organizationId,value.platformId,value.operationId,value.actorId,value.action,canvas,expected,enabled,archived]);
      if(result!==null && (!receiptShape(result) || result.operationId!==value.operationId || result.platformId!==value.platformId
        || result.actorId!==value.actorId || result.action!==value.action
        || (value.action==='create' && (result.canvasOrigin!==canvas || result.configVersion!==1 || result.enabled || result.archived))
        || (value.action==='change' && (result.configVersion!==expected+1 || result.enabled!==enabled || result.archived!==archived)))) throw unavailable();
      return result;
    },
  });
}
export function createPlatformAdminHandler({store,authenticateAndAuthorize,rateLimiter,adminOrigin}={}) {
  let admin;try {admin=new URL(adminOrigin);} catch {throw unavailable();}
  if(typeof globalThis.window!=='undefined' || admin.protocol!=='https:' || admin.origin!==adminOrigin
    || ['catalog','inspect','receipt','apply'].some(name=>typeof store?.[name]!=='function')
    || typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function') throw unavailable();
  return async(request,response)=>{
    const finish=(status,value)=>{
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
    };
    const path=request.url==='/platforms/catalog'?['','catalog','catalog']:
      /^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/configuration\/(inspect|receipt|create|change)$/.exec(request.url??'');
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
    const allowedFields={catalog:['after_id'],inspect:[],receipt:['operation_id'],create:['operation_id','canvas_origin'],
      change:['operation_id','expected_version','enabled','archived']}[path[2]];
    const chunks=[];let size=0;
    try {for await(const chunk of request) {size+=chunk.length;if(size>4096) return finish(413);chunks.push(chunk);}}
    catch {return finish(400);}
    const fields=Object.create(null);
    try {
      const body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));decodeURIComponent(body.replaceAll('+',' '));
      for(const [key,value] of new URLSearchParams(body)) {
        if(!allowedFields.includes(key) || Object.hasOwn(fields,key) || !value) return finish(400);fields[key]=value;
      }
    } catch {return finish(400);}
    if(path[2]!=='catalog' && Object.keys(fields).length!==allowedFields.length) return finish(400);
    const value={organizationId:identity.organizationId,platformId:path[1]};
    try {
      if(path[2]==='catalog') {
        if(fields.after_id!==undefined && !id(fields.after_id)) return finish(400);
        return finish(200,await store.catalog({organizationId:identity.organizationId,...(fields.after_id?{afterId:fields.after_id}:{})}));
      }
      if(path[2]==='inspect') return finish(200,{platform:await store.inspect(value)});
      if(!uuid(fields.operation_id)) return finish(400);value.operationId=fields.operation_id;
      if(path[2]==='receipt') return finish(200,{receipt:await store.receipt(value)});
      if(path[2]==='create') {
        try {value.canvasOrigin=origin(fields.canvas_origin);} catch {return finish(400);}
      } else {
        if(!/^[1-9][0-9]{0,15}$/.test(fields.expected_version) || !version(Number(fields.expected_version))
          || !['true','false'].includes(fields.enabled) || !['true','false'].includes(fields.archived)
          || (fields.enabled==='true' && fields.archived==='true')) return finish(400);
        Object.assign(value,{expectedVersion:Number(fields.expected_version),enabled:fields.enabled==='true',archived:fields.archived==='true'});
      }
      const current=await authenticateAndAuthorize(request,operation);
      if(!current || current.authorized!==true || current.organizationId!==identity.organizationId || current.actorId!==identity.actorId) return finish(403);
      const receipt=await store.apply({...value,actorId:identity.actorId,action:path[2]});
      return receipt===null?finish(409):finish(200,{receipt});
    } catch {return finish(503);}
  };
}
