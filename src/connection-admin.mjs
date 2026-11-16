// SPDX-License-Identifier: AGPL-3.0-only
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const revision=value=>Number.isSafeInteger(value) && value>=1;
const keys=(value,names)=>value!==null && typeof value==='object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const unavailable=()=>new Error('connector_connection_admin_unavailable');
function receiptShape(value) {
  return keys(value,['operationId','connectionId','actorId','expectedRevision','status','revocationJobId'])
    && uuid(value.operationId) && uuid(value.connectionId) && id(value.actorId) && revision(value.expectedRevision)
    && value.status==='disconnected' && uuid(value.revocationJobId);
}
export function createConnectionAdminStore(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') throw unavailable();
  function scope(value) {if(!id(value?.organizationId) || !id(value?.platformId)) throw unavailable();}
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
      const result=await execute(`SELECT jsonb_build_object(
        'connection',(SELECT jsonb_build_object('connectionId',connection_id,'revision',revision,'status',status)
          FROM canvas_connector.connections WHERE organization_id=$1 AND platform_id=$2),
        'pendingRevocation',EXISTS(SELECT 1 FROM canvas_connector.revocation_jobs
          WHERE organization_id=$1 AND platform_id=$2 AND completed_at IS NULL),
        'pendingRefresh',EXISTS(SELECT 1 FROM canvas_connector.refresh_attempts
          WHERE organization_id=$1 AND platform_id=$2 AND (phase IN ('exchanging','reconciliation_required')
            OR (phase='claimed' AND lease_until>clock_timestamp())))
        ) AS result`,[value.organizationId,value.platformId]);
      if(!keys(result,['connection','pendingRevocation','pendingRefresh'])
        || typeof result.pendingRevocation!=='boolean' || typeof result.pendingRefresh!=='boolean'
        || (result.connection!==null && (!keys(result.connection,['connectionId','revision','status'])
          || !uuid(result.connection.connectionId) || !revision(result.connection.revision)
          || !['connected','reauthorization_required','revocation_pending'].includes(result.connection.status)))) throw unavailable();
      return result;
    },
    async receipt(value) {
      scope(value);if(!uuid(value.operationId)) throw unavailable();
      const result=await execute(`SELECT (SELECT receipt FROM canvas_connector.connection_operation_audit
        WHERE organization_id=$1 AND platform_id=$2 AND operation_id=$3) AS result`,
      [value.organizationId,value.platformId,value.operationId]);
      if(result!==null && (!receiptShape(result) || result.operationId!==value.operationId)) throw unavailable();
      return result;
    },
    async disconnect(value) {
      scope(value);
      if(!uuid(value.connectionId) || !uuid(value.operationId) || !revision(value.expectedRevision) || !id(value.actorId)) throw unavailable();
      const result=await execute('SELECT canvas_connector.disconnect_connection($1,$2,$3,$4,$5,$6) AS result',
        [value.organizationId,value.platformId,value.connectionId,value.expectedRevision,value.operationId,value.actorId]);
      if(result!==null && (!receiptShape(result) || result.operationId!==value.operationId
        || result.connectionId!==value.connectionId || result.actorId!==value.actorId
        || result.expectedRevision!==value.expectedRevision)) throw unavailable();
      return result;
    },
  });
}

export function createConnectionAdminHandler({store,authenticateAndAuthorize,rateLimiter,adminOrigin}={}) {
  let origin;try {origin=new URL(adminOrigin);} catch {throw unavailable();}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==adminOrigin
    || ['inspect','receipt','disconnect'].some(name=>typeof store?.[name]!=='function')
    || typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function') throw unavailable();
  return async(request,response)=>{
    const finish=(status,value)=>{
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});
      response.end(body);
    };
    const path=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/connection\/(inspect|receipt|disconnect)$/.exec(request.url??'');
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
    try {for await(const chunk of request) {size+=chunk.length;if(size>2048) return finish(413);chunks.push(chunk);}}
    catch {return finish(400);}
    const fields=Object.create(null);
    const allowedFields=path[2]==='inspect'?[]:path[2]==='receipt'?['operation_id']:['operation_id','connection_id','expected_revision'];
    try {
      const body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));decodeURIComponent(body.replaceAll('+',' '));
      for(const [key,value] of new URLSearchParams(body)) {
        if(!allowedFields.includes(key) || Object.hasOwn(fields,key) || !value) return finish(400);
        fields[key]=value;
      }
    } catch {return finish(400);}
    if(Object.keys(fields).length!==allowedFields.length || (path[2]!=='inspect' && !uuid(fields.operation_id))) return finish(400);
    const value={organizationId:identity.organizationId,platformId:path[1]};
    try {
      if(path[2]==='inspect') return finish(200,await store.inspect(value));
      value.operationId=fields.operation_id;
      if(path[2]==='receipt') return finish(200,{receipt:await store.receipt(value)});
      if(!uuid(fields.connection_id) || !/^[1-9][0-9]{0,15}$/.test(fields.expected_revision)
        || !revision(Number(fields.expected_revision))) return finish(400);
      const current=await authenticateAndAuthorize(request,operation);
      if(!current || current.authorized!==true || current.organizationId!==identity.organizationId
        || current.actorId!==identity.actorId) return finish(403);
      const receipt=await store.disconnect({...value,connectionId:fields.connection_id,
        expectedRevision:Number(fields.expected_revision),actorId:identity.actorId});
      return receipt===null?finish(409):finish(200,{receipt});
    } catch {return finish(503);}
  };
}
