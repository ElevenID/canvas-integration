// SPDX-License-Identifier: AGPL-3.0-only
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const hash=value=>typeof value==='string' && /^[a-f0-9]{64}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const actions=['abandon_unstarted','queue_staged_revocation','finish_staged_revocation'];
const unavailable=()=>new Error('connector_recovery_unavailable');
const revision=value=>Number.isSafeInteger(value) && value>=1;
function keys(value,names) {
  return value!==null && typeof value==='object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',')===names.slice().sort().join(',');
}
function receiptShape(value,authorizationId) {
  return keys(value,['operationId','authorizationId','actorId','action','phase','revision','revocationJobId'])
    && uuid(value.operationId) && value.authorizationId===authorizationId && id(value.actorId)
    && actions.includes(value.action) && revision(value.revision)
    && (value.revocationJobId===null || uuid(value.revocationJobId))
    && (value.action==='queue_staged_revocation'?value.phase==='reconciliation_required' && value.revocationJobId!==null
      :value.phase==='abandoned' && (value.action==='abandon_unstarted'?value.revocationJobId===null:value.revocationJobId!==null));
}

// Connector-owned metadata only. HTTP derives organization and actor from a
// fresh public Gateway session/permission check, never request body fields.
export function createOAuthAttemptRecoveryStore(pool) {
  if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') throw unavailable();
  async function execute(sql,values) {
    try {
      const rows=(await pool.query(sql,values)).rows;
      if(rows.length!==1 || !Object.hasOwn(rows[0],'result')) throw unavailable();
      const result=rows[0].result;
      if(result!==null && (typeof result!=='object' || Array.isArray(result)
        || Buffer.byteLength(JSON.stringify(result))>16384)) throw unavailable();
      return result;
    } catch {throw unavailable();}
  }
  function scope(value) {
    if(!id(value?.organizationId) || !id(value.platformId) || !hash(value.authorizationId)) throw unavailable();
  }
  return Object.freeze({
    async inspect(value) {
      scope(value);
      const result=await execute(`SELECT (SELECT jsonb_build_object(
          'authorizationId',a.authorization_hash,'phase',a.phase,'revision',a.revision,
          'hasAccessReference',a.access_token_ref IS NOT NULL,'hasRefreshReference',a.refresh_token_ref IS NOT NULL,
          'revocationJobId',a.recovery_job_id,'revocationConfirmed',j.provider_revoked_at IS NOT NULL,
          'cleanupCompleted',j.completed_at IS NOT NULL,
          'connected',EXISTS(SELECT 1 FROM canvas_connector.connections c WHERE c.organization_id=a.organization_id AND c.platform_id=a.platform_id),
          'audit',coalesce((SELECT jsonb_agg(history.receipt ORDER BY history.created_at DESC,history.operation_id DESC)
            FROM (SELECT receipt,created_at,operation_id FROM canvas_connector.authorization_recovery_audit
              WHERE organization_id=a.organization_id AND platform_id=a.platform_id AND authorization_hash=a.authorization_hash
              ORDER BY created_at DESC,operation_id DESC LIMIT 8) history),'[]'::jsonb))
        FROM canvas_connector.authorization_attempts a LEFT JOIN canvas_connector.revocation_jobs j
          ON j.id=a.recovery_job_id AND j.organization_id=a.organization_id AND j.platform_id=a.platform_id
        WHERE a.organization_id=$1 AND a.platform_id=$2 AND a.authorization_hash=$3) AS result`,
      [value.organizationId,value.platformId,value.authorizationId]);
      if(result===null) return null;
      if(!keys(result,['authorizationId','phase','revision','hasAccessReference','hasRefreshReference',
        'revocationJobId','revocationConfirmed','cleanupCompleted','connected','audit'])
        || result.authorizationId!==value.authorizationId || !revision(result.revision)
        || !['consumed','exchanging','staged','published','reconciliation_required','abandoned'].includes(result.phase)
        || (result.revocationJobId!==null && !uuid(result.revocationJobId))
        || ['hasAccessReference','hasRefreshReference','revocationConfirmed','cleanupCompleted','connected'].some(name=>typeof result[name]!=='boolean')
        || !Array.isArray(result.audit) || result.audit.length>8 || result.audit.some(item=>!receiptShape(item,value.authorizationId))) throw unavailable();
      return result;
    },
    async receipt(value) {
      scope(value);if(!uuid(value.operationId)) throw unavailable();
      const result=await execute(`SELECT (SELECT receipt FROM canvas_connector.authorization_recovery_audit
        WHERE organization_id=$1 AND platform_id=$2 AND authorization_hash=$3 AND operation_id=$4) AS result`,
      [value.organizationId,value.platformId,value.authorizationId,value.operationId]);
      if(result!==null && (!receiptShape(result,value.authorizationId) || result.operationId!==value.operationId)) throw unavailable();
      return result;
    },
    async recover(value) {
      scope(value);
      if(!uuid(value.operationId) || !id(value.actorId) || !actions.includes(value.action)
          || !Number.isSafeInteger(value.expectedRevision) || value.expectedRevision<1) throw unavailable();
      const result=await execute('SELECT canvas_connector.recover_authorization_attempt($1,$2,$3,$4,$5,$6,$7) AS result',
      [value.organizationId,value.platformId,value.authorizationId,value.expectedRevision,value.operationId,value.actorId,value.action]);
      if(result!==null && (!receiptShape(result,value.authorizationId) || result.operationId!==value.operationId
        || result.actorId!==value.actorId || result.action!==value.action)) throw unavailable();
      return result;
    },
  });
}

export function createOAuthAttemptRecoveryHandler({store,authenticateAndAuthorize,rateLimiter,adminOrigin}={}) {
  let origin;
  try {origin=new URL(adminOrigin);} catch {throw unavailable();}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==adminOrigin
    || ['inspect','receipt','recover'].some(name=>typeof store?.[name]!=='function')
    || typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function') throw unavailable();
  return async(request,response)=>{
    const finish=(status,value)=>{
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});
      response.end(body);
    };
    const path=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/oauth\/attempts\/(inspect|receipt|recover)$/.exec(request.url??'');
    if(!path) return finish(404);
    if(request.method!=='POST') return finish(405);
    const count=name=>request.rawHeaders.filter((_,i)=>i%2===0 && request.rawHeaders[i].toLowerCase()===name).length;
    if(count('origin')!==1 || request.headers.origin!==adminOrigin) return finish(403);
    if(count('content-type')!==1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type']??'')) return finish(415);
    let allowed,identity;
    try {allowed=await rateLimiter.consume(request.socket.remoteAddress);} catch {return finish(503);}
    if(allowed!==true) return finish(429);
    try {identity=await authenticateAndAuthorize(request,{platformId:path[1],action:'integration-connector:edit'});} catch {return finish(503);}
    if(!identity) return finish(401);
    if(identity.authorized!==true || !id(identity.organizationId) || !id(identity.actorId)) return finish(403);
    const chunks=[];let size=0;
    try {
      for await(const chunk of request) {size+=chunk.length;if(size>2048) return finish(413);chunks.push(chunk);}
    } catch {return finish(400);}
    const fields=Object.create(null);
    const allowedFields=path[2]==='inspect'?['authorization_id']:path[2]==='receipt'?['authorization_id','operation_id']
      :['authorization_id','operation_id','expected_revision','action'];
    try {
      const body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));decodeURIComponent(body.replaceAll('+',' '));
      for(const [key,value] of new URLSearchParams(body)) {
        if(!allowedFields.includes(key) || Object.hasOwn(fields,key) || !value) return finish(400);
        fields[key]=value;
      }
    } catch {return finish(400);}
    if(Object.keys(fields).length!==allowedFields.length || !hash(fields.authorization_id)
      || (path[2]!=='inspect' && !uuid(fields.operation_id))) return finish(400);
    const value={organizationId:identity.organizationId,platformId:path[1],authorizationId:fields.authorization_id};
    try {
      if(path[2]==='inspect') return finish(200,{attempt:await store.inspect(value)});
      value.operationId=fields.operation_id;
      if(path[2]==='receipt') return finish(200,{receipt:await store.receipt(value)});
      if(!/^[1-9][0-9]{0,15}$/.test(fields.expected_revision) || !Number.isSafeInteger(Number(fields.expected_revision))
        || !actions.includes(fields.action)) return finish(400);
      const current=await authenticateAndAuthorize(request,{platformId:path[1],action:'integration-connector:edit'});
      if(!current || current.authorized!==true || current.organizationId!==identity.organizationId
        || current.actorId!==identity.actorId) return finish(403);
      const receipt=await store.recover({...value,actorId:identity.actorId,expectedRevision:Number(fields.expected_revision),action:fields.action});
      return receipt===null?finish(409):finish(200,{receipt});
    } catch {
      // Mutating acknowledgment may have been lost. Caller must inspect the
      // exact operation receipt; never generate another operation automatically.
      return finish(503);
    }
  };
}
