// SPDX-License-Identifier: AGPL-3.0-only
import {prepareCaptureRoute,prepareCaptureRouteIntent} from './capture-route-contract.mjs';
import {parsePrivateJson} from './private-json.mjs';
const unavailable=()=>new Error('connector_capture_route_admin_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
function revision(value) {
  if(typeof value!=='string' || !/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) throw unavailable();return Number(value);
}
const definitions=['producer_ref','binding_id','binding_revision','requirement','claim_names','effective_time_policy'];
const allowed={catalog:['after_id'],inspect:[],receipt:['operation_id'],capture:['capture_id'],
  create:['operation_id','expected_platform_version',...definitions],
  replace:['operation_id','expected_platform_version','expected_route_version',...definitions],
  activate:['operation_id','expected_platform_version','expected_route_version'],
  deactivate:['operation_id','expected_route_version'],schedule:['operation_id','expected_platform_version','expected_route_version']};
export function createCaptureRouteAdminHandler({store,readBinding,authenticateAndAuthorize,rateLimiter,adminOrigin}={}) {
  let origin;try{origin=new URL(adminOrigin);}catch{throw unavailable();}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==adminOrigin
    || ['platform','catalog','inspect','receipt','replay','apply','capture'].some(name=>typeof store?.[name]!=='function')
    || typeof readBinding!=='function' || typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function') throw unavailable();
  return async(request,response)=>{
    const finish=(status,value)=>{
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store',
        'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
    };
    const catalog=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/capture-routes\/catalog$/.exec(request.url??'');
    const path=catalog?[null,catalog[1],null,'catalog']:
      /^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/capture-routes\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/(inspect|receipt|capture|create|replace|activate|deactivate|schedule)$/.exec(request.url??'');
    if(!path) return finish(404);if(request.method!=='POST') return finish(405);
    const count=name=>request.rawHeaders.filter((_,i)=>i%2===0 && request.rawHeaders[i].toLowerCase()===name).length;
    if(count('origin')!==1 || request.headers.origin!==adminOrigin) return finish(403);
    if(count('content-type')!==1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type']??'')) return finish(415);
    for(const name of ['content-length','content-encoding','transfer-encoding']) if(count(name)>1) return finish(400);
    if(request.headers.trailer!==undefined || (request.headers['content-length']!==undefined && request.headers['transfer-encoding']!==undefined)) return finish(400);
    if(!['','identity'].includes(request.headers['content-encoding']??'')) return finish(415);
    if(request.headers['transfer-encoding']!==undefined && request.headers['transfer-encoding'].toLowerCase()!=='chunked') return finish(400);
    const length=request.headers['content-length'];
    if(length!==undefined && !/^[0-9]{1,8}$/.test(length)) return finish(400);
    if(length!==undefined && Number(length)>8192) return finish(413);
    let identity;
    try {if(await rateLimiter.consume(request.socket.remoteAddress)!==true) return finish(429);}catch{return finish(503);}
    const permission={platformId:path[1],action:'integration-connector:edit'};
    try {identity=await authenticateAndAuthorize(request,permission);}catch{return finish(503);}
    if(!identity) return finish(401);
    if(identity.authorized!==true || !id(identity.organizationId) || !id(identity.actorId)) return finish(403);
    const chunks=[];let size=0;
    try{for await(const chunk of request){size+=chunk.length;if(size>8192) return finish(413);chunks.push(chunk);}}catch{return finish(400);}
    if(length!==undefined && Number(length)!==size) return finish(400);
    const fields=Object.create(null),action=path[3];
    try {
      const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));decodeURIComponent(text.replaceAll('+',' '));
      for(const [key,value] of new URLSearchParams(text)) {
        if(!allowed[action].includes(key) || Object.hasOwn(fields,key) || !value) return finish(400);fields[key]=value;
      }
      if(action!=='catalog' && Object.keys(fields).length!==allowed[action].length) return finish(400);
    }catch{return finish(400);}
    const scope={organizationId:identity.organizationId,platformId:path[1],routeId:path[2]};
    const reauthorize=async()=>{
      const current=await authenticateAndAuthorize(request,permission);
      return current?.authorized===true && current.organizationId===identity.organizationId && current.actorId===identity.actorId;
    };
    try {
      if(action==='catalog') {
        if(fields.after_id!==undefined && !id(fields.after_id)) return finish(400);
        return finish(200,await store.catalog({organizationId:scope.organizationId,platformId:scope.platformId,...(fields.after_id?{afterId:fields.after_id}:{})}));
      }
      if(action==='inspect') return finish(200,{route:await store.inspect(scope)});
      if(action==='capture') {
        if(typeof fields.capture_id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(fields.capture_id)) return finish(400);
        return finish(200,{capture:await store.capture({...scope,captureId:fields.capture_id})});
      }
      if(!uuid(fields.operation_id)) return finish(400);
      if(action==='receipt') return finish(200,{receipt:await store.receipt({...scope,operationId:fields.operation_id})});
      const command={...scope,operationId:fields.operation_id,actorId:identity.actorId,action};
      try {
        if(action!=='deactivate') command.expectedPlatformVersion=revision(fields.expected_platform_version);
        if(action!=='create') command.expectedRouteVersion=revision(fields.expected_route_version);
        if(['create','replace'].includes(action)) command.definition=prepareCaptureRouteIntent({producerRef:fields.producer_ref,
          platformId:scope.platformId,bindingId:fields.binding_id,bindingRevision:revision(fields.binding_revision),
          requirement:parsePrivateJson(fields.requirement),claimNames:parsePrivateJson(fields.claim_names),effectiveTimePolicy:fields.effective_time_policy});
      }catch{return finish(400);}
      // Reconcile the exact original intent before consulting changing binding,
      // connection or application state. Returning history performs no write.
      const prior=await store.replay(command);
      if(prior!==null) {
        if(!await reauthorize()) return finish(403);
        return prior.conflict?finish(409):finish(200,{receipt:prior.receipt});
      }
      let candidate,snapshot,platform;
      if(action!=='deactivate') {
        platform=await store.platform(scope);
        if(platform===null || platform.configVersion!==command.expectedPlatformVersion || platform.archived) return finish(409);
        candidate=command.definition;
        if(candidate===undefined) {
          const configured=await store.inspect(scope);
          if(configured===null || configured.version!==command.expectedRouteVersion) return finish(409);candidate=configured.definition;
        }
        const read=await readBinding(request,{platformId:scope.platformId,bindingId:candidate.bindingId});
        if(!read || read.organizationId!==identity.organizationId || read.actorId!==identity.actorId) return finish(403);snapshot=read.snapshot;
      }
      if(!await reauthorize()) return finish(403);
      if(action!=='deactivate') {
        // Freshness/expiry are evaluated after the final authority round trip.
        // SQL fences the local platform/route versions against later changes.
        try{command.definition=prepareCaptureRoute(candidate,snapshot,{platformOrigin:platform.canvasOrigin});}catch{return finish(409);}
      }
      const result=await store.apply(command);return result===null?finish(409):finish(200,{receipt:result});
    }catch{return finish(503);}
  };
}
