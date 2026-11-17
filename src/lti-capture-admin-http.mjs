// SPDX-License-Identifier: AGPL-3.0-only
import {readLtiHttpForm} from './lti-launch-http.mjs';
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {prepareLtiCaptureRoute,prepareLtiCaptureRouteIntent} from './lti-capture-contract.mjs';
import {ltiCaptureAdminCommand} from './lti-capture-admin-contract.mjs';
import {parsePrivateJson} from './private-json.mjs';
const fail=()=>{throw Error('lti_capture_admin_unavailable');};
const versions=['expected_platform_version','expected_registration_version','expected_key_version','service_operation_id'];
const definition=['producer_ref','binding_id','binding_revision','requirement','claim_names','effective_time_policy'];
const allowed={catalog:['after_id'],inspect:[],receipt:['operation_id'],capture:['capture_id'],
 create:['operation_id',...versions,...definition],replace:['operation_id','expected_route_version',...versions,...definition],
 activate:['operation_id','expected_route_version',...versions],deactivate:['operation_id','expected_route_version'],schedule:['operation_id','expected_route_version',...versions]};
function version(v){if(typeof v!=='string'||!/^[1-9][0-9]{0,15}$/.test(v)||!ltiVersion(Number(v)))fail();return Number(v);}
export function createLtiCaptureAdminHandler({store,readBinding,authenticateAndAuthorize,rateLimiter,publicOrigin}={}) {
 let origin;try{origin=new URL(publicOrigin);}catch{fail();}
 if(typeof globalThis.window!=='undefined'||origin.protocol!=='https:'||origin.origin!==publicOrigin
  ||['platform','catalog','inspect','receipt','replay','apply','capture'].some(n=>typeof store?.[n]!=='function')
  ||typeof readBinding!=='function'||typeof authenticateAndAuthorize!=='function'||typeof rateLimiter?.consume!=='function')fail();
 return async(request,response)=>{
  const finish=(status,value)=>{
   if(response.destroyed)return;const body=value===undefined?'':JSON.stringify(value);
   response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store',
    'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
  };
  if(typeof request.url!=='string'||Buffer.byteLength(request.url)>8192)return finish(414);
  if(request.rawHeaders.length>128)return finish(431);
  const count=name=>request.rawHeaders.filter((_,i)=>i%2===0&&request.rawHeaders[i].toLowerCase()===name).length;
  if(count('host')!==1||request.headers.host!==origin.host)return finish(421);
  const catalog=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/capture-routes\/catalog$/.exec(request.url);
  const path=catalog?[null,catalog[1],catalog[2],null,'catalog']:
   /^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/capture-routes\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/(inspect|receipt|capture|create|replace|activate|deactivate|schedule)$/.exec(request.url);
  if(!path)return finish(404);if(request.method!=='POST')return finish(405);
  if(count('origin')!==1||request.headers.origin!==publicOrigin)return finish(403);
  const permission={platformId:path[1],action:'integration-connector:edit'};let identity;
  try{if(await rateLimiter.consume()!==true)return finish(429);identity=await authenticateAndAuthorize(request,permission);}catch{return finish(503);}
  if(!identity)return finish(401);if(identity.authorized!==true||!ltiId(identity.organizationId)||!ltiId(identity.actorId))return finish(403);
  const scope={organizationId:identity.organizationId,platformId:path[1],registrationId:path[2],routeId:path[3]},action=path[4];
  const reauthorize=async()=>{const a=await authenticateAndAuthorize(request,permission);return a?.authorized===true&&a.organizationId===identity.organizationId&&a.actorId===identity.actorId;};
  let input;
  try {
   input=await readLtiHttpForm(request,8192,allowed[action]);
   if(action!=='catalog'&&allowed[action].some(n=>!Object.hasOwn(input,n)))return finish(400);
   for(const n of ['operation_id','service_operation_id','capture_id'])if(input[n]!==undefined&&!ltiUuid(input[n]))return finish(400);
  }catch{return finish(400);}
  try {
   let result;
   if(action==='catalog') {
    if(input.after_id!==undefined&&!ltiId(input.after_id))return finish(400);
    result=await store.catalog({organizationId:scope.organizationId,platformId:scope.platformId,registrationId:scope.registrationId,...input.after_id?{afterId:input.after_id}:{}});
   }else if(action==='inspect')result={route:await store.inspect(scope)};
   else if(action==='receipt')result={receipt:await store.receipt({...scope,operationId:input.operation_id})};
   else if(action==='capture')result={capture:await store.capture({...scope,captureId:input.capture_id})};
   else {
    let command;
    try {
     command={...scope,operationId:input.operation_id,actorId:identity.actorId,action};
     if(action!=='create')command.expectedRouteVersion=version(input.expected_route_version);
     if(action!=='deactivate')Object.assign(command,{expectedPlatformVersion:version(input.expected_platform_version),
      expectedRegistrationVersion:version(input.expected_registration_version),expectedKeyVersion:version(input.expected_key_version),serviceOperationId:input.service_operation_id});
     if(['create','replace'].includes(action))command.definition=prepareLtiCaptureRouteIntent({producerRef:input.producer_ref,platformId:scope.platformId,
      registrationId:scope.registrationId,bindingId:input.binding_id,bindingRevision:version(input.binding_revision),requirement:parsePrivateJson(input.requirement),
      claimNames:parsePrivateJson(input.claim_names),effectiveTimePolicy:input.effective_time_policy});
     ltiCaptureAdminCommand(command);
    }catch{return finish(400);}
    const reconcile=async status=>{
     const history=await store.replay(command);
     if(!await reauthorize())return finish(403);
     if(history!==null)return history.conflict?finish(409):finish(200,{receipt:history.receipt});
     return finish(status);
    };
    const prior=await store.replay(command);
    if(prior!==null){if(!await reauthorize())return finish(403);return prior.conflict?finish(409):finish(200,{receipt:prior.receipt});}
    let candidate,snapshot,platform;
    if(action!=='deactivate') {
     platform=await store.platform(scope);
     if(platform===null||platform.configVersion!==command.expectedPlatformVersion||platform.archived)return await reconcile(409);
     candidate=command.definition;
     if(candidate===undefined){const r=await store.inspect(scope);if(r===null||r.version!==command.expectedRouteVersion||r.serviceOperationId!==command.serviceOperationId)return await reconcile(409);candidate=r.definition;}
     const read=await readBinding(request,{platformId:scope.platformId,bindingId:candidate.bindingId});
     if(!read||read.organizationId!==identity.organizationId||read.actorId!==identity.actorId)return await reconcile(403);snapshot=read.snapshot;
    }
    if(!await reauthorize())return finish(403);
    if(action!=='deactivate')try{prepareLtiCaptureRoute(candidate,snapshot,{platformOrigin:platform.canvasOrigin});}catch{return await reconcile(409);}
    const validUntilMs=action==='deactivate'?undefined:Math.min(Date.now()+30000,snapshot.snapshot_at_ms+30000,snapshot.record.application_expires_at_ms);
    const beforeCommit=async()=>{
     if(!await reauthorize())return false;
     if(action!=='deactivate')try{prepareLtiCaptureRoute(candidate,snapshot,{platformOrigin:platform.canvasOrigin});}catch{return false;}
     return true;
    };
    const receipt=await store.apply(command,beforeCommit,validUntilMs);
    if(!await reauthorize())return finish(403);return receipt===null?await reconcile(409):finish(200,{receipt});
   }
   if(!await reauthorize())return finish(403);return finish(200,result);
  }catch{return finish(503);}
 };
}
