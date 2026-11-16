// SPDX-License-Identifier: AGPL-3.0-only
import { readLtiHttpForm } from './lti-launch-http.mjs';
import { canvasOrigin } from './canvas-rest-network.mjs';
import { ltiId,ltiUuid,ltiVersion,prepareLtiRegistrationDefinition,validateLtiRegistrationPolicy } from './lti-registration-contract.mjs';

const definitionFields=['client_id','deployment_id','trust_profile','environment'];
const fields={catalog:['after_id'],inspect:[],receipt:['operation_id'],
  create:['operation_id','expected_platform_version',...definitionFields],
  replace:['operation_id','expected_platform_version','expected_registration_version',...definitionFields],
  activate:['operation_id','expected_platform_version','expected_registration_version'],deactivate:['operation_id','expected_registration_version']};
function version(value,increment=false) {
  if(typeof value!=='string' || !/^[1-9][0-9]{0,15}$/.test(value) || !ltiVersion(Number(value)) ||
    (increment && Number(value)>=9007199254740991)) throw Error('invalid_lti_registration');
  return Number(value);
}
export function createLtiRegistrationAdminHandler({store,authenticateAndAuthorize,rateLimiter,publicOrigin,selfManagedOriginAllowlist=[]}={}) {
  let origin;try{origin=new URL(publicOrigin);}catch{throw Error('invalid_lti_registration_admin');}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==publicOrigin ||
    ['platform','catalog','inspect','receipt','replay','apply'].some(name=>typeof store?.[name]!=='function') ||
    typeof authenticateAndAuthorize!=='function' || typeof rateLimiter?.consume!=='function' ||
    !Array.isArray(selfManagedOriginAllowlist) || selfManagedOriginAllowlist.length>32) throw Error('invalid_lti_registration_admin');
  const allowlist=Object.freeze(selfManagedOriginAllowlist.map(value=>canvasOrigin(value)));
  return async(request,response)=>{
    const finish=(status,value)=>{
      if(response.destroyed) return;
      const body=value===undefined?'':JSON.stringify(value);
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(body)),
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
    };
    if(typeof request.url!=='string' || Buffer.byteLength(request.url)>8192) return finish(414);
    if(request.rawHeaders.length>128) return finish(431);
    const count=name=>request.rawHeaders.filter((_,i)=>i%2===0 && request.rawHeaders[i].toLowerCase()===name).length;
    const values=name=>request.rawHeaders.filter((_,i)=>i%2===1 && request.rawHeaders[i-1].toLowerCase()===name);
    if(count('host')!==1 || values('host')[0]!==origin.host) return finish(421);
    const catalog=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/lti\/registrations\/catalog$/.exec(request.url);
    const path=catalog?[null,catalog[1],null,'catalog']:/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/(inspect|receipt|create|replace|activate|deactivate)$/.exec(request.url);
    if(!path) return finish(404);if(request.method!=='POST') return finish(405);
    if(count('origin')!==1 || values('origin')[0]!==publicOrigin) return finish(403);
    let identity;
    try{if(await rateLimiter.consume()!==true) return finish(429);}catch{return finish(503);}
    const permission=Object.freeze({platformId:path[1],action:'integration-connector:edit'});
    try{identity=await authenticateAndAuthorize(request,permission);}catch{return finish(503);}
    if(!identity) return finish(401);
    if(identity.authorized!==true || !ltiId(identity.organizationId) || !ltiId(identity.actorId)) return finish(403);
    const organizationId=identity.organizationId,actorId=identity.actorId;
    const scope=Object.freeze({organizationId,platformId:path[1],registrationId:path[2]}),action=path[3];
    let input;
    try {
      input=await readLtiHttpForm(request,8192,fields[action]);
      const required=fields[action].filter(key=>key!=='environment' && !(action==='catalog' && key==='after_id'));
      if(required.some(key=>!Object.hasOwn(input,key))) return finish(400);
    }catch{return finish(400);}
    const reauthorize=async()=>{
      const current=await authenticateAndAuthorize(request,permission);
      return current?.authorized===true && current.organizationId===organizationId && current.actorId===actorId;
    };
    try {
      if(action==='catalog') {
        if(input.after_id!==undefined && !ltiUuid(input.after_id)) return finish(400);
        const result=await store.catalog({organizationId,platformId:scope.platformId,...(input.after_id?{afterId:input.after_id}:{})});
        return await reauthorize()?finish(200,result):finish(403);
      }
      if(action==='inspect') {
        const result=await store.inspect(scope);return await reauthorize()?finish(200,{registration:result}):finish(403);
      }
      if(!ltiUuid(input.operation_id)) return finish(400);
      if(action==='receipt') {
        const result=await store.receipt({...scope,operationId:input.operation_id});
        return await reauthorize()?finish(200,{receipt:result}):finish(403);
      }
      let command;
      try {
        command=Object.freeze({...scope,operationId:input.operation_id,actorId,action,
          expectedPlatformVersion:action==='deactivate'?null:version(input.expected_platform_version),
          expectedRegistrationVersion:action==='create'?null:version(input.expected_registration_version,true),
          definition:['create','replace'].includes(action)?prepareLtiRegistrationDefinition({clientId:input.client_id,
            deploymentId:input.deployment_id,trustProfile:input.trust_profile,environment:input.environment??null},
            {registrationId:scope.registrationId,publicOrigin}):null});
      }catch{return finish(400);}
      const previous=await store.replay(command);
      if(previous!==null) {
        if(!await reauthorize()) return finish(403);
        return previous.conflict?finish(409):finish(200,{receipt:previous.receipt});
      }
      let platform,definition=command.definition;
      if(action!=='deactivate') {
        platform=await store.platform(scope);
        if(!platform || platform.configVersion!==command.expectedPlatformVersion || platform.archived ||
          (action==='activate' && !platform.enabled)) return finish(409);
        if(definition===null) {
          const saved=await store.inspect(scope);
          if(!saved || saved.version!==command.expectedRegistrationVersion) return finish(409);definition=saved.definition;
        }
      }
      if(!await reauthorize()) return finish(403);
      if(action!=='deactivate') {
        try{validateLtiRegistrationPolicy(definition,{registrationId:scope.registrationId,publicOrigin,
          platformOrigin:platform.canvasOrigin,selfManagedOriginAllowlist:allowlist});}catch{return finish(409);}
      }
      const result=await store.apply(command);return result===null?finish(409):finish(200,{receipt:result});
    }catch{return finish(503);}
  };
}
