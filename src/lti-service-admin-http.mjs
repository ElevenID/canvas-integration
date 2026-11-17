// SPDX-License-Identifier: AGPL-3.0-only
import { readLtiHttpForm } from './lti-launch-http.mjs';
import { ltiId,ltiUuid,ltiVersion } from './lti-registration-contract.mjs';
import { ltiServiceScopes } from './lti-service-contract.mjs';
import { parsePrivateJson } from './private-json.mjs';

const invalid=()=>{throw Error('invalid_lti_service_admin');};
function version(value) {if(typeof value!=='string'||!/^[1-9][0-9]{0,15}$/.test(value)||!ltiVersion(Number(value)))invalid();return Number(value);}
const permitted={
 'tool-key':{inspect:[],receipt:['operation_id'],provision:['operation_id','expected_platform_version','expected_registration_version'],
  rotate:['operation_id','expected_platform_version','expected_registration_version','expected_key_version'],deactivate:['operation_id','expected_key_version']},
 'service-credentials':{catalog:['after_id'],inspect:['attempt_id'],receipt:['operation_id'],recover:['attempt_id'],
  exchange:['operation_id','expected_platform_version','expected_registration_version','expected_key_version','scopes'],
  resolve:['attempt_id','operation_id','action','expected_phase','expected_platform_version','expected_registration_version','expected_key_version','confirmation_reference'],
  'resolution-receipt':['attempt_id','operation_id']},
};
function publicAttempt(a) {
 if(a===null)return null;
 return Object.freeze({attemptId:a.operationId,phase:a.phase,platformVersion:a.platformVersion,registrationVersion:a.registrationVersion,
  keyVersion:a.keyVersion,kid:a.kid,scopes:a.scopes,issuedAt:a.issuedAt,expiresAt:a.expiresAt,tokenReference:a.tokenReference,receipt:a.receipt});
}
export function createLtiServiceAdminHandler({keyStore,store,lifecycle,recoveryStore,authenticateAndAuthorize,rateLimiter,publicOrigin}={}) {
 let origin;try{origin=new URL(publicOrigin);}catch{invalid();}
 if(typeof globalThis.window!=='undefined'||origin.protocol!=='https:'||origin.origin!==publicOrigin
  ||['administer','inspect','receipt','publicKeys'].some(name=>typeof keyStore?.[name]!=='function')||['inspect','catalog'].some(name=>typeof store?.[name]!=='function')
  ||['exchange','recover'].some(name=>typeof lifecycle?.[name]!=='function')||['recover','receipt'].some(name=>typeof recoveryStore?.[name]!=='function')
  ||typeof authenticateAndAuthorize!=='function'||typeof rateLimiter?.consume!=='function')invalid();
 return async(request,response)=>{
  const finish=(status,value)=>{
   if(response.destroyed)return;const body=value===undefined?'':JSON.stringify(value);
   response.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store',
    'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
  };
  const count=name=>request.rawHeaders.filter((_,i)=>i%2===0&&request.rawHeaders[i].toLowerCase()===name).length;
  if(typeof request.url!=='string'||Buffer.byteLength(request.url)>8192)return finish(414);
  if(request.rawHeaders.length>128)return finish(431);
  if(count('host')!==1||request.headers.host!==origin.host)return finish(421);
  const jwks=/^\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/jwks$/.exec(request.url);
  if(jwks) {
   if(request.method!=='GET')return finish(405);
   if(['content-length','transfer-encoding','content-encoding'].some(name=>count(name)>1))return finish(400);
   if(!['','identity'].includes(request.headers['content-encoding']??''))return finish(415);
   if(request.headers['transfer-encoding']!==undefined||(request.headers['content-length']!==undefined&&request.headers['content-length']!=='0'))return finish(400);
   try {if(await rateLimiter.consume()!==true)return finish(429);const keys=await keyStore.publicKeys(jwks[1]);return keys===null?finish(404):finish(200,keys);}
   catch{return finish(503);}
  }
  const path=/^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/(tool-key|service-credentials)\/([a-z-]+)$/.exec(request.url);
  if(!path||!Object.hasOwn(permitted[path[3]],path[4]))return finish(404);
  if(request.method!=='POST')return finish(405);
  if(count('origin')!==1||request.headers.origin!==publicOrigin)return finish(403);
  let identity;
  const permission={platformId:path[1],action:'integration-connector:edit'};
  try {if(await rateLimiter.consume()!==true)return finish(429);identity=await authenticateAndAuthorize(request,permission);}catch{return finish(503);}
  if(!identity)return finish(401);
  if(identity.authorized!==true||!ltiId(identity.organizationId)||!ltiId(identity.actorId))return finish(403);
  const scope={organizationId:identity.organizationId,platformId:path[1],registrationId:path[2]},action=path[4];
  let denied=false;
  const reauthorize=async signal=>{
   const current=await authenticateAndAuthorize(request,{...permission,...(signal===undefined?{}:{signal})});
   const allowed=current?.authorized===true&&current.organizationId===identity.organizationId&&current.actorId===identity.actorId;
   if(!allowed)denied=true;return allowed;
  };
  const scoped=async id=>{
   const a=await store.inspect({organizationId:scope.organizationId,operationId:id});
   return a!==null&&a.platformId===scope.platformId&&a.registrationId===scope.registrationId?a:null;
  };
  let input;
  try {
   input=await readLtiHttpForm(request,8192,permitted[path[3]][action]);
   const optional=action==='resolve'?['expected_platform_version','expected_registration_version','expected_key_version','confirmation_reference']:action==='catalog'?['after_id']:[];
   if(permitted[path[3]][action].some(name=>!optional.includes(name)&&!Object.hasOwn(input,name)))return finish(400);
   for(const name of ['operation_id','attempt_id'])if(input[name]!==undefined&&!ltiUuid(input[name]))return finish(400);
  }catch{return finish(400);}
  try {
   let result;
   if(path[3]==='tool-key') {
    if(action==='inspect')result={key:await keyStore.inspect(scope),publicJwksUrl:publicOrigin+`/lti/registrations/${scope.registrationId}/jwks`};
    else if(action==='receipt')result={receipt:await keyStore.receipt({...scope,operationId:input.operation_id})};
    else {
     let command;
     try {command={...scope,operationId:input.operation_id,actorId:identity.actorId,action,
      expectedPlatformVersion:action==='deactivate'?null:version(input.expected_platform_version),
      expectedRegistrationVersion:action==='deactivate'?null:version(input.expected_registration_version),
      expectedKeyVersion:action==='provision'?null:version(input.expected_key_version)};}catch{return finish(400);}
     if(!await reauthorize())return finish(403);
     const receipt=await keyStore.administer(command,reauthorize);
     if(denied||!await reauthorize())return finish(403);return receipt===null?finish(409):finish(200,{receipt});
    }
   } else if(action==='catalog') {
    if(input.after_id!==undefined&&!ltiUuid(input.after_id))return finish(400);
    const page=await store.catalog({...scope,...(input.after_id?{afterId:input.after_id}:{})});
    result={attempts:page.attempts.map(publicAttempt),nextCursor:page.nextCursor};
   } else if(action==='exchange') {
    let command;
    try {command={...scope,operationId:input.operation_id,actorId:identity.actorId,expectedPlatformVersion:version(input.expected_platform_version),
     expectedRegistrationVersion:version(input.expected_registration_version),expectedKeyVersion:version(input.expected_key_version),scopes:ltiServiceScopes(parsePrivateJson(input.scopes))};}catch{return finish(400);}
    if(!await reauthorize())return finish(403);
    const a=await lifecycle.exchange(command,reauthorize);
    if(denied||!await reauthorize())return finish(403);return a===null?finish(409):finish(200,{attempt:publicAttempt(a)});
   } else if(action==='resolution-receipt')result={receipt:await recoveryStore.receipt({...scope,attemptId:input.attempt_id,operationId:input.operation_id})};
   else if(action==='resolve') {
    let command;
    try {const external=input.action==='resolve_unknown';command={...scope,attemptId:input.attempt_id,operationId:input.operation_id,
     actorId:identity.actorId,action:input.action,expectedPhase:input.expected_phase,
     expectedPlatformVersion:external?version(input.expected_platform_version):null,expectedRegistrationVersion:external?version(input.expected_registration_version):null,
     expectedKeyVersion:external?version(input.expected_key_version):null,confirmationReference:external?input.confirmation_reference:null};
     if(!external&&['expected_platform_version','expected_registration_version','expected_key_version','confirmation_reference'].some(name=>input[name]!==undefined))return finish(400);
     if(!['abandon_prepared','retire_known','resolve_unknown'].includes(command.action)||(external&&!ltiUuid(command.confirmationReference)))return finish(400);
     if(command.action==='abandon_prepared'?command.expectedPhase!=='prepared':command.action==='retire_known'?!['staged','published'].includes(command.expectedPhase):!['exchanging','uncertain'].includes(command.expectedPhase))return finish(400);
    }catch{return finish(400);}
    if(!await reauthorize())return finish(403);const receipt=await recoveryStore.recover(command);
    if(!await reauthorize())return finish(403);return receipt===null?finish(409):finish(200,{receipt});
   } else {
    const id=action==='receipt'?input.operation_id:input.attempt_id,a=await scoped(id);
    if(action==='recover'&&a!==null) {
     if(!await reauthorize())return finish(403);
     result={attempt:publicAttempt(await lifecycle.recover({organizationId:scope.organizationId,operationId:id},reauthorize))};
    } else result=action==='receipt'?{receipt:a?.receipt??null,phase:a?.phase??null,attemptId:a?.operationId??null}:{attempt:publicAttempt(a)};
   }
   return denied||!await reauthorize()?finish(403):finish(200,result);
  }catch{return finish(503);}
 };
}
