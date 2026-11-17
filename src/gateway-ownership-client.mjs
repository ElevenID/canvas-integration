// SPDX-License-Identifier: AGPL-3.0-only
// Session-only public Gateway adapter. No Core database, producer key or provider token.
import {request as httpsRequest} from 'node:https';
import {parsePrivateJson} from './private-json.mjs';

export class GatewayOwnershipError extends Error {
 constructor(code,status) {super('Gateway ownership request failed: '+code);this.name='GatewayOwnershipError';this.code=code;if(status!==undefined)this.status=status;}
}
const fail=code=>{throw new GatewayOwnershipError(code);};
const id=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value);
const user=value=>id(value)&&/^[A-Za-z0-9]/.test(value);
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)&&value!=='00000000-0000-0000-0000-000000000000';
const version=value=>Number.isSafeInteger(value)&&value>=1;
function exact(value,names,optional=[]) {
 if(value===null||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('invalid_request');
 const entries=Object.entries(Object.getOwnPropertyDescriptors(value));
 if(entries.some(([key,descriptor])=>!names.includes(key)&&!optional.includes(key)||!Object.hasOwn(descriptor,'value'))
  ||names.some(key=>!Object.hasOwn(value,key)))fail('invalid_request');
}
function prepare(operation) {
 exact(operation,['applicationId','action','body'],['signal','expectedReceipt']);
 const {applicationId,action,body,signal,expectedReceipt}=operation;
 if(!id(applicationId)||!['propose','confirm','revoke','inspect','receipt'].includes(action)
  ||signal!==undefined&&(!(signal instanceof AbortSignal)||signal.aborted))fail('invalid_request');
 const mutation=['propose','confirm','revoke'].includes(action),proposal=action==='propose';
 if(action==='receipt') {
  exact(expectedReceipt,['action','revision']);
  if(!['propose','confirm','revoke'].includes(expectedReceipt.action)||!version(expectedReceipt.revision))fail('invalid_request');
 }else if(expectedReceipt!==undefined)fail('invalid_request');
 const names=action==='inspect'?[]:action==='receipt'?['operation_id']:
  ['operation_id','expected_revision','expected_application_revision',...proposal?['user_id']:[]];
 exact(body,names);
 if(action!=='inspect'&&!uuid(body.operation_id)||mutation&&(!Number.isSafeInteger(body.expected_revision)
  ||body.expected_revision<(proposal?0:1)||body.expected_revision>=Number.MAX_SAFE_INTEGER||!version(body.expected_application_revision))
  ||proposal&&!user(body.user_id))fail('invalid_request');
 const frozen=Object.freeze(Object.fromEntries(names.map(name=>[name,body[name]])));
 return Object.freeze({applicationId,action,body:frozen,payload:JSON.stringify(frozen),mutation,signal,
  expectedReceipt:expectedReceipt===undefined?undefined:Object.freeze({...expectedReceipt})});
}
function receipt(value,operation,lookup=false) {
 exact(value,['operation_id','application_id','action','revision','status']);
 const status={propose:'proposed',confirm:'confirmed',revoke:'revoked'};
 if(value.operation_id!==operation.body.operation_id||value.application_id!==operation.applicationId
  ||!Object.hasOwn(status,value.action)||value.status!==status[value.action]||!version(value.revision)
  ||(lookup?(value.action!==operation.expectedReceipt.action||value.revision!==operation.expectedReceipt.revision):
   value.action!==operation.action||value.revision!==operation.body.expected_revision+1))fail('invalid_response');
 return Object.freeze({...value});
}
function project(value,operation) {
 if(operation.mutation)return receipt(value,operation);
 if(operation.action==='receipt') {
  exact(value,['kind','receipt']);if(value.kind!=='receipt')fail('invalid_response');
  return Object.freeze({kind:'receipt',receipt:receipt(value.receipt,operation,true)});
 }
 exact(value,['kind','record']);if(value.kind!=='current')fail('invalid_response');
 if(value.record===null)return Object.freeze({kind:'current',record:null});
 const row=value.record;
 exact(row,['application_id','user_id','revision','status','application_revision','proposal_application_revision','current']);
 if(row.application_id!==operation.applicationId||!user(row.user_id)||![row.revision,row.application_revision,row.proposal_application_revision].every(version)
  ||!['proposed','confirmed','revoked'].includes(row.status)||typeof row.current!=='boolean'
  ||row.current&&(row.status!=='confirmed'||row.application_revision!==row.proposal_application_revision))fail('invalid_response');
 return Object.freeze({kind:'current',record:Object.freeze({...row})});
}
export function createGatewayOwnershipClient(configuration={}) {
 let gateway,admin;
 try {
  exact(configuration,['gatewayOrigin','adminOrigin','sessionCookieName'],['ca','timeoutMs']);
  gateway=new URL(configuration.gatewayOrigin);admin=new URL(configuration.adminOrigin);
  if(typeof globalThis.window!=='undefined'||gateway.protocol!=='https:'||gateway.origin!==configuration.gatewayOrigin
   ||gateway.username||gateway.password||gateway.search||gateway.hash||gateway.pathname!=='/'
   ||/^(?:issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(gateway.hostname)
   ||/(?:\.svc|\.cluster\.local|\.internal)$/i.test(gateway.hostname)||gateway.hostname==='169.254.169.254'
   ||admin.protocol!=='https:'||admin.origin!==configuration.adminOrigin
   ||typeof configuration.sessionCookieName!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(configuration.sessionCookieName)
   ||configuration.ca!==undefined&&(typeof configuration.ca!=='string'||configuration.ca.length>65536
    ||!configuration.ca.includes('-----BEGIN CERTIFICATE-----')||configuration.ca.includes('PRIVATE KEY')))fail('invalid_configuration');
 }catch{fail('invalid_configuration');}
 const {adminOrigin,sessionCookieName,ca,timeoutMs=15000}=configuration;
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<50||timeoutMs>120000)fail('invalid_configuration');
 function incomingContext(incoming) {
  const raw=incoming?.rawHeaders;
  if(!Array.isArray(raw)||raw.length>128||raw.length%2||raw.some(value=>typeof value!=='string'||value.length>8192))fail('session_required');
  const values=name=>raw.filter((_,index)=>index%2===1&&raw[index-1].toLowerCase()===name);
  const origins=values('origin'),intent=values('x-connector-organization-intent');
  if(origins.length!==1||origins[0]!==adminOrigin||intent.length>1||intent.length===1&&!uuid(intent[0])
   ||['x-api-key','x-api-key-id','authorization'].some(name=>values(name).length))fail('session_required');
  const cookies=values('cookie');if(cookies.join(';').length>8192)fail('session_required');
  const selected=cookies.flatMap(value=>value.split(';')).map(value=>value.trim()).filter(value=>value.split('=')[0]===sessionCookieName);
  if(selected.length!==1||!new RegExp('^'+sessionCookieName+'=[A-Za-z0-9._~-]{16,1024}$').test(selected[0]))fail('session_required');
  return {cookie:selected[0],intent:intent[0]};
 }
 function send(path,context,signal,payload) {
  return new Promise((resolve,reject)=>{
   let request,settled=false;
   const finish=(error,value)=>{if(settled)return;settled=true;if(error){request?.destroy();reject(error);}else resolve(value);};
   try {
    request=httpsRequest(new URL(path,gateway),{method:payload===undefined?'GET':'POST',agent:false,rejectUnauthorized:true,
     minVersion:'TLSv1.2',maxHeaderSize:16384,signal,...ca===undefined?{}:{ca},headers:{Accept:'application/json','Accept-Encoding':'identity',
      'Cache-Control':'no-store',Cookie:context.cookie,...payload===undefined?{}:{Origin:adminOrigin,'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}}},response=>{
     response.on('error',()=>finish(new GatewayOwnershipError('ownership_unavailable')));
     response.on('aborted',()=>finish(new GatewayOwnershipError('ownership_unavailable')));
     const deny=()=>{finish(new GatewayOwnershipError('ownership_unavailable',response.statusCode));response.destroy();};
     if(response.statusCode!==200)return deny();
     const count=name=>response.rawHeaders.filter((_,i)=>i%2===0&&response.rawHeaders[i].toLowerCase()===name).length;
     if(count('content-type')!==1||count('content-encoding')>1||count('content-length')>1
      ||String(response.headers['content-type']??'').split(';')[0].trim().toLowerCase()!=='application/json'
      ||!['','identity'].includes(String(response.headers['content-encoding']??''))||response.headers.trailer!==undefined
      ||payload!==undefined&&!String(response.headers['cache-control']??'').split(',').some(value=>value.trim().toLowerCase()==='no-store'))return deny();
     const length=response.headers['content-length'];
     if(length!==undefined&&(!/^[0-9]{1,6}$/.test(length)||Number(length)>65536))return deny();
     const chunks=[];let size=0;
     response.on('data',chunk=>{size+=chunk.length;if(size>65536)return deny();if(!settled)chunks.push(chunk);});
     response.on('end',()=>{
      if(settled)return;
      try {if(length!==undefined&&Number(length)!==size)throw Error();
       finish(null,parsePrivateJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))));
      }catch{finish(new GatewayOwnershipError('invalid_response'));}
     });
    });
    request.on('error',()=>finish(new GatewayOwnershipError('ownership_unavailable')));
    request.end(payload);
   }catch{finish(new GatewayOwnershipError('ownership_unavailable'));}
  });
 }
 async function session(context,signal) {
  const value=await send('/v1/auth/me',context,signal);
  const identity=value?.user;
  if(value?.authenticated!==true||!identity||!user(identity.user_id)||!uuid(identity.organization_id)
   ||identity.organization_context_unavailable===true||context.intent!==undefined&&context.intent!==identity.organization_id)fail('session_required');
  return Object.freeze({organizationId:identity.organization_id,actorId:identity.user_id});
 }
 return Object.freeze({async execute(incoming,operation) {
  let dispatched=false;
  const plan=prepare(operation),context=incomingContext(incoming),controller=new AbortController();
  const abort=()=>controller.abort();plan.signal?.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,timeoutMs);
  try {
   if(plan.signal?.aborted||controller.signal.aborted)fail('ownership_unavailable');
   const initial=await session(context,controller.signal);
   if(controller.signal.aborted)fail('ownership_unavailable');
   dispatched=plan.mutation;
   const value=await send(`/v1/organizations/${initial.organizationId}/application-ownerships/${plan.applicationId}/${plan.action}`,
    context,controller.signal,plan.payload);
   let result;try{result=project(value,plan);}catch{fail('invalid_response');}
   const current=await session(context,controller.signal);
   if(initial.organizationId!==current.organizationId||initial.actorId!==current.actorId||controller.signal.aborted)fail('session_required');
   return Object.freeze({...current,result});
  }catch(error) {
   if(dispatched)throw new GatewayOwnershipError('ownership_commit_unknown',error instanceof GatewayOwnershipError?error.status:undefined);
   throw new GatewayOwnershipError(error instanceof GatewayOwnershipError?error.code:'ownership_unavailable');
  }finally{clearTimeout(timer);plan.signal?.removeEventListener('abort',abort);}
 }});
}
