// SPDX-License-Identifier: AGPL-3.0-only
// Server-only producer adapter. Canonical identity and consent remain in Core.
import {request as httpsRequest} from 'node:https';
import {parsePrivateJson} from './private-json.mjs';

export class GatewayAssociationError extends Error {
 constructor(code,status) {super('Gateway association request failed: '+code);this.name='GatewayAssociationError';this.code=code;if(status!==undefined)this.status=status;}
}
const fail=code=>{throw new GatewayAssociationError(code);};
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)&&value!=='00000000-0000-0000-0000-000000000000';
const id=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value);
const version=value=>Number.isSafeInteger(value)&&value>=1;
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const phase={create:'pending',abandon:'abandoned',expire:'expired'};
function snapshot(input,required,optional=[]) {
 if(input===null||typeof input!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(input)))fail('invalid_request');
 const descriptors=Object.getOwnPropertyDescriptors(input),names=Reflect.ownKeys(descriptors);
 if(names.some(name=>typeof name!=='string'||!required.includes(name)&&!optional.includes(name)
    ||!Object.hasOwn(descriptors[name],'value')||!descriptors[name].enumerable)||required.some(name=>!Object.hasOwn(descriptors,name)))fail('invalid_request');
 return Object.freeze(Object.fromEntries(names.map(name=>[name,descriptors[name].value])));
}
function prepare(input,sourceGrantId) {
 const value=snapshot(input,['challengeId','bindingId','action','body'],['expectedReceipt','signal']);
 const {challengeId,bindingId,action,signal}=value;
 if(!uuid(challengeId)||!id(bindingId)||!['create','inspect','receipt','abandon','expire'].includes(action)
  ||signal!==undefined&&(!(signal instanceof AbortSignal)||signal.aborted))fail('invalid_request');
 const mutation=Object.hasOwn(phase,action);
 const fields=action==='inspect'?[]:action==='create'?['operation_id','expected_source_revision','expected_binding_revision',
  'provider_reference','provider_revision','code_hash','expires_at_ms']:action==='receipt'?['operation_id']:['operation_id','expected_revision'];
 const body=snapshot(value.body,fields);
 if(action!=='inspect'&&!uuid(body.operation_id)||action==='create'&&(![body.expected_source_revision,body.expected_binding_revision,body.provider_revision,body.expires_at_ms].every(version)
  ||!hash(body.provider_reference)||!hash(body.code_hash))||['abandon','expire'].includes(action)&&body.expected_revision!==1)fail('invalid_request');
 let expectedReceipt;
 if(action==='receipt') {
  expectedReceipt=snapshot(value.expectedReceipt,['action','revision']);
  if(!Object.hasOwn(phase,expectedReceipt.action)||expectedReceipt.revision!==(expectedReceipt.action==='create'?1:2))fail('invalid_request');
 }else if(value.expectedReceipt!==undefined)fail('invalid_request');
 const payload=action==='create'?{...body,challenge_id:challengeId,source_grant_id:sourceGrantId,binding_id:bindingId}:body;
 const bytes=Buffer.from(JSON.stringify(payload));if(bytes.length>4096)fail('invalid_request');
 return Object.freeze({challengeId,bindingId,action,body,mutation,expectedReceipt,signal,bytes});
}
function receipt(input,operation,lookup=false) {
 const value=snapshot(input,['operation_id','challenge_id','action','revision','phase']);
 const expected=lookup?operation.expectedReceipt:{action:operation.action,revision:operation.action==='create'?1:operation.body.expected_revision+1};
 if(value.operation_id!==operation.body.operation_id||value.challenge_id!==operation.challengeId
  ||value.action!==expected.action||value.revision!==expected.revision||value.phase!==phase[expected.action])fail('invalid_response');
 return value;
}
function project(input,operation,sourceId) {
 if(operation.mutation)return receipt(input,operation);
 if(operation.action==='receipt') {
  const value=snapshot(input,['kind','receipt']);if(value.kind!=='receipt')fail('invalid_response');
  return Object.freeze({kind:'receipt',receipt:receipt(value.receipt,operation,true)});
 }
 const value=snapshot(input,['kind','record']);if(value.kind!=='current')fail('invalid_response');
 const row=snapshot(value.record,['challenge_id','source_id','binding_id','revision','phase','current','expired','expires_at_ms',
  'application_id','subject_id','identity','can_relink']);
 if(row.challenge_id!==operation.challengeId||row.source_id!==sourceId||row.binding_id!==operation.bindingId
  ||!version(row.expires_at_ms)||!['pending','confirmed','denied','abandoned','expired'].includes(row.phase)||row.revision!==(row.phase==='pending'?1:2)
  ||typeof row.current!=='boolean'||typeof row.expired!=='boolean'||row.application_id!==null||row.subject_id!==null||row.identity!==null||row.can_relink!==false
  ||row.current&&!(row.phase==='confirmed'||row.phase==='pending'&&!row.expired))fail('invalid_response');
 return Object.freeze({kind:'current',record:row});
}

/** No arbitrary headers, URL, transport, session or caller-selected tenant.
 * Source/binding pointers must come from the connector's approved local route.
 * This adapter performs no identity assignment and never retries a write.
 */
export function createGatewayAssociationClient(configuration) {
 let config,gateway;
 try {
  config=snapshot(configuration,['gatewayOrigin','sourceId','sourceGrantId','apiKey'],['ca','timeoutMs']);
  gateway=new URL(config.gatewayOrigin);
  if(typeof globalThis.window!=='undefined'||gateway.protocol!=='https:'||gateway.origin!==config.gatewayOrigin
   ||gateway.username||gateway.password||gateway.search||gateway.hash||gateway.pathname!=='/'
   ||/^(?:issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(gateway.hostname)
   ||/(?:\.svc|\.cluster\.local|\.internal)$/i.test(gateway.hostname)||gateway.hostname==='169.254.169.254'
   ||!id(config.sourceId)||!uuid(config.sourceGrantId)||typeof config.apiKey!=='string'||!/^[A-Za-z0-9._~-]{32,512}$/.test(config.apiKey)
   ||config.ca!==undefined&&(typeof config.ca!=='string'||config.ca.length>65536||!config.ca.includes('-----BEGIN CERTIFICATE-----')||config.ca.includes('PRIVATE KEY')))fail('invalid_configuration');
 }catch{fail('invalid_configuration');}
 const {sourceId,sourceGrantId,apiKey,ca,timeoutMs=15000}=config;
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<50||timeoutMs>120000)fail('invalid_configuration');
 return Object.freeze({
  async execute(input) {
   const operation=prepare(input,sourceGrantId);
   if(operation.signal?.aborted)fail('request_aborted');
   const target=new URL(`/v1/identity/association-challenges/${operation.challengeId}/${operation.action}`,gateway);
   return new Promise((resolve,reject)=>{
    let request,timer,settled=false,dispatched=false;
    const finish=(error,value)=>{
     if(settled)return;settled=true;clearTimeout(timer);operation.signal?.removeEventListener('abort',abort);
     if(error){request?.destroy();reject(operation.mutation&&dispatched?new GatewayAssociationError('association_commit_unknown',error.status):error);}
     else resolve(value);
    };
    const abort=()=>finish(new GatewayAssociationError('request_aborted'));
    timer=setTimeout(()=>finish(new GatewayAssociationError('gateway_timeout')),timeoutMs);
    operation.signal?.addEventListener('abort',abort,{once:true});
    try {
     request=httpsRequest(target,{method:'POST',headers:{'Accept':'application/json','Accept-Encoding':'identity',
      'Content-Type':'application/json','Content-Length':operation.bytes.length,'X-API-Key':apiKey},
      agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,...ca===undefined?{}:{ca}},response=>{
      const status=response.statusCode??0;
      response.on('error',()=>finish(new GatewayAssociationError('transport_error')));
      response.on('aborted',()=>finish(new GatewayAssociationError('transport_error')));
      const header=name=>{
       const values=response.rawHeaders.filter((_,i)=>i%2===1&&response.rawHeaders[i-1].toLowerCase()===name);
       if(values.length>1)throw new GatewayAssociationError('invalid_response');return values[0];
      };
      let length;
      try {
       if(status!==200)throw new GatewayAssociationError(status>=300&&status<400?'redirect_denied':'gateway_rejected',status);
       const type=header('content-type'),encoding=header('content-encoding'),cache=header('cache-control'),declared=header('content-length'),transfer=header('transfer-encoding');
       if(!/^application\/json(?:;\s*charset=(?:utf-8|"utf-8"))?$/i.test(type??'')||encoding!==undefined&&!/^identity$/i.test(encoding)
        ||!/(?:^|,)\s*no-store\s*(?:,|$)/i.test(cache??'')||header('trailer')!==undefined||declared!==undefined&&transfer!==undefined
        ||transfer!==undefined&&!/^chunked$/i.test(transfer))throw new GatewayAssociationError('invalid_response');
       if(declared!==undefined){if(!/^(?:0|[1-9][0-9]{0,4})$/.test(declared)||(length=Number(declared))>8192)throw new GatewayAssociationError('invalid_response');}
      }catch(error){finish(error);return;}
      let size=0;const chunks=[];
      response.on('data',chunk=>{if(settled)return;size+=chunk.length;if(size>8192)finish(new GatewayAssociationError('invalid_response'));else chunks.push(chunk);});
      response.once('end',()=>{
       if(settled)return;
       try {
        if(!response.complete||Object.keys(response.trailers).length||length!==undefined&&length!==size)throw new GatewayAssociationError('invalid_response');
        const value=parsePrivateJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
        finish(null,project(value,operation,sourceId));
       }catch{finish(new GatewayAssociationError('invalid_response'));}
      });
     });
     request.on('error',()=>finish(new GatewayAssociationError('transport_error')));
     if(operation.signal?.aborted){abort();return;}
     dispatched=true;request.end(operation.bytes);
    }catch{finish(new GatewayAssociationError('transport_error'));}
   });
  },
 });
}
