// SPDX-License-Identifier: AGPL-3.0-only
import {request as httpsRequest} from 'node:https';
import {createGatewayAdminAuthenticator} from './gateway-admin-auth.mjs';
import {parsePrivateJson} from './private-json.mjs';
const unavailable=()=>new Error('gateway_binding_read_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);

// Fixed public-Gateway session transport. No URL/tenant/header/credential override
// or authority snapshot supplied by a caller or production configuration.
export function createGatewayBindingReader(configuration={}) {
  let authenticate,gateway;
  try {
    if(configuration===null || typeof configuration!=='object' || Array.isArray(configuration)
      || Object.keys(configuration).some(key=>!['gatewayOrigin','adminOrigin','sessionCookieName','ca','timeoutMs'].includes(key))) throw unavailable();
    authenticate=createGatewayAdminAuthenticator(configuration);gateway=new URL(configuration.gatewayOrigin);
  } catch {throw unavailable();}
  const {adminOrigin,sessionCookieName,ca,timeoutMs=15000}=configuration;
  function read(organization,binding,cookie) {
    return new Promise((resolve,reject)=>{
      let request,settled=false;
      const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);
      const finish=(error,value)=>{
        if(settled) return;settled=true;clearTimeout(timer);
        if(error) {request?.destroy();reject(unavailable());} else resolve(value);
      };
      request=httpsRequest(new URL(`/v1/organizations/${organization}/external-observation-bindings/${binding}/inspect`,gateway),{
        method:'POST',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,signal:controller.signal,
        ...(ca===undefined?{}:{ca}),headers:{Accept:'application/json','Accept-Encoding':'identity',
          'Content-Type':'application/json','Content-Length':2,Origin:adminOrigin,Cookie:cookie}},response=>{
        response.on('error',()=>finish(true));response.on('aborted',()=>finish(true));
        if([401,403].includes(response.statusCode)) {finish(false,null);response.destroy();return;}
        const count=name=>response.rawHeaders.filter((_,i)=>i%2===0 && response.rawHeaders[i].toLowerCase()===name).length;
        if(response.statusCode!==200 || count('content-type')!==1 || count('content-encoding')>1 || count('content-length')>1
          || String(response.headers['content-type']??'').split(';')[0].trim().toLowerCase()!=='application/json'
          || !['','identity'].includes(String(response.headers['content-encoding']??''))
          || !String(response.headers['cache-control']??'').split(',').some(value=>value.trim().toLowerCase()==='no-store')) return finish(true);
        const length=response.headers['content-length'];
        if(length!==undefined && (!/^[0-9]{1,6}$/.test(length) || Number(length)>131072)) return finish(true);
        const chunks=[];let size=0;
        response.on('data',chunk=>{size+=chunk.length;if(size>131072) return finish(true);if(!settled) chunks.push(chunk);});
        response.on('end',()=>{
          if(settled) return;
          try {
            if(length!==undefined && Number(length)!==size) throw unavailable();
            const value=parsePrivateJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
            if(value===null || typeof value!=='object' || Array.isArray(value)
              || Object.keys(value).sort().join(',')!=='found,record,snapshot_at_ms' || typeof value.found!=='boolean'
              || !Number.isSafeInteger(value.snapshot_at_ms) || value.snapshot_at_ms<=0
              || (value.found?(value.record===null || typeof value.record!=='object' || Array.isArray(value.record) || value.record.id!==binding):value.record!==null)) throw unavailable();
            finish(false,value);
          } catch {finish(true);}
        });
      });
      request.on('error',()=>finish(true));request.end('{}');
    });
  }
  return async(incoming,operation)=>{
    try {
      if(operation===null || typeof operation!=='object' || Object.keys(operation).sort().join(',')!=='bindingId,platformId'
        || !id(operation.bindingId) || typeof operation.platformId!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(operation.platformId)) throw unavailable();
      const authOperation={platformId:operation.platformId,action:'integration-connector:edit'};
      const identity=await authenticate(incoming,authOperation);
      if(!identity || identity.authorized!==true) return null;
      // The authenticator accepted exactly one bounded session cookie and Origin.
      // Reconstruct only that cookie; never forward a producer key, other cookies
      // or caller organization/user/service headers.
      const cookies=incoming.rawHeaders.flatMap((value,i)=>i%2===1 && incoming.rawHeaders[i-1].toLowerCase()==='cookie'?value.split(';'):[]);
      const selected=cookies.map(value=>value.trim()).filter(value=>value.split('=')[0]===sessionCookieName);
      if(selected.length!==1 || !new RegExp(`^${sessionCookieName}=[A-Za-z0-9._~-]{16,1024}$`).test(selected[0])) return null;
      const snapshot=await read(identity.organizationId,operation.bindingId,selected[0]);if(snapshot===null) return null;
      const current=await authenticate(incoming,authOperation);
      if(!current || current.authorized!==true || current.organizationId!==identity.organizationId || current.actorId!==identity.actorId) return null;
      return Object.freeze({organizationId:identity.organizationId,actorId:identity.actorId,snapshot});
    } catch {throw unavailable();}
  };
}
