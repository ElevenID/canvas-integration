// SPDX-License-Identifier: AGPL-3.0-only
import { request as httpsRequest } from 'node:https';

const unavailable=()=>new Error('connector_key_provider_unavailable');
const identifier=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const record=value=>value!==null && typeof value==='object' && !Array.isArray(value);
/** Read-only, connector-owned OpenBao KV v2 envelope-key custody. Immutable
 * per-key records avoid pruning old keys when the current pointer rotates.
 * No database, Canvas, Gateway, environment, key cache or write capability.
 */
export function createOpenBaoKeyProvider({openbaoOrigin,mount,keyPath,keyNamespace,tokenProvider,ca,timeoutMs=10000}={}) {
  let origin;
  try {origin=new URL(openbaoOrigin);} catch {throw unavailable();}
  if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==openbaoOrigin
      || origin.hostname.endsWith('.') || origin.username || origin.password || origin.search || origin.hash || origin.pathname!=='/'
      || !identifier(mount) || typeof keyPath!=='string' || keyPath.length>512
      || !keyPath.split('/').every(identifier) || !identifier(keyNamespace) || keyNamespace.length>64
      || typeof tokenProvider?.getToken!=='function' || !Number.isSafeInteger(timeoutMs) || timeoutMs<50 || timeoutMs>120000
      || (ca!==undefined && (typeof ca!=='string' || !ca.includes('-----BEGIN CERTIFICATE-----') || ca.length>65536 || /PRIVATE KEY/.test(ca)))) throw unavailable();
  const validKeyId=id=>identifier(id) && id.startsWith(keyNamespace+'-') && id.length>keyNamespace.length+1;
  const read=(path,token,signal)=>new Promise((resolve,reject)=>{
    if(signal.aborted) {reject(unavailable());return;}
    let request;let settled=false;
    const finish=(error,value)=>{
      if(settled)return;settled=true;
      if(error){request?.destroy();reject(unavailable());} else resolve(value);
    };
    request=httpsRequest(new URL(path,origin),{method:'GET',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',
      maxHeaderSize:16384,signal,...(ca===undefined?{}:{ca}),
      headers:{Accept:'application/json','Accept-Encoding':'identity','X-Vault-Token':token}},response=>{
      response.on('error',()=>finish(true));response.on('aborted',()=>finish(true));
      const count=name=>response.rawHeaders.filter((v,i)=>i%2===0&&v.toLowerCase()===name).length;
      if(response.statusCode!==200 || count('content-type')!==1 || count('content-encoding')>1
          || String(response.headers['content-type']??'').split(';')[0].trim().toLowerCase()!=='application/json'
          || !['','identity'].includes(String(response.headers['content-encoding']??''))) return finish(true);
      let size=0;const chunks=[];
      response.on('data',chunk=>{
        size+=chunk.length;if(size>8192)return finish(true);if(!settled)chunks.push(chunk);
      });
      response.on('end',()=>{
        if(settled)return;
        try {
          const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
          const metadata=body?.data?.metadata;
          if(!record(body?.data?.data) || !record(metadata) || !Number.isSafeInteger(metadata.version) || metadata.version<1
              || metadata.destroyed!==false || metadata.deletion_time!=='') throw unavailable();
          finish(false,{data:body.data.data,version:metadata.version});
        } catch {finish(true);}
      });
    });
    request.on('error',()=>finish(true));request.end();
  });
  const operation=async run=>{
    const controller=new AbortController();let timer;
    try {
      return await Promise.race([(async()=>{
        const token=await tokenProvider.getToken({signal:controller.signal});
        if(controller.signal.aborted || typeof token!=='string' || !/^[A-Za-z0-9._~-]{16,4096}$/.test(token)) throw unavailable();
        return run(token,controller.signal);
      })(),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(unavailable());},timeoutMs);})]);
    } catch {throw unavailable();} finally {clearTimeout(timer);controller.abort();}
  };
  const readKey=async(id,token,signal)=>{
    const value=await read(`/v1/${mount}/data/${keyPath}/keys/${id}?version=1`,token,signal);
    if(value.version!==1 || Object.keys(value.data).length!==1 || typeof value.data.key_base64!=='string'
        || !/^[A-Za-z0-9+/]{43}=$/.test(value.data.key_base64)) throw unavailable();
    const key=Buffer.from(value.data.key_base64,'base64');
    if(key.length!==32 || key.toString('base64')!==value.data.key_base64){key.fill(0);throw unavailable();}
    return key;
  };
  return Object.freeze({
    current:()=>operation(async(token,signal)=>{
      const pointer=await read(`/v1/${mount}/data/${keyPath}/current`,token,signal);
      if(Object.keys(pointer.data).length!==1 || !validKeyId(pointer.data.id)) throw unavailable();
      const id=pointer.data.id;return Object.freeze({id,key:await readKey(id,token,signal)});
    }),
    byId:async id=>{
      if(!validKeyId(id))throw unavailable();
      return operation((token,signal)=>readKey(id,token,signal));
    },
  });
}
