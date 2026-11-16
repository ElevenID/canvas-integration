// SPDX-License-Identifier: AGPL-3.0-only
import { createHash,timingSafeEqual } from 'node:crypto';
import { readLtiHttpForm } from './lti-launch-http.mjs';
import { readLtiBrowserCookie } from './lti-browser-binding.mjs';
const proof=value=>typeof value==='string' && /^[A-Za-z0-9_-]{43}$/.test(value)
 && Buffer.from(value,'base64url').toString('base64url')===value;
const digest=value=>createHash('sha256').update(value).digest('hex');
export function createLtiProviderIdentityHandler({store,publicOrigin,rateLimiter}={}) {
 let origin;try{origin=new URL(publicOrigin);}catch{throw Error('invalid_lti_identity_http');}
 if(typeof globalThis.window!=='undefined' || origin.protocol!=='https:' || origin.origin!==publicOrigin
  || typeof store?.observe!=='function' || typeof store?.current!=='function' || typeof rateLimiter?.consume!=='function') throw Error('invalid_lti_identity_http');
 return async(request,response)=>{
  const finish=(status,value)=>{
   if(response.destroyed)return;
   const body=value===undefined?'':JSON.stringify(value);
   response.writeHead(status,{'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(body)),
    'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);
  };
  if(typeof request.url!=='string' || Buffer.byteLength(request.url)>8192)return finish(414);
  if(request.rawHeaders.length>128)return finish(431);
  const values=name=>request.rawHeaders.filter((_,i)=>i%2===1 && request.rawHeaders[i-1].toLowerCase()===name);
  const hosts=values('host'),origins=values('origin');
  if(hosts.length!==1 || hosts[0]!==origin.host)return finish(421);
  const path=/^\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/provider-identity$/.exec(request.url);
  if(!path)return finish(404);if(request.method!=='POST')return finish(405);
  if(origins.length!==1 || origins[0]!==publicOrigin)return finish(403);
  try{if(await rateLimiter.consume()!==true)return finish(429);}catch{return finish(503);}
  let fields;
  try{fields=await readLtiHttpForm(request,2048,['state','browser_proof']);}catch{return finish(400);}
  if(!proof(fields.state) || (fields.browser_proof!==undefined && !proof(fields.browser_proof)))return finish(400);
  const cookie=readLtiBrowserCookie(request,fields.state);if(cookie.kind==='invalid')return finish(400);
  if(cookie.kind==='present' && fields.browser_proof!==undefined &&
    !timingSafeEqual(Buffer.from(cookie.proof),Buffer.from(fields.browser_proof)))return finish(400);
  const browserProof=cookie.kind==='present'?cookie.proof:fields.browser_proof;
  if(!proof(browserProof))return finish(403);
  const input=Object.freeze({registrationId:path[1],stateHash:digest(fields.state),browserHash:digest(browserProof)});
  try {
   const receipt=await store.observe(input);if(receipt===null)return finish(403);
   const current=await store.current(input);
   // Only local provider status reaches the browser. Never expose provider IDs,
   // credentials or Core identity/application/grant/binding authority here.
   return finish(200,{receipt,current:current===null?null:{status:current.status,
    identityRevision:current.identityRevision,numericIdAvailable:current.canvasUserId!==null}});
  }catch{return finish(503);}
 };
}
