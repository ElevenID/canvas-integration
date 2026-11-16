// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:https';
import { createLtiProviderIdentityHandler } from '../src/lti-provider-identity-http.mjs';
import { createLtiProviderIdentityStore } from '../src/lti-provider-identity-store.mjs';
import { ltiBrowserCookieName } from '../src/lti-browser-binding.mjs';
import { httpsFixture } from './support/canvas-https-fixture.mjs';
const registrationId='10000000-0000-4000-8000-000000000003',identityId='20000000-0000-4000-8000-000000000003';
const state=Buffer.alloc(32,1).toString('base64url'),proof=Buffer.alloc(32,2).toString('base64url');
const cookie=ltiBrowserCookieName(state)+'='+proof,path=`/lti/registrations/${registrationId}/provider-identity`;
const receipt={launchId:'30000000-0000-4000-8000-000000000003',registrationId,identityId,status:'numeric_linked',identityRevision:2,numericIdSupplied:true,recordedAtMs:1794859200000};
const digest=value=>createHash('sha256').update(value).digest('hex');
const input={registrationId,stateHash:digest(state),browserHash:digest(proof)};
async function fixture(options={}) {
 const tls=await httpsFixture(),calls=[];
 const handler=createLtiProviderIdentityHandler({publicOrigin:tls.origin,rateLimiter:options.rateLimiter??{consume:async()=>true},
  store:options.store??{observe:async value=>{calls.push(['observe',value]);return receipt;},
   current:async value=>{calls.push(['current',value]);return {identityId,status:'numeric_linked',identityRevision:2,canvasUserId:'42'};}}});
 tls.setHandler((req,res)=>{void handler(req,res).catch(()=>res.destroy());});
 async function send(fields={state},{headers=[],method='POST',includeOrigin=true,includeCookie=true}={}) {
  const body=new URLSearchParams(fields).toString();
  return new Promise((resolve,reject)=>{
   const req=request(new URL(path,tls.origin),{method,ca:tls.ca,agent:false,headers:['Host',new URL(tls.origin).host,
    'Content-Type','application/x-www-form-urlencoded','Content-Length',String(Buffer.byteLength(body)),
    ...(includeOrigin?['Origin',tls.origin]:[]),...(includeCookie?['Cookie',cookie]:[]),...headers]},res=>{
     let result='';res.setEncoding('utf8');res.on('data',chunk=>result+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:result}));
   });req.on('error',reject);req.end(body);
  });
 }
 return {...tls,calls,send};
}
test('accepted browser proof records provider status without exposing numeric or canonical authority',async()=>{
 const f=await fixture();try{
  const result=await f.send();assert.equal(result.status,200);assert.equal(result.headers['cache-control'],'no-store');
  assert.deepEqual(f.calls,[['observe',input],['current',input]]);
  assert.deepEqual(JSON.parse(result.body),{receipt,current:{status:'numeric_linked',identityRevision:2,numericIdAvailable:true}});
  assert.equal(result.body.includes('canvasUserId'),false);assert.equal(result.body.includes('42'),false);
 }finally{await f.close();}
});
test('cookie-free proof works while conflicting or duplicate cookies fail before mutation',async()=>{
 const f=await fixture();try{
  assert.equal((await f.send({state,browser_proof:proof},{includeCookie:false})).status,200);
  assert.equal((await f.send({state,browser_proof:proof})).status,200);
  const before=f.calls.length;
  assert.equal((await f.send({state,browser_proof:Buffer.alloc(32,3).toString('base64url')})).status,400);
  assert.equal((await f.send({state},{headers:['Cookie',cookie]})).status,400);assert.equal(f.calls.length,before);
 }finally{await f.close();}
});
test('caller identity, malformed proof, missing proof and foreign Origin confer no observation',async()=>{
 const f=await fixture();try{
  for(const extra of [{organization_id:'attacker'},{subject:'attacker'},{canvas_user_id:'42'},{application_id:'attacker'},{verified:'true'}]) {
   assert.equal((await f.send({state,...extra})).status,400);
  }
  assert.equal((await f.send({state},{includeCookie:false})).status,403);
  assert.equal((await f.send({state:'invalid'})).status,400);
  assert.equal((await f.send({state},{includeOrigin:false})).status,403);
  assert.equal((await f.send({state},{includeOrigin:false,headers:['Origin','https://evil.invalid']})).status,403);
  assert.equal((await f.send({state},{headers:['Origin',f.origin]})).status,403);
  assert.equal((await f.send({state},{method:'GET'})).status,405);assert.equal(f.calls.length,0);
 }finally{await f.close();}
});
test('quota and unknown commit fail closed without automatic write retry or sensitive errors',async()=>{
 let calls=0;
 const f=await fixture({store:{observe:async()=>{calls++;throw Error('secret synthetic failure');},current:async()=>{throw Error('must not read');}}});
 try{const result=await f.send();assert.equal(result.status,503);assert.equal(result.body,'');assert.equal(calls,1);}finally{await f.close();}
 const limited=await fixture({rateLimiter:{consume:async()=>false}});
 try{assert.equal((await limited.send()).status,429);assert.equal(limited.calls.length,0);}finally{await limited.close();}
});
test('historical receipt can coexist with no current provider mapping',async()=>{
 const f=await fixture({store:{observe:async()=>receipt,current:async()=>null}});
 try{assert.deepEqual(JSON.parse((await f.send()).body),{receipt,current:null});}finally{await f.close();}
});
test('repository binds SQL scope and rejects corrupted receipts and caller authority fields',async()=>{
 const calls=[];let result=receipt;
 const store=createLtiProviderIdentityStore({query:async(sql,values)=>{calls.push({sql,values});return {rows:[{result}]};}});
 assert.deepEqual(await store.observe(input),receipt);assert.equal(calls[0].values[0],registrationId);
 assert.deepEqual(calls[0].values.slice(1,3),[input.stateHash,input.browserHash]);
 for(const change of [v=>v.registrationId=identityId,v=>v.status='verified',v=>v.identityRevision=0,v=>v.subjectId='forbidden',v=>v.numericIdSupplied='true']) {
  result=structuredClone(receipt);change(result);await assert.rejects(store.observe(input),{message:'lti_provider_identity_unavailable'});
 }
 const before=calls.length;
 await assert.rejects(store.observe({...input,organizationId:'attacker'}));assert.equal(calls.length,before);
});
test('current mapping decoder suppresses quarantined numeric IDs and rejects extra authority',async()=>{
 let result={identityId,status:'numeric_linked',identityRevision:2,canvasUserId:'42'};
 const store=createLtiProviderIdentityStore({query:async()=>({rows:[{result}]})});
 assert.equal((await store.current(input)).canvasUserId,'42');
 result={identityId,status:'quarantined',identityRevision:3,canvasUserId:null};assert.equal((await store.current(input)).canvasUserId,null);
 for(const invalid of [{...result,canvasUserId:'42'},{...result,userId:'forbidden'},{...result,identityRevision:'3'}]) {
  result=invalid;await assert.rejects(store.current(input),{message:'lti_provider_identity_unavailable'});
 }
});
