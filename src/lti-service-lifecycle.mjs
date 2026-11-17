// SPDX-License-Identifier: AGPL-3.0-only
import { randomUUID } from 'node:crypto';
import { createCanvasLtiServiceClient } from './canvas-lti-service-client.mjs';
import { ltiServiceExact,ltiServiceCommand,ltiServiceHandle } from './lti-service-contract.mjs';

const unavailable=()=>{throw Error('lti_service_lifecycle_unavailable');};
export function createLtiServiceLifecycle({store,toolKeyStore,canvasPolicy}={}) {
 if(typeof globalThis.window!=='undefined'||['prepare','inspect','begin','permitDispatch','stage','publish','uncertain'].some(name=>typeof store?.[name]!=='function')
  ||typeof toolKeyStore?.current!=='function')unavailable();
 ltiServiceExact(canvasPolicy,['ca','allowedPrivateAddresses','timeoutMs','maxResponseBytes']);
 const policy={...canvasPolicy,allowedPrivateAddresses:[...canvasPolicy.allowedPrivateAddresses]};
 const handle=a=>({organizationId:a.organizationId,operationId:a.operationId});
 const dispatch=a=>({...handle(a),dispatchId:a.dispatchId});
 async function uncertain(h) {try{await store.uncertain(h);}catch{/* Original attempt remains the recovery anchor. */}}
 async function recover(h,reauthorize) {
  let a=await store.inspect(h);if(a===null||a.phase!=='staged')return a;
  try{await store.publish(dispatch(a),reauthorize);}catch{/* Inspect original commit; never reacquire provider credentials. */}
  return store.inspect(h);
 }
 return Object.freeze({
  async recover(value,reauthorize) {try{
   if(reauthorize!==undefined&&typeof reauthorize!=='function')unavailable();return await recover(ltiServiceHandle(value),reauthorize);
  }catch{unavailable();}},
  async exchange(value,reauthorize) {
   try {
    if(reauthorize!==undefined&&typeof reauthorize!=='function')unavailable();
    const authorized=signal=>reauthorize===undefined?Promise.resolve(true):reauthorize(signal);
    const input=ltiServiceCommand(value);
    if(await authorized()!==true)return null;
    const prepared=await store.prepare(input);
    if(prepared===null)return null;
    if(prepared.phase==='staged')return recover(handle(prepared),authorized);
    if(prepared.phase!=='prepared')return prepared;
    const material=await toolKeyStore.current({organizationId:prepared.organizationId,platformId:prepared.platformId,
     registrationId:prepared.registrationId,expectedPlatformVersion:prepared.platformVersion,
     expectedRegistrationVersion:prepared.registrationVersion,expectedKeyVersion:prepared.keyVersion});
    if(material===null)return store.inspect(handle(prepared));
    if(material.kid!==prepared.kid||material.clientId!==prepared.clientId||material.toolOrigin!==prepared.toolOrigin
     ||material.platformVersion!==prepared.platformVersion||material.registrationVersion!==prepared.registrationVersion||material.keyVersion!==prepared.keyVersion)unavailable();
    const claim={...handle(prepared),dispatchId:randomUUID()};
    const client=createCanvasLtiServiceClient({...policy,canvasOrigin:prepared.canvasOrigin,toolOrigin:prepared.toolOrigin,
     clientId:prepared.clientId,toolKey:{kid:material.kid,privateKeyPem:material.privateKeyPem},beforeTokenSend:async({signal})=>{
      if(await authorized(signal)!==true||signal.aborted)return false;return store.permitDispatch(claim);
     }});
    let a;
    if(await authorized()!==true)return store.inspect(handle(prepared));
    try{a=await store.begin(claim);}catch{await uncertain(claim);unavailable();}
    if(a===null)return store.inspect(handle(prepared));
    let bundle;
    try{bundle=await client.requestAccessToken({requestId:a.operationId,issuedAt:a.issuedAt,expiresAt:a.expiresAt,scopes:a.scopes});}
    catch{await uncertain(claim);return store.inspect(handle(prepared));}
    try {
     const staged=await store.stage(a,{accessToken:bundle.accessToken,scopes:bundle.scopes},(a.issuedAt+bundle.expiresIn)*1000);
     if(staged===null){await uncertain(claim);return store.inspect(handle(prepared));}
    }catch {
     const known=await store.inspect(handle(prepared));
     if(known===null||!['staged','published'].includes(known.phase)){await uncertain(claim);return store.inspect(handle(prepared));}
    }
    return recover(handle(prepared),authorized);
   }catch{unavailable();}
  },
 });
}
