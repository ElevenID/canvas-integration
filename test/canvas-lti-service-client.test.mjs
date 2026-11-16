// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomUUID, verify } from 'node:crypto';
import { generateLtiToolKey, prepareLtiToolKey, signLtiClientAssertion } from '../src/lti-tool-assertion.mjs';
import { createCanvasLtiServiceClient, ltiReadScopes } from '../src/canvas-lti-service-client.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const tool=generateLtiToolKey(), tokenValue='synthetic_canvas_lti_service_access_token_000001';
const toolOrigin='https://tool.example.test';
const requestInput=(requested=[ltiReadScopes.results])=>{
  const issuedAt=Math.floor(Date.now()/1000);return{requestId:randomUUID(),issuedAt,expiresAt:issuedAt+90,scopes:requested};
};
const access=(requested=Object.values(ltiReadScopes))=>({accessToken:tokenValue,scopes:requested,expiresAtMs:Date.now()+60000});
async function fixture(t,changes={}) {
  const peer=await httpsFixture();t.after(()=>peer.close());
  const configuration={canvasOrigin:peer.origin,toolOrigin,clientId:'canvas-lti-client',toolKey:{kid:tool.kid,privateKeyPem:tool.privateKeyPem},ca:peer.ca,
    allowedPrivateAddresses:['127.0.0.1','::1'],...changes};
  return{peer,client:createCanvasLtiServiceClient(configuration),configuration};
}
function result(origin,user='opaque:user') {return{id:origin+'/api/lti/courses/11/line_items/33/results/44',userId:user,scoreOf:origin+'/api/lti/courses/11/line_items/33',resultScore:8,resultMaximum:10,comment:'private learner comment'};}

test('connector tool key has public-only JWKS projection and narrow original-attempt RS256 assertions',()=>{
  const prepared=prepareLtiToolKey({kid:tool.kid,privateKeyPem:tool.privateKeyPem}),attempt=requestInput();
  assert.deepEqual(Object.keys(prepared.publicJwk).sort(),['alg','e','kid','kty','n','use']);
  const jwt=signLtiClientAssertion(prepared,{toolOrigin,clientId:'client',tokenEndpoint:'https://canvas.example.test/login/oauth2/token',...Object.fromEntries(Object.entries(attempt).filter(([name])=>name!=='scopes'))});
  const [header,payload,signature]=jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header,'base64url')),{typ:'JWT',alg:'RS256',kid:tool.kid});
  assert.deepEqual(JSON.parse(Buffer.from(payload,'base64url')),{iss:toolOrigin,sub:'client',aud:'https://canvas.example.test/login/oauth2/token',iat:attempt.issuedAt,exp:attempt.expiresAt,jti:attempt.requestId});
  assert.equal(verify('RSA-SHA256',Buffer.from(header+'.'+payload),createPublicKey({key:prepared.publicJwk,format:'jwk'}),Buffer.from(signature,'base64url')),true);
  const weak=generateKeyPairSync('rsa',{modulusLength:1024});
  assert.throws(()=>prepareLtiToolKey({kid:randomUUID(),privateKeyPem:weak.privateKey.export({type:'pkcs8',format:'pem'})}),/lti_tool_key_unavailable/);
  assert.throws(()=>signLtiClientAssertion(prepared,{toolOrigin,clientId:'client',tokenEndpoint:'https://canvas.example.test/internal/sign',requestId:attempt.requestId,issuedAt:attempt.issuedAt,expiresAt:attempt.expiresAt}),/lti_tool_key_unavailable/);
});

test('actual verified-TLS token request signs only configured Canvas audience and exact read scopes, once',async t=>{
  const {peer,client}=await fixture(t),attempt=requestInput([ltiReadScopes.memberships,ltiReadScopes.results]);let calls=0;
  peer.setHandler((req,res)=>{void(async()=>{
    calls++;assert.equal(req.method,'POST');assert.equal(req.url,'/login/oauth2/token');assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);
    let body='';for await(const chunk of req)body+=chunk;const form=new URLSearchParams(body);
    assert.deepEqual([...form.keys()].sort(),['client_assertion','client_assertion_type','grant_type','scope']);
    assert.equal(form.get('grant_type'),'client_credentials');assert.equal(form.get('client_assertion_type'),'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    assert.equal(form.get('scope'),[...attempt.scopes].sort().join(' '));
    const [head,payload,signature]=form.get('client_assertion').split('.'),claims=JSON.parse(Buffer.from(payload,'base64url'));
    assert.equal(claims.aud,peer.origin+'/login/oauth2/token');assert.equal(claims.iss,toolOrigin);assert.equal(claims.sub,'canvas-lti-client');assert.equal(claims.jti,attempt.requestId);
    assert.equal(verify('RSA-SHA256',Buffer.from(head+'.'+payload),createPublicKey({key:client.publicJwk,format:'jwk'}),Buffer.from(signature,'base64url')),true);
    json(res,{access_token:tokenValue,token_type:'Bearer',expires_in:3600,scope:ltiReadScopes.results});
  })().catch(()=>res.destroy());});
  assert.deepEqual(await client.requestAccessToken(attempt),{accessToken:tokenValue,expiresIn:3600,scopes:[ltiReadScopes.results]});
  assert.equal(calls,1,'subset grant is reported, never expanded or retried');
});

test('AGS reads pin result learner and line item, strip comments and never infer completion',async t=>{
  const {peer,client}=await fixture(t);let mode='lineitem';
  peer.setHandler((req,res)=>{
    assert.equal(req.headers.authorization,'Bearer '+tokenValue);assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
    if(mode==='lineitem')return json(res,{id:peer.origin+'/api/lti/courses/11/line_items/33',scoreMaximum:10,resourceLinkId:'link-one',label:'private gradebook label'});
    const value=result(peer.origin);if(mode==='foreign')value.userId='another-learner';if(mode==='lineitem-mismatch')value.scoreOf=peer.origin+'/api/lti/courses/12/line_items/33';
    if(mode==='duplicate')return json(res,[value,value]);if(mode==='empty')return json(res,[]);json(res,[value]);
  });
  assert.deepEqual(await client.readLineItem({token:access(),courseId:'11',lineItemId:'33'}),{id:peer.origin+'/api/lti/courses/11/line_items/33',scoreMaximum:10,resourceLinkId:'link-one'});
  mode='results';const value=await client.readResults({token:access(),courseId:'11',lineItemId:'33',userId:'opaque:user'});
  assert.deepEqual(value,{userId:'opaque:user',resultScore:8,resultMaximum:10,lineItemUrl:peer.origin+'/api/lti/courses/11/line_items/33'});
  assert.equal(JSON.stringify(value).includes('private'),false);assert.equal(Object.hasOwn(value,'completed'),false);
  assert.equal(new URL(peer.seen.at(-1).url,peer.origin).searchParams.get('user_id'),'opaque:user');
  for(mode of ['foreign','lineitem-mismatch','duplicate'])await assert.rejects(client.readResults({token:access(),courseId:'11',lineItemId:'33',userId:'opaque:user'}),/resource_mismatch/);
  mode='empty';assert.equal(await client.readResults({token:access(),courseId:'11',lineItemId:'33',userId:'opaque:user'}),null);
});

test('NRPS completes bounded same-scope pagination and returns only provider membership fields',async t=>{
  const {peer,client}=await fixture(t);let mode='valid';
  peer.setHandler((req,res)=>{
    const url=new URL(req.url,peer.origin),page=url.searchParams.get('page');assert.equal(url.searchParams.get('rlid'),'link-one');
    const row={user_id:page?'learner-opaque':'other-opaque',status:'Active',roles:['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],name:'private learner name',email:'private@example.test'};
    if(mode==='duplicate')row.user_id='learner-opaque';
    const next=new URL(url);next.searchParams.set('page','2');if(mode==='scope-drift')next.searchParams.set('rlid','other-link');
    if(mode==='origin-drift')next.hostname='evil.example';if(mode==='loop')next.href=url.href;
    json(res,{id:url.href,context:{id:mode==='context-drift'?'wrong':'context-one'},members:[row]},200,page?{}:{Link:`<${next.href}>; rel="next"`});
  });
  const input=()=>({token:access(),courseId:'11',userId:'learner-opaque',contextId:'context-one',resourceLinkId:'link-one'});
  assert.deepEqual(await client.readMembership(input()),{userId:'learner-opaque',contextId:'context-one',status:'Active',roles:['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner']});
  assert.equal(peer.seen.length,2);
  for(mode of ['scope-drift','origin-drift','loop','context-drift','duplicate'])await assert.rejects(client.readMembership(input()),/canvas_lti_service_/);
});

test('redirects, malformed or enlarged responses, escalated scope and unknown token replies never retry',async t=>{
  const {peer,client}=await fixture(t,{maxResponseBytes:512});
  for(const handler of [
    (_req,res)=>{res.writeHead(302,{Location:'https://evil.example/steal'});res.end();},
    (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end('{"access_token":"private","access_token":"duplicate"}');},
    (_req,res)=>json(res,{access_token:tokenValue,token_type:'Bearer',expires_in:3600,scope:ltiReadScopes.memberships}),
    (_req,res)=>json(res,{access_token:tokenValue,token_type:'Bearer',expires_in:3600,scope:ltiReadScopes.results,extra:'private'.repeat(100)}),
    (_req,res)=>res.destroy(),
  ]) {
    peer.setHandler(handler);const before=peer.seen.length;
    await assert.rejects(client.requestAccessToken(requestInput()),error=>{assert.equal(error.message.includes(tokenValue),false);assert.equal(error.message.includes('private'),false);return /^canvas_lti_service_/.test(error.message);});
    assert.equal(peer.seen.length-before,1);
  }
});

test('server-only configuration rejects alternate transports, expired assertions and ungranted reads before network',async t=>{
  const {peer,client,configuration}=await fixture(t);
  for(const change of [{transport:()=>{}},{canvasOrigin:'http://canvas.example'},{canvasOrigin:'https://issuance.internal'},{clientId:'bad\nclient'},{toolKey:{...configuration.toolKey,kid:'caller-kid'}}])assert.throws(()=>createCanvasLtiServiceClient({...configuration,...change}),/invalid_configuration/);
  await assert.rejects(client.requestAccessToken({...requestInput(),expiresAt:Math.floor(Date.now()/1000)-1}),/expired_assertion/);
  await assert.rejects(client.readResults({token:access([ltiReadScopes.memberships]),courseId:'11',lineItemId:'33',userId:'learner'}),/invalid_token/);
  assert.equal(peer.seen.length,0);
  globalThis.window={};
  try{assert.throws(()=>createCanvasLtiServiceClient(configuration),/invalid_configuration/);assert.throws(()=>generateLtiToolKey(),/lti_tool_key_unavailable/);}
  finally{delete globalThis.window;}
});

test('pagination cannot send an expired credential or extend its lifetime by mutating caller state',async t=>{
  const {peer,client}=await fixture(t),token=access(),realNow=Date.now;
  let clock=realNow(),calls=0;
  peer.setHandler((req,res)=>{
    calls++;const url=new URL(req.url,peer.origin),next=new URL(url);next.searchParams.set('page','2');
    // The first response consumes the original credential lifetime. A caller
    // mutation cannot authorize the next page using that same access token.
    clock=token.expiresAtMs+1;token.expiresAtMs=clock+60000;
    json(res,[],200,{Link:`<${next.href}>; rel="next"`});
  });
  Date.now=()=>clock;
  try {
    await assert.rejects(client.readResults({token,courseId:'11',lineItemId:'33',userId:'opaque:user'}),/expired_credential/);
    assert.equal(calls,1,'expired credentials never reach a second network send');
  } finally {Date.now=realNow;}
});
