// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
import { createLtiRegistrationAdminHandler } from '../src/lti-registration-admin-http.mjs';
import { prepareLtiRegistrationDefinition } from '../src/lti-registration-contract.mjs';
import { httpsFixture } from './support/canvas-https-fixture.mjs';

const reg='40000000-0000-4000-8000-000000000001',op='40000000-0000-4000-8000-000000000002';
const prefix=`/platforms/platform-one/lti/registrations/${reg}`;
const fields={operation_id:op,expected_platform_version:'1',client_id:'public-client',deployment_id:'deployment-one',trust_profile:'hosted_global',environment:'production'};
async function fixture(options={}) {
  const peer=await httpsFixture(),calls=[];let authCalls=0;
  const identity={organizationId:'org-one',actorId:'actor-one',authorized:true};
  const store={
    async platform(scope){calls.push(['platform',scope]);return{platformId:'platform-one',configVersion:1,canvasOrigin:options.canvasOrigin??'https://college.instructure.com',enabled:true,archived:false};},
    async catalog(scope){calls.push(['catalog',scope]);return{registrations:[],nextCursor:null};},
    async inspect(scope){calls.push(['inspect',scope]);return{version:1,definition:prepareLtiRegistrationDefinition({clientId:'public-client',deploymentId:'deployment-one',trustProfile:'hosted_global',environment:'production'},{registrationId:reg,publicOrigin:peer.origin})};},
    async receipt(scope){calls.push(['receipt',scope]);return null;},
    async replay(command){calls.push(['replay',command]);return options.replay??null;},
    async apply(command){calls.push(['apply',command]);return{operationId:command.operationId};},
  };
  const handler=createLtiRegistrationAdminHandler({store,publicOrigin:peer.origin,selfManagedOriginAllowlist:options.allowlist??[],
    rateLimiter:{consume:async()=>options.quota!==false},authenticateAndAuthorize:async()=>{
      authCalls++;return options.identity===null?null:authCalls>1&&options.finalIdentity?options.finalIdentity:options.identity??identity;
    }});
  peer.setHandler((req,res)=>{void handler(req,res).catch(()=>res.destroy());});
  async function send(action,value={},extra=[]) {
    authCalls=0;
    const body=typeof value==='string'?value:new URLSearchParams(value).toString();
    return new Promise((resolve,reject)=>{
      const req=request(new URL(action==='catalog'?'/platforms/platform-one/lti/registrations/catalog':prefix+'/'+action,peer.origin),
        {method:'POST',agent:false,ca:peer.ca,headers:['Host',new URL(peer.origin).host,'Origin',peer.origin,
          'Content-Type','application/x-www-form-urlencoded','Content-Length',String(Buffer.byteLength(body)),...extra]},res=>{
          const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{const text=Buffer.concat(chunks).toString('utf8');resolve({status:res.statusCode,body:text?JSON.parse(text):null});});
        });req.on('error',reject);req.end(body);
    });
  }
  return{...peer,calls,send,authCalls:()=>authCalls};
}
test('registration creates derive scope and fixed URLs; callers cannot supply authority or transport policy',async()=>{
  const f=await fixture();try{
    assert.equal((await f.send('create',fields,['X-Organization-ID','forged'])).status,200);
    const command=f.calls.find(([name])=>name==='apply')[1];
    assert.equal(command.organizationId,'org-one');assert.equal(command.actorId,'actor-one');assert.equal(command.expectedRegistrationVersion,null);
    assert.equal(command.definition.targetLinkUri,f.origin+`/lti/registrations/${reg}/resource`);assert.ok(Object.isFrozen(command));
    for(const extra of [{actor_id:'forged'},{organization_id:'forged'},{target_link_uri:'https://evil.invalid'},
      {allowed_private_addresses:'127.0.0.1'},{api_key:'private'}])assert.equal((await f.send('create',{...fields,...extra})).status,400);
  }finally{await f.close();}
});
test('reauthorization binds the same current tenant and actor before reads or writes',async()=>{
  for(const finalIdentity of [{organizationId:'org-one',actorId:'actor-one',authorized:false},
    {organizationId:'org-two',actorId:'actor-one',authorized:true},{organizationId:'org-one',actorId:'actor-two',authorized:true}]) {
    const f=await fixture({finalIdentity});try {
      assert.equal((await f.send('create',fields)).status,403);assert.equal(f.calls.filter(([name])=>name==='apply').length,0);
      assert.equal((await f.send('inspect')).status,403);
    }finally{await f.close();}
  }
});
test('exact original receipt replay precedes current platform and trust policy, with fresh authorization',async()=>{
  const original={operationId:op};
  const f=await fixture({canvasOrigin:'https://gateway.internal',replay:{conflict:false,receipt:original}});try{
    const response=await f.send('create',fields);assert.equal(response.status,200);assert.deepEqual(response.body,{receipt:original});
    assert.deepEqual(f.calls.map(([name])=>name),['replay']);assert.equal(f.authCalls(),2);
  }finally{await f.close();}
  const conflict=await fixture({replay:{conflict:true}});try{assert.equal((await conflict.send('create',fields)).status,409);}finally{await conflict.close();}
});
test('self-managed registration requires independent exact operator origin allowlist',async()=>{
  const self={...fields,trust_profile:'self_managed_same_origin'};delete self.environment;
  for(const [allowlist,expected] of [[[],409],[['https://canvas.custom.example'],200]]) {
    const f=await fixture({canvasOrigin:'https://canvas.custom.example',allowlist});try{assert.equal((await f.send('create',self)).status,expected);}finally{await f.close();}
  }
});
test('deactivation does not depend on current platform policy; activation checks matching snapshot',async()=>{
  const f=await fixture({canvasOrigin:'https://gateway.internal'});try{
    assert.equal((await f.send('deactivate',{operation_id:op,expected_registration_version:'1'})).status,200);
    assert.ok(!f.calls.some(([name])=>name==='platform'));
    assert.equal((await f.send('activate',{operation_id:op,expected_platform_version:'1',expected_registration_version:'1'})).status,409);
  }finally{await f.close();}
});
test('empty inspection/catalog forms work while ambiguous, malformed and overflowing inputs cannot write',async()=>{
  const f=await fixture();try{
    assert.equal((await f.send('inspect')).status,200);assert.equal((await f.send('catalog')).status,200);
    for(const value of ['operation_id='+op+'&operation_id='+op,'operation_id=%E0%A4%A',
      new URLSearchParams({...fields,expected_platform_version:'9007199254740992'}).toString()])assert.equal((await f.send('create',value)).status,400);
    assert.equal((await f.send('deactivate',{operation_id:op,expected_registration_version:'9007199254740991'})).status,400);
    assert.equal((await f.send('inspect',{},['Origin',f.origin])).status,403);
    assert.equal((await f.send('create',fields,['Content-Type','application/json'])).status,400);
    assert.equal(f.calls.filter(([name])=>name==='apply').length,0);
  }finally{await f.close();}
});
test('absent identity, missing permission and exhausted shared quota never reach storage',async()=>{
  for(const [options,status] of [[{identity:null},401],[{identity:{organizationId:'org-one',actorId:'actor-one',authorized:false}},403],[{quota:false},429]]) {
    const f=await fixture(options);try{assert.equal((await f.send('create',fields)).status,status);assert.equal(f.calls.length,0);}finally{await f.close();}
  }
});
