// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayBindingReader} from '../src/gateway-binding-reader.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const org='20000000-0000-4000-8000-000000000001',admin='https://connector.example.test';
const session={authenticated:true,user:{user_id:'operator-one',organization_id:org}};
const snapshot={found:true,record:{id:'binding-one'},snapshot_at_ms:1794844800000};
const path=`/v1/organizations/${org}/external-observation-bindings/binding-one/inspect`;
const operation={platformId:'platform',bindingId:'binding-one'};
const incoming=()=>({rawHeaders:['Origin',admin,'Cookie','session=synthetic-session-token; private=never-forward',
  'Authorization','Bearer never-forward','X-Organization-ID','forged','X-API-Key','never-forward']});
const options=fixture=>({gatewayOrigin:fixture.origin,adminOrigin:admin,sessionCookieName:'session',ca:fixture.ca,timeoutMs:500});
const reply=(res,value=snapshot)=>json(res,value,200,{'Cache-Control':'no-store'});
function setup(fixture,handle) {
  fixture.setHandler((req,res)=>{
    if(req.url==='/v1/auth/me') return json(res,session);
    if(req.url.endsWith('/members/me/permissions')) return json(res,{permissions:['integration-connector:edit']});
    return handle(req,res);
  });
}
test('binding reader derives tenant from fresh Gateway sessions and sends only the exact public POST',async()=>{
  const fixture=await httpsFixture();
  try {
    let body;setup(fixture,async(req,res)=>{body='';for await(const chunk of req) body+=chunk;reply(res);});
    const reader=createGatewayBindingReader(options(fixture));
    assert.deepEqual(await reader(incoming(),operation),{organizationId:org,actorId:'operator-one',snapshot});
    assert.equal(body,'{}');assert.equal(fixture.seen.length,5);
    const post=fixture.seen[2];assert.equal(post.url,path);assert.equal(post.method,'POST');assert.equal(post.headers.origin,admin);
    for(const seen of fixture.seen) {
      assert.equal(seen.headers.cookie,'session=synthetic-session-token');
      for(const name of ['authorization','x-api-key','x-organization-id','x-user-id']) assert.equal(seen.headers[name],undefined);
    }
    await reader(incoming(),operation);assert.equal(fixture.seen.length,10,'no permission or snapshot cache');
  } finally {await fixture.close();}
});
test('session tenant/actor or exact permission changes discard the binding snapshot',async()=>{
  const fixture=await httpsFixture();
  try {
    for(const change of ['tenant','actor','permission']) {
      let sessions=0,permissions=0;
      fixture.setHandler((req,res)=>{
        if(req.url==='/v1/auth/me') {sessions++;return json(res,sessions===1?session:{...session,user:{...session.user,
          ...(change==='tenant'?{organization_id:'20000000-0000-4000-8000-000000000002'}:{}),...(change==='actor'?{user_id:'other'}:{})}});}
        if(req.url.endsWith('/members/me/permissions')) {permissions++;return json(res,{permissions:permissions===2 && change==='permission'?[]:['integration-connector:edit']});}
        reply(res);
      });
      assert.equal(await createGatewayBindingReader(options(fixture))(incoming(),operation),null);
      assert.deepEqual(fixture.seen.filter(item=>item.method==='POST').map(item=>item.url),[path]);
    }
  } finally {await fixture.close();}
});
test('missing session, duplicate cookie, forbidden origin and caller authority fields never cause a binding lookup',async()=>{
  const fixture=await httpsFixture();
  try {
    setup(fixture,(_req,res)=>reply(res));const reader=createGatewayBindingReader(options(fixture));
    for(const request of [{rawHeaders:[]},{rawHeaders:['Origin',admin,'Cookie','session=one; session=two']},
      {rawHeaders:['Origin','https://evil.test','Cookie','session=synthetic-session-token']}]) assert.equal(await reader(request,operation),null);
    for(const value of [{...operation,organizationId:org},{...operation,apiKey:'never'}, {...operation,bindingId:'../binding'},
      {...operation,url:'https://other.test'}]) await assert.rejects(reader(incoming(),value),{message:'gateway_binding_read_unavailable'});
    assert.equal(fixture.seen.length,0);
  } finally {await fixture.close();}
});
test('Core permission denial and explicit absent snapshot remain distinct from transport failure',async()=>{
  const fixture=await httpsFixture();
  try {
    const reader=createGatewayBindingReader(options(fixture));
    for(const status of [401,403]) {setup(fixture,(_req,res)=>{res.writeHead(status);res.end();});assert.equal(await reader(incoming(),operation),null);}
    const absent={found:false,record:null,snapshot_at_ms:1794844800000};setup(fixture,(_req,res)=>reply(res,absent));
    assert.deepEqual((await reader(incoming(),operation)).snapshot,absent);
    setup(fixture,(_req,res)=>{res.writeHead(503);res.end();});await assert.rejects(reader(incoming(),operation),{message:'gateway_binding_read_unavailable'});
  } finally {await fixture.close();}
});
test('redirects, ambiguous JSON, malformed snapshots, absent no-store, oversized content and encoding fail closed',async()=>{
  const fixture=await httpsFixture();
  try {
    const reader=createGatewayBindingReader(options(fixture));
    for(const handle of [
      (_req,res)=>{res.writeHead(302,{Location:'https://other.test'});res.end();},
      (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"found":true,"found":false,"record":null,"snapshot_at_ms":1}');},
      (_req,res)=>reply(res,{found:true,record:[],snapshot_at_ms:1}),
      (_req,res)=>reply(res,{...snapshot,record:{id:'different-binding'}}),
      (_req,res)=>reply(res,{found:false,record:null,snapshot_at_ms:9007199254740992}),
      (_req,res)=>json(res,snapshot),
      (_req,res)=>reply(res,{...snapshot,extra:'x'.repeat(131073)}),
      (_req,res)=>json(res,snapshot,200,{'Cache-Control':'no-store','Content-Encoding':'gzip'}),
    ]) {setup(fixture,handle);await assert.rejects(reader(incoming(),operation),{message:'gateway_binding_read_unavailable'});assert.equal(fixture.seen.length,3);}
  } finally {await fixture.close();}
});
test('TLS failure and a stalled binding response do not become missing configuration',async()=>{
  const fixture=await httpsFixture();
  try {
    setup(fixture,()=>{});
    await assert.rejects(createGatewayBindingReader(options(fixture))(incoming(),operation),{message:'gateway_binding_read_unavailable'});
    await assert.rejects(createGatewayBindingReader({...options(fixture),ca:undefined})(incoming(),operation),{message:'gateway_binding_read_unavailable'});
  } finally {await fixture.close();}
});
