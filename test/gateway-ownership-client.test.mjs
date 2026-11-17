// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayOwnershipClient} from '../src/gateway-ownership-client.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const ORG='10000000-0000-4000-8000-000000000001',OTHER='10000000-0000-4000-8000-000000000002';
const OP='20000000-0000-4000-8000-000000000001',ADMIN='https://connector.example';
const COOKIE='sessionId=synthetic_session_token_000000001';
const incoming=(extra=[])=>({rawHeaders:['Origin',ADMIN,'Cookie',COOKIE+'; unrelated=not-forwarded',...extra]});
const inspect=()=>({applicationId:'app-one',action:'inspect',body:{}});
const command=()=>({applicationId:'app-one',action:'propose',body:{operation_id:OP,expected_revision:0,expected_application_revision:123,user_id:'learner-one'}});
const stored=()=>({operation_id:OP,application_id:'app-one',action:'propose',revision:1,status:'proposed'});
const lookup=()=>({applicationId:'app-one',action:'receipt',body:{operation_id:OP},expectedReceipt:{action:'propose',revision:1}});
const config=gateway=>({gatewayOrigin:gateway.origin,adminOrigin:ADMIN,sessionCookieName:'sessionId',ca:gateway.ca});
async function peer(run) {
 const gateway=await httpsFixture();
 try {await run(gateway);}finally{await gateway.close();}
}
function handler(gateway,{post=(_req,res)=>json(res,{kind:'current',record:null},200,{'Cache-Control':'no-store'}),session}={}) {
 let reads=0;
 gateway.setHandler(async(req,res)=>{
  if(req.url==='/v1/auth/me') {
   reads++;return json(res,session?.(reads)??{authenticated:true,user:{user_id:'actor-one',organization_id:ORG}});
  }
  const chunks=[];for await(const chunk of req)chunks.push(chunk);
  req.testBody=JSON.parse(Buffer.concat(chunks).toString('utf8'));return post(req,res);
 });
}
test('public Gateway derives session tenant and receives only its selected cookie and bounded command',()=>peer(async gateway=>{
 const bodies=[];
 handler(gateway,{post:(req,res)=>{bodies.push(req.testBody);json(res,stored(),200,{'Cache-Control':'no-store'});}});
 const result=await createGatewayOwnershipClient(config(gateway)).execute(incoming(['X-User-ID','forged','X-Organization-ID',OTHER]),command());
 assert.equal(result.organizationId,ORG);assert.equal(result.actorId,'actor-one');assert.deepEqual(result.result,stored());
 assert.deepEqual(bodies,[command().body]);assert.equal(gateway.seen.length,3);
 assert.equal(gateway.seen[1].url,`/v1/organizations/${ORG}/application-ownerships/app-one/propose`);
 for(const request of gateway.seen) {
  assert.equal(request.headers.cookie,COOKIE);assert.equal(request.headers['x-api-key'],undefined);
  assert.equal(request.headers.authorization,undefined);assert.equal(request.headers['x-user-id'],undefined);
  assert.equal(request.headers['x-organization-id'],undefined);assert.ok(!JSON.stringify(request).includes('not-forwarded'));
 }
}));
test('invalid identity, credential and body overrides fail before any Gateway connection',()=>peer(async gateway=>{
 handler(gateway);const client=createGatewayOwnershipClient(config(gateway));
 for(const bad of [incoming(['Authorization','Bearer synthetic_canvas_token']),incoming(['X-API-Key','synthetic_org_api_key']),
  incoming(['Origin',ADMIN]),incoming(['Cookie',COOKIE]),{rawHeaders:['Origin',ADMIN,'Cookie','sessionId=short']}])
  await assert.rejects(client.execute(bad,inspect()),{code:'session_required'});
 for(const value of [{...inspect(),organizationId:OTHER},{...inspect(),applicationId:'../app'},
  {...command(),body:{...command().body,actor_id:'actor-one'}},
  {...command(),body:{...command().body,canvas_credentials:'synthetic-secret'}},
  {...command(),body:{...command().body,expected_revision:Number.MAX_SAFE_INTEGER}},
  {...lookup(),expectedReceipt:undefined}])await assert.rejects(client.execute(incoming(),value),{code:'invalid_request'});
 assert.equal(gateway.seen.length,0);
}));
test('lost committed reply reconciles original receipt without another mutation or metadata leakage',()=>peer(async gateway=>{
 let commits=0;const requests=[];
 handler(gateway,{post:(req,res)=>{
  requests.push({path:req.url,body:req.testBody});
  if(req.url.endsWith('/propose')){commits++;req.socket.destroy();return;}
  json(res,{kind:'receipt',receipt:stored()},200,{'Cache-Control':'no-store'});
 }});
 const client=createGatewayOwnershipClient(config(gateway));
 await assert.rejects(client.execute(incoming(),command()),{code:'ownership_commit_unknown'});
 const result=await client.execute(incoming(),lookup());
 assert.equal(commits,1);assert.deepEqual(result.result,{kind:'receipt',receipt:stored()});
 assert.deepEqual(requests[1].body,{operation_id:OP});assert.equal(requests.length,2);
 assert.equal(result.result.kind,'receipt','historical receipt never becomes current ownership');
}));
test('final canonical actor or tenant changes retain uncertain mutation outcome',()=>peer(async gateway=>{
 for(const session of [n=>({authenticated:true,user:{user_id:n===1?'actor-one':'actor-two',organization_id:ORG}}),
  n=>({authenticated:true,user:{user_id:'actor-one',organization_id:n===1?ORG:OTHER}})]) {
  let writes=0;handler(gateway,{session,post:(_req,res)=>{writes++;json(res,stored(),200,{'Cache-Control':'no-store'});}});
  await assert.rejects(createGatewayOwnershipClient(config(gateway)).execute(incoming(),command()),{code:'ownership_commit_unknown'});
  assert.equal(writes,1);
 }
}));
test('wrong well-formed receipt and current/history substitutions fail closed',()=>peer(async gateway=>{
 const client=createGatewayOwnershipClient(config(gateway));
 for(const change of [{revision:999},{action:'confirm',status:'confirmed'},{application_id:'another-app'},
  {operation_id:'20000000-0000-4000-8000-000000000002'}]) {
  handler(gateway,{post:(_req,res)=>json(res,{...stored(),...change},200,{'Cache-Control':'no-store'})});
  await assert.rejects(client.execute(incoming(),command()),{code:'ownership_commit_unknown'});
  handler(gateway,{post:(_req,res)=>json(res,{kind:'receipt',receipt:{...stored(),...change}},200,{'Cache-Control':'no-store'})});
  await assert.rejects(client.execute(incoming(),lookup()),{code:'invalid_response'});
 }
 handler(gateway,{post:(_req,res)=>json(res,{kind:'receipt',receipt:stored()},200,{'Cache-Control':'no-store'})});
 await assert.rejects(client.execute(incoming(),inspect()),{code:'invalid_response'});
}));
test('redirect, duplicate JSON, permission loss and missing no-store never trigger a write retry',()=>peer(async gateway=>{
 const client=createGatewayOwnershipClient(config(gateway));
 for(const post of [(_req,res)=>{res.writeHead(307,{Location:'https://private.internal/escape'});res.end();},
  (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(stored()).replace('"revision":1','"revision":1,"revision":2'));},
  (_req,res)=>json(res,{error:'secret-upstream-detail'},403),(_req,res)=>json(res,stored())]) {
  handler(gateway,{post});await assert.rejects(client.execute(incoming(),command()),error=>{
   assert.equal(error.code,'ownership_commit_unknown');assert.ok(!error.message.includes('secret-upstream-detail'));return true;
  });assert.equal(gateway.seen.filter(req=>req.method==='POST').length,1);
 }
}));
test('tenant intent is a precondition and a single absolute deadline cancels the composed operation',()=>peer(async gateway=>{
 handler(gateway);const client=createGatewayOwnershipClient({...config(gateway),timeoutMs:50});
 await assert.rejects(client.execute(incoming(['X-Connector-Organization-Intent',OTHER]),inspect()),{code:'session_required'});
 assert.equal(gateway.seen.filter(req=>req.method==='POST').length,0);
 handler(gateway,{post:(_req,_res)=>{}});
 await assert.rejects(client.execute(incoming(),command()),{code:'ownership_commit_unknown'});
 assert.equal(gateway.seen.filter(req=>req.method==='POST').length,1);
}));
test('current projection stays bounded and does not accept a historical or stale confirmation as current',()=>peer(async gateway=>{
 const row={application_id:'app-one',user_id:'learner-one',revision:2,status:'confirmed',application_revision:123,proposal_application_revision:123,current:true};
 handler(gateway,{post:(_req,res)=>json(res,{kind:'current',record:row},200,{'Cache-Control':'no-store'})});
 const client=createGatewayOwnershipClient(config(gateway)),result=await client.execute(incoming(),inspect());
 assert.deepEqual(result.result.record,row);assert.ok(Object.isFrozen(result.result.record));
 handler(gateway,{post:(_req,res)=>json(res,{kind:'current',record:{...row,proposal_application_revision:122}},200,{'Cache-Control':'no-store'})});
 await assert.rejects(client.execute(incoming(),inspect()),{code:'invalid_response'});
}));
