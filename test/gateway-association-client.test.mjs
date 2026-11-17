// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayAssociationClient} from '../src/gateway-association-client.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
const CH='10000000-0000-4000-8000-00000000000a',GRANT='20000000-0000-4000-8000-000000000001';
const OP='30000000-0000-4000-8000-000000000001',KEY='synthetic_gateway_association_key_00000001';
const config=gateway=>({gatewayOrigin:gateway.origin,sourceId:'canvas-source',sourceGrantId:GRANT,apiKey:KEY,ca:gateway.ca});
const command=()=>({challengeId:CH,bindingId:'binding-one',action:'create',body:{operation_id:OP,expected_source_revision:4,
 expected_binding_revision:2,provider_reference:'b'.repeat(64),provider_revision:3,code_hash:'a'.repeat(64),expires_at_ms:Date.now()+120000}});
const stored=()=>({operation_id:OP,challenge_id:CH,action:'create',revision:1,phase:'pending'});
const inspect=()=>({challengeId:CH,bindingId:'binding-one',action:'inspect',body:{}});
const lookup=()=>({challengeId:CH,bindingId:'binding-one',action:'receipt',body:{operation_id:OP},expectedReceipt:{action:'create',revision:1}});
const row=()=>({challenge_id:CH,source_id:'canvas-source',binding_id:'binding-one',revision:2,phase:'confirmed',current:true,expired:true,
 expires_at_ms:Date.now()-1000,application_id:null,subject_id:null,identity:null,can_relink:false});
async function peer(run) {const gateway=await httpsFixture();try{await run(gateway);}finally{await gateway.close();}}
function handler(gateway,run) {gateway.setHandler(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);
 req.testBody=JSON.parse(Buffer.concat(chunks).toString('utf8'));await run(req,res);});}
const reply=(res,value)=>json(res,value,200,{'Cache-Control':'no-store'});

test('producer sends only its fixed public Gateway key and exact source/binding intent',()=>peer(async gateway=>{
 const seen=[];handler(gateway,(req,res)=>{seen.push(req.testBody);reply(res,stored());});
 const client=createGatewayAssociationClient(config(gateway)),input=command();
 assert.deepEqual(await client.execute(input),stored());assert.equal(gateway.seen.length,1);
 assert.equal(gateway.seen[0].url,`/v1/identity/association-challenges/${CH}/create`);
 assert.deepEqual(seen,[{...input.body,challenge_id:CH,source_grant_id:GRANT,binding_id:'binding-one'}]);
 assert.equal(gateway.seen[0].headers['x-api-key'],KEY);
 for(const name of ['cookie','authorization','x-user-id','x-api-key-id','x-organization-id'])assert.equal(gateway.seen[0].headers[name],undefined);
 assert.equal(Object.hasOwn(client,'apiKey'),false);
}));

test('caller authority, provider secrets, getters and receipt expectation overrides fail before dispatch',()=>peer(async gateway=>{
 const client=createGatewayAssociationClient(config(gateway));
 const input=command();
 for(const field of ['organization_id','user_id','application_id','challenge_id','source_grant_id','binding_id','access_token','client_secret','code'])
  await assert.rejects(client.execute({...input,body:{...input.body,[field]:'forged'}}),{code:'invalid_request'});
 for(const value of [{...input,headers:{Authorization:'Bearer provider-token'}},{...input,challengeId:CH.toUpperCase()},
  {...input,bindingId:'../binding'},{...input,body:{...input.body,code_hash:'g'.repeat(64)}},
  {...lookup(),expectedReceipt:undefined},{...lookup(),expectedReceipt:{action:'confirm',revision:2}},
  {...lookup(),expectedReceipt:{action:'create',revision:2}}])await assert.rejects(client.execute(value),{code:'invalid_request'});
 let reads=0;const body={...input.body};Object.defineProperty(body,'code_hash',{get(){reads++;return 'a'.repeat(64);},enumerable:true});
 await assert.rejects(client.execute({...input,body}),{code:'invalid_request'});assert.equal(reads,0);assert.equal(gateway.seen.length,0);
}));

test('lost committed create recovers only its original receipt with no automatic write retry',()=>peer(async gateway=>{
 let commits=0;const bodies=[];
 handler(gateway,(req,res)=>{bodies.push(req.testBody);if(req.url.endsWith('/create')){commits++;req.socket.destroy();return;}reply(res,{kind:'receipt',receipt:stored()});});
 const client=createGatewayAssociationClient(config(gateway));
 await assert.rejects(client.execute(command()),{code:'association_commit_unknown'});
 assert.deepEqual(await client.execute(lookup()),{kind:'receipt',receipt:stored()});assert.equal(commits,1);assert.equal(gateway.seen.length,2);
 assert.deepEqual(bodies[1],{operation_id:OP},'local action/revision expectations never enter the request');
 handler(gateway,(_req,res)=>reply(res,{kind:'receipt',receipt:{...stored(),revision:2}}));
 await assert.rejects(client.execute(lookup()),{code:'invalid_response'});
}));

test('current reads require matching immutable pointers and never accept Core learner data or receipt history',()=>peer(async gateway=>{
 const current=row();handler(gateway,(_req,res)=>reply(res,{kind:'current',record:current}));
 const client=createGatewayAssociationClient(config(gateway));
 const result=await client.execute(inspect());assert.deepEqual(result.record,current);assert.ok(Object.isFrozen(result.record));
 for(const bad of [{...current,binding_id:'another-binding'},{...current,source_id:'another-source'},
  {...current,application_id:'private-app'},{...current,subject_id:'private-subject'},{...current,identity:{identity_id:OP}},
  {...current,can_relink:true},{...current,phase:'denied',current:true}]) {
  handler(gateway,(_req,res)=>reply(res,{kind:'current',record:bad}));
  await assert.rejects(client.execute(inspect()),{code:'invalid_response'});
 }
 handler(gateway,(_req,res)=>reply(res,{kind:'receipt',receipt:stored()}));
 await assert.rejects(client.execute(inspect()),{code:'invalid_response'});
}));

test('mutation intent and local receipt expectations are snapshotted before asynchronous transport',()=>peer(async gateway=>{
 const bodies=[];handler(gateway,(req,res)=>{bodies.push(req.testBody);reply(res,stored());});
 const client=createGatewayAssociationClient(config(gateway)),input=command(),expected={...input.body};
 const pending=client.execute(input);input.body.operation_id=GRANT;input.body.code_hash='f'.repeat(64);input.bindingId='changed';
 assert.deepEqual(await pending,stored());assert.deepEqual(bodies[0],{...expected,challenge_id:CH,source_grant_id:GRANT,binding_id:'binding-one'});
 handler(gateway,(_req,res)=>reply(res,{kind:'receipt',receipt:stored()}));
 const recovery=lookup(),read=client.execute(recovery);recovery.expectedReceipt.action='expire';recovery.body.operation_id=GRANT;
 assert.deepEqual(await read,{kind:'receipt',receipt:stored()});
}));

test('redirects, upstream errors, malformed JSON and wrong write receipts remain uncertain and private',()=>peer(async gateway=>{
 const client=createGatewayAssociationClient(config(gateway));
 for(const run of [
  (_req,res)=>{res.writeHead(302,{Location:'https://canvas.example/credentials'});res.end();},
  (_req,res)=>{res.writeHead(403);res.end('private-upstream-detail');},
  (_req,res)=>reply(res,{...stored(),challenge_id:GRANT}),
  (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"revision":1,"revision":2}');},
  (_req,res)=>json(res,stored()),
 ]) {
  handler(gateway,run);await assert.rejects(client.execute(command()),error=>{
   assert.equal(error.code,'association_commit_unknown');assert.ok(!error.message.includes('private-upstream-detail'));return true;
  });assert.equal(gateway.seen.length,1);
 }
}));

test('response framing, trailers, size, UTF-8 and an absolute deadline fail closed without retries',()=>peer(async gateway=>{
 const client=createGatewayAssociationClient({...config(gateway),timeoutMs:1000});
 for(const run of [
  (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(Buffer.from([0xc3,0x28]));},
  (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(' '.repeat(8193));},
  (_req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','Trailer':'x-user-id'});res.addTrailers({'x-user-id':'private'});res.end('{}');},
 ]) {
  handler(gateway,run);await assert.rejects(client.execute(inspect()),{code:'invalid_response'});assert.equal(gateway.seen.length,1);
 }
 handler(gateway,()=>{});
 await assert.rejects(createGatewayAssociationClient({...config(gateway),timeoutMs:500}).execute(command()),{code:'association_commit_unknown'});
 assert.equal(gateway.seen.length,1);
}));

test('abandon and expiry preserve original operation and terminal receipt correlation',()=>peer(async gateway=>{
 const client=createGatewayAssociationClient(config(gateway));
 for(const [action,phase] of [['abandon','abandoned'],['expire','expired']]) {
  const terminal={operation_id:OP,challenge_id:CH,action,revision:2,phase},bodies=[];
  handler(gateway,(req,res)=>{bodies.push(req.testBody);reply(res,req.url.endsWith('/receipt')?{kind:'receipt',receipt:terminal}:terminal);});
  assert.deepEqual(await client.execute({challengeId:CH,bindingId:'binding-one',action,body:{operation_id:OP,expected_revision:1}}),terminal);
  assert.deepEqual(await client.execute({...lookup(),expectedReceipt:{action,revision:2}}),{kind:'receipt',receipt:terminal});
  assert.deepEqual(bodies,[{operation_id:OP,expected_revision:1},{operation_id:OP}]);
 }
}));

test('caller cancellation after dispatch leaves a mutation uncertain and never retries', {timeout:10000},()=>peer(async gateway=>{
 let ready;const dispatched=new Promise(resolve=>{ready=resolve;});
 handler(gateway,()=>{ready();});
 const client=createGatewayAssociationClient(config(gateway)),controller=new AbortController();
 const pending=client.execute({...command(),signal:controller.signal});await dispatched;controller.abort();
 await assert.rejects(pending,{code:'association_commit_unknown'});assert.equal(gateway.seen.length,1);
 const before=AbortSignal.abort();await assert.rejects(client.execute({...command(),signal:before}),{code:'invalid_request'});
 assert.equal(gateway.seen.length,1);
}));

test('TLS verification and fixed configuration cannot be replaced by caller transports or private Core targets',()=>peer(async gateway=>{
 handler(gateway,(_req,res)=>reply(res,stored()));
 for(const bad of [{...config(gateway),gatewayOrigin:'http://gateway.example'},
  {...config(gateway),gatewayOrigin:'https://issuance-native.internal'},
  {...config(gateway),gatewayOrigin:'https://gateway.example/private'},
  {...config(gateway),gatewayOrigin:'https://user:secret@gateway.example'},
  {...config(gateway),transport:()=>{}},{...config(gateway),organizationId:OP}])
  assert.throws(()=>createGatewayAssociationClient(bad),{code:'invalid_configuration'});
 await assert.rejects(createGatewayAssociationClient({...config(gateway),ca:undefined}).execute(command()),{code:'association_commit_unknown'});
 assert.equal(gateway.seen.length,0);
}));
