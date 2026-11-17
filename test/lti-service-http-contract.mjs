// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { request } from 'node:https';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';
import { ltiServiceReadScopes } from '../src/lti-service-contract.mjs';
import { createLtiToolKeyStore } from '../src/lti-tool-key-store.mjs';
import { createLtiServiceStore } from '../src/lti-service-store.mjs';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { httpsFixture,json } from './support/canvas-https-fixture.mjs';

export async function ltiServiceHttpContract(configuration,{pool,owner}) {
 const gateway=await httpsFixture(),canvas=await httpsFixture(),org='a50e8400-e29b-41d4-a716-446655440001';
 let permitted=true,organizationId=org,authReads=0,onAuth=()=>{},providerCalls=0;
 const runtimes=[];
 gateway.setHandler((req,res)=>{
  assert.equal(req.headers.cookie,'session=abcdefghijklmnop');assert.equal(req.headers.authorization,undefined);assert.equal(req.headers['x-api-key'],undefined);
  if(req.url==='/v1/auth/me'){authReads++;onAuth();return json(res,{authenticated:true,user:{user_id:'operator',organization_id:organizationId}});}
  if(req.url===`/v1/organizations/${organizationId}/members/me/permissions`)return json(res,{permissions:permitted?['integration-connector:edit']:[]});
  res.writeHead(404);res.end();
 });
 canvas.setHandler((req,res)=>{void(async()=>{
  providerCalls++;assert.equal(req.url,'/login/oauth2/token');assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
  let body='';for await(const chunk of req)body+=chunk;
  const form=new URLSearchParams(body);assert.equal(form.get('grant_type'),'client_credentials');
  json(res,{access_token:'synthetic_mounted_lti_service_token_00001',token_type:'Bearer',expires_in:3600,scope:ltiServiceReadScopes.results});
 })().catch(()=>res.destroy());});
 const configured={...configuration,gatewayAuthentication:{gatewayOrigin:gateway.origin,ca:gateway.ca,sessionCookieName:'session'},
  lti:{selfManagedOriginAllowlist:[canvas.origin],allowedPrivateAddresses:['127.0.0.1','::1'],ca:canvas.ca,timeoutMs:5000,services:true}};
 async function runtime(settings=configured){const value=await createConnectorOAuthRuntime(settings);runtimes.push(value);return value;}
 const send=(address,path,fields={},method='POST')=>new Promise((resolve,reject)=>{
  const body=method==='GET'?'':new URLSearchParams(fields).toString();
  const req=request({hostname:'localhost',port:address.port,path,method,ca:configuration.http.tls.cert,agent:false,
   headers:{Host:'localhost',Origin:'https://localhost',Cookie:'session=abcdefghijklmnop','Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}},res=>{
   let text='';res.on('data',chunk=>text+=chunk);res.on('end',()=>{
    for(const privateValue of ['PRIVATE KEY','privateKeyPem','ciphertext','wrappingKeyId','dispatchId','synthetic_mounted_lti_service_token_00001'])assert.equal(text.includes(privateValue),false);
    resolve({status:res.statusCode,headers:res.headers,body:text,value:text?JSON.parse(text):null});
   });res.on('error',reject);
  });req.on('error',reject);req.end(body);
 });
 try {
  owner("UPDATE canvas_connector.oauth_http_limit SET hits=0,window_started_at=clock_timestamp()-interval '1 second';");
  const disabled=await runtime({...configured,lti:{...configured.lti,services:false}}),disabledAddress=await disabled.listen();
  assert.equal((await send(disabledAddress,`/lti/registrations/${randomUUID()}/jwks`,{},'GET')).status,404);await disabled.close();
  const missing=await runtime();await assert.rejects(missing.listen(),/connector_oauth_runtime_unavailable/);await missing.close();
  owner('GRANT canvas_lti_services TO canvas_oauth_http;');
  const capturesConfigured={...configured,lti:{...configured.lti,captures:true}};
  const missingCaptures=await runtime(capturesConfigured);await assert.rejects(missingCaptures.listen(),/connector_oauth_runtime_unavailable/);await missingCaptures.close();
  owner('GRANT canvas_lti_capture_admin TO canvas_oauth_http;');
  const capturesLive=await runtime(capturesConfigured),capturesAddress=await capturesLive.listen();
  assert.equal((await send(capturesAddress,`/platforms/absent/lti/registrations/${randomUUID()}/capture-routes/catalog`)).status,200);
  await capturesLive.close();
  const live=await runtime(),address=await live.listen(),platformId='mounted-lti-platform',registrationId=randomUUID();
  assert.equal((await send(address,`/platforms/absent/lti/registrations/${randomUUID()}/capture-routes/catalog`)).status,404);
  owner(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES('${org}','${platformId}','${canvas.origin}',true);
   INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
   VALUES('${registrationId}','${org}','${platformId}','mounted-client','deployment','self_managed_same_origin','https://localhost/lti/registrations/${registrationId}/resource',true);`);
  const base=`/platforms/${platformId}/lti/registrations/${registrationId}`,key=base+'/tool-key/',credentials=base+'/service-credentials/';
  const input={operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1'};
  permitted=false;assert.equal((await send(address,key+'provision',input)).status,403);permitted=true;
  assert.equal((await send(address,key+'provision',{...input,organization_id:org})).status,400);
  authReads=0;onAuth=()=>{if(authReads===3)permitted=false;};
  assert.equal((await send(address,key+'provision',input)).status,403);
  assert.equal((await pool.query('SELECT count(*)::float8 AS count FROM canvas_connector.lti_tool_keys WHERE organization_id=$1',[org])).rows[0].count,0,'revocation after Bao and before commit prevents key publication');
  permitted=true;authReads=0;onAuth=()=>{if(authReads===4)permitted=false;};
  assert.equal((await send(address,key+'provision',input)).status,403,'post-commit permission loss returns no private result');
  permitted=true;onAuth=()=>{};
  const receipt=(await send(address,key+'receipt',{operation_id:input.operation_id})).value.receipt;assert.equal(receipt.version,1);
  assert.equal((await send(address,key+'provision',input)).value.receipt.kid,receipt.kid,'same original operation reconciles after post-commit permission loss');
  const inspected=await send(address,key+'inspect');assert.equal(inspected.value.publicJwksUrl,`https://localhost/lti/registrations/${registrationId}/jwks`);
  const authBefore=authReads;permitted=false;
  const publicKeys=await send(address,`/lti/registrations/${registrationId}/jwks`,{},'GET');assert.equal(publicKeys.status,200);
  assert.equal(authReads,authBefore,'public JWK discovery never authenticates or forwards a session');assert.equal(publicKeys.value.keys[0].kid,receipt.kid);
  assert.deepEqual(Object.keys(publicKeys.value.keys[0]).sort(),['alg','e','kid','kty','n','use']);permitted=true;
  organizationId='b50e8400-e29b-41d4-a716-446655440001';assert.equal((await send(address,key+'inspect')).value.key,null);organizationId=org;
  const exchange={operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1',expected_key_version:'1',scopes:JSON.stringify([ltiServiceReadScopes.results])};
  const minted=await send(address,credentials+'exchange',exchange);assert.equal(minted.status,200);assert.equal(minted.value.attempt.phase,'published');assert.equal(providerCalls,1);
  assert.equal((await send(address,credentials+'exchange',exchange)).value.attempt.phase,'published');assert.equal(providerCalls,1);
  assert.equal((await send(address,credentials+'receipt',{operation_id:exchange.operation_id})).value.receipt.operationId,exchange.operation_id);
  const unrelated=`/platforms/other/lti/registrations/${registrationId}/service-credentials/`;
  assert.equal((await send(address,unrelated+'recover',{attempt_id:exchange.operation_id})).value.attempt,null);
  assert.equal((await send(address,credentials+'inspect',{attempt_id:exchange.operation_id})).value.attempt.attemptId,exchange.operation_id);
  assert.equal((await send(address,credentials+'catalog')).value.attempts[0].attemptId,exchange.operation_id);
  const stagedRegistration=randomUUID();
  owner(`INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
   VALUES('${stagedRegistration}','${org}','${platformId}','staged-client','staged-deployment','self_managed_same_origin','https://localhost/lti/registrations/${stagedRegistration}/resource',true);`);
  const keyProvider=createOpenBaoKeyProvider(configuration.keyCustody),toolKeys=createLtiToolKeyStore({pool,keyProvider}),tokens=createLtiServiceStore({pool,keyProvider});
  await toolKeys.administer({organizationId:org,platformId,registrationId:stagedRegistration,operationId:randomUUID(),actorId:'operator',action:'provision',
   expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null});
  const pending=await tokens.prepare({organizationId:org,platformId,registrationId:stagedRegistration,operationId:randomUUID(),actorId:'operator',
   expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1,scopes:[ltiServiceReadScopes.results]});
  const begun=await tokens.begin({organizationId:org,operationId:pending.operationId,dispatchId:randomUUID()});
  await tokens.stage(begun,{accessToken:'synthetic_mounted_staged_token_00002',scopes:begun.scopes},(begun.issuedAt+3600)*1000);
  const stagedPath=`/platforms/${platformId}/lti/registrations/${stagedRegistration}/service-credentials/`;
  authReads=0;onAuth=()=>{if(authReads===4)permitted=false;};
  assert.equal((await send(address,stagedPath+'recover',{attempt_id:begun.operationId})).status,403);
  permitted=true;onAuth=()=>{};
  assert.equal((await send(address,stagedPath+'receipt',{operation_id:begun.operationId})).value.receipt.operationId,begun.operationId);
  assert.equal((await send(address,stagedPath+'recover',{attempt_id:begun.operationId})).value.attempt.phase,'published');assert.equal(providerCalls,1);
  const secondRegistration=randomUUID();
  owner(`INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
   VALUES('${secondRegistration}','${org}','${platformId}','second-client','second-deployment','self_managed_same_origin','https://localhost/lti/registrations/${secondRegistration}/resource',true);`);
  const second=`/platforms/${platformId}/lti/registrations/${secondRegistration}`;
  assert.equal((await send(address,second+'/tool-key/provision',{...input,operation_id:randomUUID()})).status,200);
  authReads=0;onAuth=()=>{if(authReads===5)permitted=false;};
  const denied={...exchange,operation_id:randomUUID()};
  assert.equal((await send(address,second+'/service-credentials/exchange',denied)).status,403);assert.equal(providerCalls,1,'TLS-time Gateway revocation prevents a Canvas credential request');
  permitted=true;onAuth=()=>{};
  const unknown=(await send(address,second+'/service-credentials/inspect',{attempt_id:denied.operation_id})).value.attempt;
  assert.equal(unknown.phase,'uncertain');assert.equal((await send(address,second+'/service-credentials/exchange',denied)).value.attempt.phase,'uncertain');assert.equal(providerCalls,1);
  assert.equal((await send(address,second+'/tool-key/deactivate',{operation_id:randomUUID(),expected_key_version:'1'})).status,200);
  assert.equal((await send(address,second+'/deactivate',{operation_id:randomUUID(),expected_registration_version:'1'})).status,200);
  assert.equal((await send(address,`/platforms/${platformId}/configuration/change`,{operation_id:randomUUID(),expected_version:'1',enabled:'false',archived:'false'})).status,200);
  const resolution={attempt_id:denied.operation_id,operation_id:randomUUID(),action:'resolve_unknown',expected_phase:'uncertain',
   expected_platform_version:'2',expected_registration_version:'2',expected_key_version:'2',confirmation_reference:randomUUID()};
  const resolved=await send(address,second+'/service-credentials/resolve',resolution);assert.equal(resolved.status,200);
  assert.equal(resolved.value.receipt.providerDisposition,'operator_attested_external_disposition');
  assert.deepEqual((await send(address,second+'/service-credentials/resolution-receipt',{attempt_id:denied.operation_id,operation_id:resolution.operation_id})).value.receipt,resolved.value.receipt);
  assert.equal((await send(address,second+'/service-credentials/recover',{attempt_id:denied.operation_id})).value.attempt.phase,'resolved');assert.equal(providerCalls,1);
  console.log('Actual Gateway -> mounted restricted-role LTI admin/JWK/credential/recovery paths: tenant projection, Bao/precommit/postcommit/TLS authority changes and original-operation no-resend PASS');
 } finally {
  onAuth=()=>{};permitted=true;
  await Promise.allSettled(runtimes.map(value=>value.close()));await gateway.close();await canvas.close();
  owner("UPDATE canvas_connector.oauth_http_limit SET hits=0,window_started_at=clock_timestamp();");
 }
}
