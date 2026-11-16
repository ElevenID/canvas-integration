// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createLtiToolKeyStore } from '../src/lti-tool-key-store.mjs';
import { createLtiServiceStore } from '../src/lti-service-store.mjs';
import { createLtiServiceLifecycle } from '../src/lti-service-lifecycle.mjs';
import { ltiServiceReadScopes } from '../src/lti-service-contract.mjs';
import { httpsFixture,json } from './support/canvas-https-fixture.mjs';

export async function ltiServiceLifecycleContract(pool,{keyProvider,ownerQuery}) {
 const peer=await httpsFixture(),organizationId='lti-lifecycle-org',scope=ltiServiceReadScopes.results;
 try {
  let requests=0,mode='success',current;
  peer.setHandler((req,res)=>{void(async()=>{
   requests++;assert.equal(req.url,'/login/oauth2/token');assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
   let body='';for await(const chunk of req)body+=chunk;
   const form=new URLSearchParams(body),claims=JSON.parse(Buffer.from(form.get('client_assertion').split('.')[1],'base64url'));
   assert.equal(claims.jti,current.operationId);assert.equal(claims.aud,peer.origin+'/login/oauth2/token');assert.equal(form.get('scope'),scope);
   if(mode==='unknown')return res.destroy();
   if(mode==='drift')await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${organizationId}' AND id='${current.platformId}';`);
   json(res,{access_token:'synthetic_canvas_lifecycle_token_00001',token_type:'Bearer',expires_in:3600,scope});
  })().catch(()=>res.destroy());});
  const toolKeyStore=createLtiToolKeyStore({pool,keyProvider});
  async function setup() {
   const platformId='platform-'+randomUUID(),registrationId=randomUUID();
   await ownerQuery(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES('${organizationId}','${platformId}','${peer.origin}',true);
    INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
    VALUES('${registrationId}','${organizationId}','${platformId}','client','deployment','hosted_global','production',
     'https://tool.example.test/lti/registrations/${registrationId}/resource',true);`);
   await toolKeyStore.administer({organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',action:'provision',
    expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null});
   return {organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',
    expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1,scopes:[scope]};
  }
  const policy={ca:peer.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:5000,maxResponseBytes:4096};
  const store=createLtiServiceStore({pool,keyProvider}),lifecycle=createLtiServiceLifecycle({store,toolKeyStore,canvasPolicy:policy});
  current=await setup();
  await Promise.all(Array.from({length:4},()=>lifecycle.exchange(current)));
  const published=await lifecycle.recover({organizationId,operationId:current.operationId});
  assert.equal(published.phase,'published');assert.equal(requests,1);
  assert.equal((await store.currentToken({organizationId,operationId:current.operationId})).accessToken,'synthetic_canvas_lifecycle_token_00001');
  await lifecycle.exchange(current);assert.equal(requests,1);
  current=await setup();mode='unknown';
  assert.equal((await lifecycle.exchange(current)).phase,'uncertain');const before=requests;
  assert.equal((await lifecycle.exchange(current)).phase,'uncertain');assert.equal(requests,before);
  assert.equal(await lifecycle.exchange({...current,operationId:randomUUID()}),null);
  current=await setup();mode='success';
  const dropped=new Set();
  const lossyStore=createLtiServiceStore({keyProvider,pool:{async query(sql,values){
   const result=await pool.query(sql,values);
   for(const name of ['stage_lti_service_token','publish_lti_service_token'])
    if(sql.includes('SELECT canvas_connector.'+name)&&!dropped.has(name)){dropped.add(name);throw Error('synthetic lost committed reply');}
   return result;
  }}});
  const lossy=createLtiServiceLifecycle({store:lossyStore,toolKeyStore,canvasPolicy:policy}),start=requests;
  assert.equal((await lossy.exchange(current)).phase,'published');assert.equal(dropped.size,2);assert.equal(requests,start+1);
  await lossy.exchange(current);assert.equal(requests,start+1);
  current=await setup();let denied=false;
  const fencedStore=createLtiServiceStore({keyProvider,pool:{async query(sql,values){
   if(sql.includes("AND phase='exchanging'")&&!denied){denied=true;await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false
    WHERE organization_id='${organizationId}' AND id='${current.platformId}';`);}
   return pool.query(sql,values);
  }}});
  const fenced=createLtiServiceLifecycle({store:fencedStore,toolKeyStore,canvasPolicy:policy}),noSend=requests;
  assert.equal((await fenced.exchange(current)).phase,'uncertain');assert.equal(denied,true);assert.equal(requests,noSend,'final TLS-time durable fence denies credential transmission');
  current=await setup();mode='drift';
  const drifted=await lifecycle.exchange(current);assert.equal(drifted.phase,'staged');assert.notEqual(drifted.tokenReference,null);
  const driftRequests=requests;assert.equal((await lifecycle.exchange(current)).phase,'staged');assert.equal(requests,driftRequests);
  assert.equal(await store.currentToken({organizationId,operationId:current.operationId}),null);
  console.log('Actual Canvas TLS -> original durable LTI attempt -> encrypted token publication; concurrency/unknown provider/lost stage+publish replies/TLS-time drift fences PASS');
 } finally {await peer.close();}
}
