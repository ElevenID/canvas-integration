// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { generateKeyPairSync,randomUUID,sign } from 'node:crypto';
import { json } from './support/canvas-https-fixture.mjs';

export async function ltiRuntimeHttpContract({owner,pool,send,server,address,peer,org,origin}) {
  const registrationId=randomUUID(),base=`/lti/registrations/${registrationId}`;
  const admin=`/platforms/lti-runtime-platform/lti/registrations/${registrationId}/`;
  const post=async(action,fields)=>{
    const response=await send(address,{path:admin+action,body:new URLSearchParams(fields).toString()}).response;
    assert.equal(response.status,200);return JSON.parse(response.body);
  };
  owner(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES('${org}','lti-runtime-platform','${peer.origin}',true);`);
  const created=await post('create',{operation_id:randomUUID(),expected_platform_version:'1',client_id:'lti-runtime-client',
    deployment_id:'lti-runtime-deployment',trust_profile:'self_managed_same_origin'});
  assert.equal(created.receipt.enabled,false);
  const login=base+'/login?'+new URLSearchParams({iss:peer.origin,login_hint:'opaque'});
  assert.equal((await send(address,{path:login,method:'GET'}).response).status,403);
  const activate={operation_id:randomUUID(),expected_platform_version:'1',expected_registration_version:'1'};
  const activated=await post('activate',activate);assert.equal(activated.receipt.version,2);
  const started=await send(address,{path:login,method:'GET'}).response;assert.equal(started.status,200);
  const plan=JSON.parse(/\)\((\{.*\})\);<\/script>/.exec(started.body)[1]);
  const authorize=new URL(plan.authorizationUrl),state=authorize.searchParams.get('state'),nonce=authorize.searchParams.get('nonce');
  assert.equal(authorize.origin,peer.origin);assert.equal(authorize.pathname,'/api/lti/authorize_redirect');
  const cookie=started.headers['set-cookie'][0].split(';')[0];
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'runtime-synthetic-key',alg:'RS256',use:'sig'};
  peer.setHandler((req,res)=>{
    assert.equal(req.url,'/api/lti/security/jwks');
    assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
    return json(res,{keys:[jwk]});
  });
  const claim='https://purl.imsglobal.org/spec/lti/claim/';
  const now=Math.floor(Date.now()/1000),payload={iss:peer.origin,aud:'lti-runtime-client',sub:'synthetic-provider-subject',nonce,iat:now-1,exp:now+120,
    [claim+'deployment_id']:'lti-runtime-deployment',[claim+'message_type']:'LtiResourceLinkRequest',[claim+'version']:'1.3.0',
    [claim+'target_link_uri']:origin+base+'/resource',[claim+'resource_link']:{id:'synthetic-resource'},[claim+'roles']:[]};
  const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
  const input=encode({alg:'RS256',typ:'JWT',kid:jwk.kid})+'.'+encode(payload);
  const token=input+'.'+sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url');
  const callback=()=>send(address,{path:base+'/launch',cookie,requestOrigin:peer.origin,
    body:new URLSearchParams({state,id_token:token}).toString()}).response;
  const accepted=await callback();assert.equal(accepted.status,303);assert.equal(accepted.headers.location,base+'/resource?state='+state);
  // The public bridge intentionally does not expose a canonical learner identity.
  const active=await send(address,{path:accepted.headers.location,method:'GET',cookie}).response;
  assert.equal(active.status,200);assert.ok(!active.body.includes(payload.sub));assert.ok(!active.body.includes(token));
  assert.equal((await callback()).status,303);
  owner("UPDATE canvas_connector.platforms SET enabled=false WHERE id='lti-runtime-platform';");
  assert.equal((await callback()).status,303);
  assert.equal((await send(address,{path:accepted.headers.location,method:'GET',cookie}).response).status,403);
  const replay=await post('activate',activate);assert.deepEqual(replay,activated);
  assert.equal((await post('deactivate',{operation_id:randomUUID(),expected_registration_version:'2'})).receipt.enabled,false);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM canvas_connector.lti_launch_receipts WHERE receipt->>\'registrationId\'=$1',[registrationId])).rows[0].n,1);
  await server.close();
  console.log('Actual runtime/CLI verified-TLS PostgreSQL role + Gateway administration + pinned Canvas JWKS/JWT + browser-proof receipt/current resource passed; replay survives closure without learner authority');
}
