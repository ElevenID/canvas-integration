// SPDX-License-Identifier: AGPL-3.0-only
// Disposable PostgreSQL plus concrete verified HTTPS Canvas exchange. Wrappers
// discard replies after real commits; they do not emulate database outcomes.
import assert from 'node:assert/strict';
import { createCanvasOAuthLifecycle } from '../src/canvas-oauth.mjs';
import { createCanvasOAuthProvider } from '../src/canvas-oauth-provider.mjs';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

export async function initialOAuthLifecycleContract(pool,options={}) {
  const keyProvider=options.keyProvider??{current:async()=>({id:'synthetic-lifecycle-key',key:Buffer.alloc(32,49)}),byId:async()=>Buffer.alloc(32,49)};
  const query=(sql,values=[])=>pool.query(sql,values);
  const durable=createPostgresRepository(pool), vault=createEncryptedVault({pool,keyProvider});
  const canvas=await httpsFixture();
  const ACCESS='synthetic-lifecycle-access-token', REFRESH='synthetic-lifecycle-refresh-token';
  const CLIENT='synthetic-lifecycle-client-secret', BROWSER=Buffer.alloc(32,19).toString('base64url');
  const markers={consume:'FROM canvas_connector.consume_authorization_attempt(',begin:'SELECT canvas_connector.begin_authorization_exchange(',
    stage:'FROM canvas_connector.stage_authorization_result(',publish:'SELECT canvas_connector.publish_authorization_connection('};
  let requests=0, mode, org;
  canvas.setHandler(async(req,res)=>{
    assert.equal(req.url,'/login/oauth2/token');assert.equal(req.method,'POST');
    assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);
    const chunks=[];for await(const chunk of req) chunks.push(chunk);
    const form=new URLSearchParams(Buffer.concat(chunks).toString());
    assert.equal(form.get('code'),'synthetic-lifecycle-code');assert.equal(form.get('client_secret'),CLIENT);
    requests++;
    if(mode==='provider') {res.destroy();return;}
    if(mode==='drift') await query('UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1',[org]);
    json(res,{access_token:ACCESS,refresh_token:REFRESH,expires_in:3600,token_type:'Bearer'});
  });
  try {
    let serial=0;
    for(mode of ['healthy','consume','begin','stage','publish','stage-before','publish-before','provider','drift']) {
      org='initial-lifecycle-'+(++serial);
      await query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ($1,$2,$3,true)',[org,'platform',canvas.origin]);
      const clientRef=await vault.put(org,{platformId:'platform',provider:'canvas',purpose:'oauth_client_secret'},CLIENT);
      const fault=mode.split('-')[0],before=mode.endsWith('-before');let fired=false;
      const uncertainPool={async query(sql,values) {
        const discard=!fired && markers[fault] && sql.includes(markers[fault]);
        if(discard && before) {fired=true;throw Error('synthetic unavailable database before write');}
        const result=await query(sql,values);
        if(discard) {fired=true;throw Error('synthetic committed but reply lost');}
        return result;
      }};
      const lifecycle=createCanvasOAuthLifecycle({publicOrigin:'https://connector.example.test',completionUrl:'https://connector.example.test/complete',
        repository:createPostgresRepository(uncertainPool),secretVault:createEncryptedVault({pool:uncertainPool,keyProvider}),
        provider:createCanvasOAuthProvider({ca:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:2000})});
      const start=await lifecycle.start({organizationId:org,platformId:'platform',clientId:'client',clientSecretRef:clientRef,
        capabilities:['catalog'],browserBinding:BROWSER});
      const state=new URL(start.authorizationUrl).searchParams.get('state');
      const previous=requests;
      const result=await lifecycle.callback({state,code:'synthetic-lifecycle-code',browserBinding:BROWSER});
      const location=new URL(result.location);
      assert.doesNotMatch(location.href,/synthetic|access_token|refresh_token|client_secret/);
      const attempt=(await query('SELECT phase FROM canvas_connector.authorization_attempts WHERE organization_id=$1',[org])).rows[0];
      const early=['consume','begin'].includes(mode);
      assert.equal(requests-previous,early?0:1);
      assert.equal(attempt.phase,mode==='consume'?'consumed':['healthy','publish'].includes(mode)?'published':'reconciliation_required');
      const committed=['healthy','publish'].includes(mode);
      const connection=await durable.connection(org,'platform');assert.equal(Boolean(connection),committed);
      const hasTokens=!early && !['stage-before','provider'].includes(mode);
      assert.equal((await query('SELECT (count(*)=$2) AS ok FROM canvas_connector.secrets WHERE organization_id=$1',[org,hasTokens?3:1])).rows[0].ok,true);
      if(hasTokens) {
        const refs=(await query('SELECT access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef" FROM canvas_connector.authorization_attempts WHERE organization_id=$1',[org])).rows[0];
        assert.equal(await vault.get(org,refs.accessTokenRef,{platformId:'platform',provider:'canvas',purpose:'oauth_access_token'}),ACCESS);
        assert.equal(await vault.get(org,refs.refreshTokenRef,{platformId:'platform',provider:'canvas',purpose:'oauth_refresh_token'}),REFRESH);
      }
      if(mode==='healthy') assert.equal(location.searchParams.get('outcome'),'connected');
      else assert.match(location.searchParams.get('error_code'),/^oauth_(connection_reconciliation_required|authorization_conflict|token_exchange_failed)$/);
      const replay=await lifecycle.callback({state,code:'synthetic-lifecycle-code',browserBinding:BROWSER});
      assert.equal(new URL(replay.location).searchParams.get('error_code'),'oauth_state_invalid');
      assert.equal(requests-previous,early?0:1,'callback replay must never repeat the concrete provider exchange');
    }
  } finally {await canvas.close();}
  console.log('Actual HTTPS Canvas callback/PG/encrypted vault lost consumption, begin, staging and publication replies, provider uncertainty, drift and no-repeat contracts passed');
}
