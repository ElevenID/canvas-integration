// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createPostgresRepository} from '../src/postgres-repository.mjs';
import {createEncryptedVault} from '../src/encrypted-vault.mjs';
import {createOAuthAttemptRecoveryStore} from '../src/oauth-attempt-recovery.mjs';
import {createRevocationWorker} from '../src/revocation-worker.mjs';
import {createCanvasOAuthProvider} from '../src/canvas-oauth-provider.mjs';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';

export async function oauthAttemptRecoveryContract(pool,options={}) {
  const query=(sql,values=[])=>pool.query(sql,values), owner=options.ownerQuery??query;
  const keyProvider=options.keyProvider??{current:async()=>({id:'recovery-test-key',key:Buffer.alloc(32,51)}),byId:async()=>Buffer.alloc(32,51)};
  const repo=createPostgresRepository(pool),vault=createEncryptedVault({pool,keyProvider}),store=createOAuthAttemptRecoveryStore(pool);
  const canvas=await httpsFixture();let revoked=0,serial=0;
  canvas.setHandler((req,res)=>{
    assert.equal(req.method,'DELETE');assert.equal(req.url,'/login/oauth2/token');
    assert.equal(req.headers.authorization,'Bearer synthetic-recovery-access');
    assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-api-key'],undefined);revoked++;json(res,{});
  });
  async function fixture(phase='staged') {
    const organizationId='recovery-contract-'+(++serial),platformId='platform';
    await query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES($1,$2,$3,true)',[organizationId,platformId,canvas.origin]);
    const clientSecretRef=await vault.put(organizationId,{platformId,provider:'canvas',purpose:'oauth_client_secret'},'synthetic-recovery-client');
    const authorizationId=createHash('sha256').update(organizationId).digest('hex'),now=Date.now();
    const a={organizationId,platformId,authorizationId,stateHash:authorizationId,browserBindingHash:'c'.repeat(64),
      platformConfigVersion:1,canvasOrigin:canvas.origin,clientId:'client',clientSecretRef,capabilities:['catalog'],scopes:['read'],
      redirectUri:'https://connector.example.test/oauth/callback',createdAt:now,expiresAt:now+600000};
    await repo.saveAuthorization(a);await repo.markAuthorizationPending(organizationId,platformId,1,authorizationId);
    await repo.consumeAuthorizationAttempt(authorizationId,a.browserBindingHash);
    if(phase!=='consumed') await repo.beginAuthorizationExchange(authorizationId,organizationId,platformId);
    if(phase==='staged' || phase==='published') await vault.stageAuthorizationResult(a,{accessToken:'synthetic-recovery-access',refreshToken:'synthetic-recovery-refresh'},null);
    if(phase==='published') await repo.publishAuthorizationConnection(authorizationId,organizationId,platformId);
    if(phase==='unknown') await repo.requireAuthorizationReconciliation(authorizationId,organizationId,platformId);
    return a;
  }
  const mutation=(a,snapshot,action)=>({...a,expectedRevision:snapshot.revision,operationId:randomUUID(),actorId:'current-operator',action});
  try {
    {
      const a=await fixture('consumed'),snapshot=await store.inspect(a);
      assert.equal(snapshot.phase,'consumed');assert.equal(snapshot.revision,1);
      assert.equal(await store.inspect({...a,organizationId:'foreign'}),null);
      assert.equal(await store.inspect({...a,platformId:'foreign'}),null);
      assert.equal(await store.recover(mutation(a,snapshot,'queue_staged_revocation')),null);
      const input=mutation(a,snapshot,'abandon_unstarted'),receipt=await store.recover(input);
      assert.equal(receipt.phase,'abandoned');assert.equal(receipt.revision,2);
      assert.deepEqual(await store.recover(input),receipt);
      assert.deepEqual(await store.receipt(input),receipt);
      assert.equal(await store.recover({...input,actorId:'other-operator'}),null);
      assert.equal(await store.recover({...input,action:'finish_staged_revocation'}),null);
      assert.equal(await store.receipt({...input,platformId:'foreign'}),null);
      assert.equal(await repo.beginAuthorizationExchange(a.authorizationId,a.organizationId,a.platformId),false);
      await assert.rejects(query('UPDATE canvas_connector.authorization_recovery_audit SET actor_id=$2 WHERE organization_id=$1',[a.organizationId,'forged']));
      await assert.rejects(query('DELETE FROM canvas_connector.authorization_recovery_audit WHERE organization_id=$1',[a.organizationId]));
    }
    {
      const a=await fixture(),snapshot=await store.inspect(a);
      await query('UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1',[a.organizationId]);
      const input=mutation(a,snapshot,'queue_staged_revocation');
      let lost=false;
      const uncertain=createOAuthAttemptRecoveryStore({async query(sql,values){
        const result=await query(sql,values);
        if(!lost && sql.includes('recover_authorization_attempt')) {lost=true;throw Error('synthetic lost recovery reply');}
        return result;
      }});
      await assert.rejects(uncertain.recover(input),/connector_recovery_unavailable/);
      const receipt=await store.receipt(input);assert.equal(receipt.phase,'reconciliation_required');assert.ok(receipt.revocationJobId);
      assert.deepEqual(await store.recover(input),receipt);
      let pending=await store.inspect(a);assert.equal(pending.revision,snapshot.revision+1);assert.equal(pending.audit.length,1);
      assert.equal(await repo.publishAuthorizationConnection(a.authorizationId,a.organizationId,a.platformId),false);
      assert.equal(await store.recover(mutation(a,pending,'finish_staged_revocation')),null);
      const worker=createRevocationWorker({repository:repo,secretVault:vault,provider:createCanvasOAuthProvider({ca:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1']})});
      assert.equal(await worker.runOnce(),'completed');assert.equal(revoked,1);
      pending=await store.inspect(a);assert.equal(pending.revocationConfirmed,true);assert.equal(pending.cleanupCompleted,true);
      const finished=await store.recover(mutation(a,pending,'finish_staged_revocation'));
      assert.equal(finished.phase,'abandoned');assert.equal((await store.inspect(a)).audit.length,2);
      assert.equal((await query('SELECT (count(*)=1) AS ok FROM canvas_connector.secrets WHERE organization_id=$1',[a.organizationId])).rows[0].ok,true);
    }
    for(const phase of ['exchanging','unknown','published']) {
      const a=await fixture(phase),snapshot=await store.inspect(a);
      for(const action of ['abandon_unstarted','queue_staged_revocation','finish_staged_revocation'])
        assert.equal(await store.recover(mutation(a,snapshot,action)),null);
      assert.equal((await store.inspect(a)).phase,snapshot.phase);
    }
    {
      const a=await fixture('consumed'),snapshot=await store.inspect(a);
      const winners=await Promise.all(Array.from({length:8},()=>store.recover(mutation(a,snapshot,'abandon_unstarted'))));
      assert.equal(winners.filter(Boolean).length,1);assert.equal((await store.inspect(a)).audit.length,1);
    }
    // Audit failure must roll back both the disposition and queued revocation.
    for(const phase of ['consumed','staged']) {
      const a=await fixture(phase),snapshot=await store.inspect(a);
      await owner(`CREATE FUNCTION canvas_connector.synthetic_recovery_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.organization_id='${a.organizationId}' THEN RAISE EXCEPTION 'synthetic audit unavailable'; END IF; RETURN NEW; END $$`);
      await owner('CREATE TRIGGER synthetic_recovery_audit_failure BEFORE INSERT ON canvas_connector.authorization_recovery_audit FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_recovery_audit_failure()');
      try {await assert.rejects(store.recover(mutation(a,snapshot,phase==='consumed'?'abandon_unstarted':'queue_staged_revocation')),/connector_recovery_unavailable/);}
      finally {await owner('DROP TRIGGER synthetic_recovery_audit_failure ON canvas_connector.authorization_recovery_audit');await owner('DROP FUNCTION canvas_connector.synthetic_recovery_audit_failure()');}
      assert.equal((await store.inspect(a)).revision,snapshot.revision);assert.equal((await store.inspect(a)).phase,phase);
      assert.equal((await query('SELECT (count(*)=0) AS ok FROM canvas_connector.revocation_jobs WHERE organization_id=$1',[a.organizationId])).rows[0].ok,true);
    }
  } finally {await canvas.close();}
  console.log('Actual PostgreSQL operator recovery CAS/audit/unknown replies/rollback and concrete HTTPS revocation, secret cleanup and final disposition contracts passed');
}
