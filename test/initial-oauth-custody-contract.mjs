// SPDX-License-Identifier: AGPL-3.0-only
// Invoked only by disposable real PostgreSQL contracts. No configured database.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createPostgresRepository } from '../src/postgres-repository.mjs';
import { createEncryptedVault } from '../src/encrypted-vault.mjs';

export async function initialOAuthCustodyContract(pool,options={}) {
  const query=(sql,values=[])=>pool.query(sql,values);
  const owner=options.ownerQuery??query;
  const repo=createPostgresRepository(pool);
  const keyProvider=options.keyProvider??{current:async()=>({id:'synthetic-initial-key',key:Buffer.alloc(32,41)}),byId:async()=>Buffer.alloc(32,41)};
  const vault=createEncryptedVault({pool,keyProvider});
  const bundle={accessToken:'synthetic-initial-access-token',refreshToken:'synthetic-initial-refresh-token'};
  let serial=0;
  async function fixture() {
    const org='initial-custody-'+(++serial), platform='platform';
    const authorizationId=createHash('sha256').update(org).digest('hex');
    await query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES ($1,$2,$3,true)',[org,platform,'https://canvas.example.test']);
    const ref=await vault.put(org,{platformId:platform,provider:'canvas',purpose:'oauth_client_secret'},'synthetic-client-secret');
    const now=Date.now();
    const authorization={authorizationId,stateHash:authorizationId,browserBindingHash:'b'.repeat(64),
      organizationId:org,platformId:platform,platformConfigVersion:1,canvasOrigin:'https://canvas.example.test',
      clientId:'client',clientSecretRef:ref,capabilities:['catalog'],scopes:['read'],
      redirectUri:'https://connector.example.test/oauth/callback',createdAt:now,expiresAt:now+600000};
    assert.equal(await repo.saveAuthorization(authorization),true);
    assert.equal(await repo.markAuthorizationPending(org,platform,1,authorizationId),true);
    return authorization;
  }
  const consume=a=>repo.consumeAuthorizationAttempt(a.authorizationId,a.browserBindingHash);
  const begin=a=>repo.beginAuthorizationExchange(a.authorizationId,a.organizationId,a.platformId);
  const publish=a=>repo.publishAuthorizationConnection(a.authorizationId,a.organizationId,a.platformId);
  const snapshot=a=>repo.authorizationAttempt(a.authorizationId,a.organizationId,a.platformId);
  async function countSecrets(a,n) {
    assert.equal((await query('SELECT (count(*)=$2) AS ok FROM canvas_connector.secrets WHERE organization_id=$1',[a.organizationId,n])).rows[0].ok,true);
  }
  // Browser binding is atomic with durable consumption; a lost acknowledgment
  // cannot cause the authorization code to become available for another call.
  {
    const a=await fixture();
    assert.equal(await repo.consumeAuthorizationAttempt(a.authorizationId,'c'.repeat(64)),null);
    assert.equal(await snapshot(a),null);
    const uncertain=createPostgresRepository({async query(sql,values){
      const result=await query(sql,values);
      if(sql.includes('FROM canvas_connector.consume_authorization_attempt')) throw Error('synthetic lost consume reply');
      return result;
    }});
    await assert.rejects(uncertain.consumeAuthorizationAttempt(a.authorizationId,a.browserBindingHash),/connector_database_unavailable/);
    assert.equal((await snapshot(a)).phase,'consumed');
    assert.equal(await consume(a),null);
    assert.equal(await begin({...a,organizationId:'foreign'}),false);
    const winners=await Promise.all(Array.from({length:8},()=>begin(a)));
    assert.equal(winners.filter(Boolean).length,1);
    assert.equal(await begin(a),false);
  }
  for(const withRefresh of [true,false]) {
    const a=await fixture();await consume(a);assert.equal(await begin(a),true);
    const refs=await vault.stageAuthorizationResult(a,withRefresh?bundle:{accessToken:bundle.accessToken},null);
    assert.equal(await vault.get(a.organizationId,refs.accessTokenRef,{platformId:a.platformId,provider:'canvas',purpose:'oauth_access_token'}),bundle.accessToken);
    if(withRefresh) assert.equal(await vault.get(a.organizationId,refs.refreshTokenRef,{platformId:a.platformId,provider:'canvas',purpose:'oauth_refresh_token'}),bundle.refreshToken);
    assert.equal((await snapshot(a)).phase,'staged');
    assert.equal(await publish(a),true);
    assert.equal((await snapshot(a)).phase,'published');
    assert.equal(await publish(a),false);
    await countSecrets(a,withRefresh?3:2);
  }
  {
    const a=await fixture();
    const winners=await Promise.all(Array.from({length:8},()=>consume(a)));
    assert.equal(winners.filter(Boolean).length,1);
    assert.equal((await snapshot(a)).phase,'consumed');
  }
  // Storage acknowledgment loss leaves ciphertext and its exact references in
  // one recoverable record; conflicting re-staging never creates more secrets.
  {
    const a=await fixture();await consume(a);await begin(a);
    let exact;
    const uncertain=createEncryptedVault({keyProvider,pool:{async query(sql,values){
      const result=await query(sql,values);
      if(sql.includes('FROM canvas_connector.stage_authorization_result')) {exact=values;throw Error('synthetic lost stage reply');}
      return result;
    }}});
    await assert.rejects(uncertain.stageAuthorizationResult(a,bundle,Date.now()+600000),/connector_vault_unavailable/);
    const staged=await snapshot(a);assert.equal(staged.phase,'staged');
    assert.equal(staged.accessTokenRef,exact[3]);assert.equal(staged.refreshTokenRef,exact[8]);
    assert.equal(await vault.get(a.organizationId,staged.accessTokenRef),bundle.accessToken);
    assert.equal((await query(`SELECT authorization_hash FROM canvas_connector.stage_authorization_result(
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,to_timestamp($14::float8/1000))`,exact)).rows.length,1);
    await assert.rejects(vault.stageAuthorizationResult(a,bundle,Date.now()+600000),/connector_vault_unavailable/);
    await countSecrets(a,3);
    const unknownPublish=createPostgresRepository({async query(sql,values){
      const result=await query(sql,values);
      if(sql.includes('publish_authorization_connection')) throw Error('synthetic lost publish reply');
      return result;
    }});
    await assert.rejects(unknownPublish.publishAuthorizationConnection(a.authorizationId,a.organizationId,a.platformId),/connector_database_unavailable/);
    assert.equal((await snapshot(a)).phase,'published');
    assert.equal((await repo.connection(a.organizationId,a.platformId)).accessTokenRef,staged.accessTokenRef);
    await countSecrets(a,3);
  }
  // The second insert failing must roll back the first ciphertext and refs.
  {
    const a=await fixture();await consume(a);await begin(a);
    await owner(`CREATE FUNCTION canvas_connector.synthetic_initial_failure() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.organization_id='${a.organizationId}' AND NEW.purpose='oauth_refresh_token' THEN
        RAISE EXCEPTION 'synthetic second insert failure'; END IF; RETURN NEW; END $$`);
    await owner('CREATE TRIGGER synthetic_initial_failure BEFORE INSERT ON canvas_connector.secrets FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_initial_failure()');
    try {await assert.rejects(vault.stageAuthorizationResult(a,bundle,null),/connector_vault_unavailable/);}
    finally {await owner('DROP TRIGGER synthetic_initial_failure ON canvas_connector.secrets');await owner('DROP FUNCTION canvas_connector.synthetic_initial_failure()');}
    await countSecrets(a,1);assert.equal((await snapshot(a)).phase,'exchanging');
    assert.equal((await query('SELECT (access_token_ref IS NULL) AS ok FROM canvas_connector.authorization_attempts WHERE authorization_hash=$1',[a.authorizationId])).rows[0].ok,true);
  }
  // Publication fences never discard custody after a provider may have issued
  // tokens. These cases intentionally remain for explicit operator recovery.
  for(const scenario of ['disabled','revision','expired-token','revoked-client','reconciliation','new-pending']) {
    const a=await fixture();await consume(a);await begin(a);
    if(scenario==='disabled') await query('UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1',[a.organizationId]);
    if(scenario==='revision') await query('UPDATE canvas_connector.platforms SET canvas_origin=$2 WHERE organization_id=$1',[a.organizationId,'https://new-canvas.example.test']);
    if(scenario==='reconciliation') assert.equal(await repo.requireAuthorizationReconciliation(a.authorizationId,a.organizationId,a.platformId),true);
    if(scenario==='new-pending') await query('UPDATE canvas_connector.oauth_status SET authorization_hash=$2 WHERE organization_id=$1',[a.organizationId,'f'.repeat(64)]);
    // Publication uses the database clock; avoid assuming the fixture VM and
    // host clocks agree closely enough for a one-second negative deadline.
    const expiry=scenario==='expired-token'?(await query("SELECT floor(extract(epoch FROM clock_timestamp()-interval '1 second')*1000)::float8 AS expired")).rows[0].expired:null;
    const refs=await vault.stageAuthorizationResult(a,bundle,expiry);
    if(scenario==='revoked-client') await query('UPDATE canvas_connector.secrets SET enabled=false WHERE organization_id=$1 AND reference=$2',[a.organizationId,a.clientSecretRef]);
    assert.equal(await publish(a),false);
    assert.equal(await vault.get(a.organizationId,refs.accessTokenRef),bundle.accessToken);
    await countSecrets(a,3);
    assert.equal(await repo.connection(a.organizationId,a.platformId),null);
  }
  // Tenant isolation, current configuration, deadline and pending authorization
  // are checked before exchange can begin; two unknown exchanges cannot overlap.
  for(const scenario of ['revision','expired','pending','connection','active']) {
    const a=await fixture();await consume(a);
    if(scenario==='revision') await query('UPDATE canvas_connector.platforms SET enabled=true WHERE organization_id=$1',[a.organizationId]);
    if(scenario==='expired') await query("UPDATE canvas_connector.authorization_attempts SET authorization_expires_at=clock_timestamp()-interval '1 second' WHERE authorization_hash=$1",[a.authorizationId]);
    if(scenario==='pending') await query('UPDATE canvas_connector.oauth_status SET authorization_hash=$2 WHERE organization_id=$1',[a.organizationId,'f'.repeat(64)]);
    if(scenario==='connection') await repo.publishConnection({...a,accessTokenRef:'synthetic-existing-ref',refreshTokenRef:null,tokenExpiresAt:null},1);
    if(scenario==='active') {
      await begin(a);assert.equal(await repo.requireAuthorizationReconciliation(a.authorizationId,a.organizationId,a.platformId),true);
      const second={...a,authorizationId:'a'.repeat(64),stateHash:'a'.repeat(64)};
      await repo.saveAuthorization(second);await repo.markAuthorizationPending(a.organizationId,a.platformId,1,second.stateHash);
      await consume(second);assert.equal(await begin(second),false);continue;
    }
    assert.equal(await begin(a),false);await countSecrets(a,1);
  }
  {
    const a=await fixture();await consume(a);await begin(a);
    await assert.rejects(vault.stageAuthorizationResult({...a,organizationId:'foreign'},bundle,null),/connector_vault_unavailable/);
    await assert.rejects(vault.stageAuthorizationResult(a,{...bundle,refreshToken:''},null),/connector_vault_unavailable/);
    const unavailable=createEncryptedVault({pool,keyProvider:{...keyProvider,current:async()=>{throw Error('synthetic no key');}}});
    await assert.rejects(unavailable.stageAuthorizationResult(a,bundle,null),/connector_vault_unavailable/);
    await countSecrets(a,1);
  }
  // Final fences must run after locks/triggers, rolling back writes if time
  // elapsed inside the statement. A pre-write check alone cannot prove this.
  for(const transition of ['begin','publish']) {
    const a=await fixture();await consume(a);
    if(transition==='publish') {
      await begin(a);await vault.stageAuthorizationResult(a,bundle,null);
    }
    const expiry=transition==='begin'?'authorization_expires_at':'token_expires_at';
    await owner(`CREATE FUNCTION canvas_connector.synthetic_initial_delay() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.authorization_hash='${a.authorizationId}' AND NEW.phase='${transition==='begin'?'exchanging':'published'}' THEN
        PERFORM pg_sleep(greatest(0,extract(epoch FROM OLD.${expiry}-clock_timestamp()))+0.1);
        END IF; RETURN NEW; END $$`);
    await owner('CREATE TRIGGER synthetic_initial_delay BEFORE UPDATE ON canvas_connector.authorization_attempts FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_initial_delay()');
    try {
      await query(`UPDATE canvas_connector.authorization_attempts SET ${expiry}=clock_timestamp()+interval '3 seconds' WHERE authorization_hash=$1`,[a.authorizationId]);
      await assert.rejects(transition==='begin'?begin(a):publish(a),/connector_database_unavailable/);
    } finally {await owner('DROP TRIGGER synthetic_initial_delay ON canvas_connector.authorization_attempts');await owner('DROP FUNCTION canvas_connector.synthetic_initial_delay()');}
    assert.equal((await snapshot(a)).phase,transition==='begin'?'consumed':'staged');
    assert.equal(await repo.connection(a.organizationId,a.platformId),null);
  }
  console.log('Actual PostgreSQL initial OAuth attempt consumption, atomic ciphertext staging, lost acknowledgments, rollback and publication fences passed');
}
