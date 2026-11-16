// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createEncryptedVault} from '../src/encrypted-vault.mjs';
import {createOAuthClientStore} from '../src/oauth-client-admin.mjs';
import {createPostgresRepository} from '../src/postgres-repository.mjs';
export async function oauthClientProvisioningContract(pool,{keyProvider,ownerQuery}={}) {
  const query=(sql,values=[])=>pool.query(sql,values),owner=ownerQuery??query;
  let rotated=false;
  const keys={current:async()=>rotated?{id:'canvas-key-two',key:await keyProvider.byId('canvas-key-two')}:keyProvider.current(),byId:id=>keyProvider.byId(id)};
  const vault=createEncryptedVault({pool,keyProvider:keys}),store=createOAuthClientStore(pool,vault),repo=createPostgresRepository(pool);
  const org='client-provision-'+randomUUID(),platform='platform',scope={organizationId:org,platformId:platform};
  const secret='synthetic_雪_oauth_client_secret_0001';
  const metadata={platformId:platform,provider:'canvas',purpose:'oauth_client_secret'};
  const add=async id=>query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES($1,$2,$3,true)',[org,id,'https://canvas.example.test']);
  await add(platform);
  const input={...scope,operationId:randomUUID(),actorId:'operator',expectedVersion:1,clientId:'client'};
  const first=await store.provision(input,secret);assert.equal(first.configVersion,2);
  assert.equal(await vault.get(org,first.clientSecretRef,metadata),secret);
  const saved=(await query('SELECT ciphertext,key_id FROM canvas_connector.secrets WHERE organization_id=$1 AND reference=$2',[org,first.clientSecretRef])).rows[0];
  assert.equal(saved.ciphertext.includes(Buffer.from(secret)),false);assert.equal(saved.key_id,'canvas-key-one');
  const audit=(await query('SELECT input_digest,receipt FROM canvas_connector.oauth_client_provisioning_audit WHERE organization_id=$1 AND operation_id=$2',[org,input.operationId])).rows[0];
  assert.equal(audit.input_digest.length,32);assert.notDeepEqual(audit.input_digest,createHash('sha256').update(secret).digest());
  assert.equal(JSON.stringify(audit.receipt).includes(secret),false);
  assert.deepEqual(await store.provision(input,secret),first);
  assert.equal(await store.provision(input,secret+'-different'),null);
  assert.equal(await store.provision({...input,clientId:'other-client'},secret),null);
  assert.equal(await store.provision({...input,actorId:'other'},secret),null);
  assert.equal(await store.receipt({...input,organizationId:'foreign'}),null);
  await assert.rejects(vault.get('foreign',first.clientSecretRef,metadata));
  assert.equal(await repo.configuredClient(org,platform,1),null);
  assert.deepEqual(await repo.configuredClient(org,platform,2),{clientId:'client',clientSecretRef:first.clientSecretRef});
  rotated=true;
  assert.deepEqual(await store.provision(input,secret),first);
  const secondInput={...input,operationId:randomUUID(),expectedVersion:2},second=await store.provision(secondInput,secret+'-rotated');
  assert.equal(second.configVersion,3);
  assert.equal((await query('SELECT key_id FROM canvas_connector.secrets WHERE organization_id=$1 AND reference=$2',[org,second.clientSecretRef])).rows[0].key_id,'canvas-key-two');
  assert.deepEqual(await store.provision(input,secret),first);
  assert.equal((await store.inspect(scope)).clientSecretRef,second.clientSecretRef);
  const unavailableVault=createEncryptedVault({pool,keyProvider:{current:keys.current,byId:async()=>{throw Error('synthetic retired key');}}});
  const unavailable=createOAuthClientStore(pool,unavailableVault);
  assert.deepEqual(await unavailable.receipt(input),first);await assert.rejects(unavailable.provision(input,secret));
  for(const sql of ['UPDATE canvas_connector.oauth_client_provisioning_audit SET actor_id=actor_id WHERE organization_id=$1',
    'DELETE FROM canvas_connector.oauth_client_provisioning_audit WHERE organization_id=$1']) await assert.rejects(query(sql,[org]));
  for(const sameOperation of [true,false]) {
    const id=sameOperation?'same-op':'different-ops';await add(id);
    const value={...input,platformId:id,operationId:randomUUID()};
    const results=await Promise.all(Array.from({length:8},()=>store.provision(sameOperation?value:{...value,operationId:randomUUID()},secret)));
    if(sameOperation)assert.ok(results.every(r=>JSON.stringify(r)===JSON.stringify(results[0])));
    else assert.equal(results.filter(Boolean).length,1);
    assert.equal(Number((await query('SELECT count(*) FROM canvas_connector.secrets WHERE organization_id=$1 AND platform_id=$2',[org,id])).rows[0].count),1);
  }
  await add('rollback');
  await owner(`CREATE FUNCTION canvas_connector.client_provision_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.actor_id='synthetic-fault' THEN RAISE EXCEPTION 'synthetic provisioning audit failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER client_provision_test_fault BEFORE INSERT ON canvas_connector.oauth_client_provisioning_audit
      FOR EACH ROW EXECUTE FUNCTION canvas_connector.client_provision_test_fault();`);
  try {
    await assert.rejects(store.provision({...input,platformId:'rollback',operationId:randomUUID(),actorId:'synthetic-fault'},secret));
    assert.equal(Number((await query("SELECT count(*) FROM canvas_connector.secrets WHERE organization_id=$1 AND platform_id='rollback'",[org])).rows[0].count),0);
    assert.equal(await store.inspect({...scope,platformId:'rollback'}),null);
    assert.equal(Number((await query("SELECT config_version FROM canvas_connector.platforms WHERE organization_id=$1 AND id='rollback'",[org])).rows[0].config_version),1);
  } finally {await owner('DROP TRIGGER client_provision_test_fault ON canvas_connector.oauth_client_provisioning_audit; DROP FUNCTION canvas_connector.client_provision_test_fault();');}
  await add('unknown-reply');let writes=0;
  const unknownInput={...input,platformId:'unknown-reply',operationId:randomUUID()};
  const unknownPool={query:async(sql,values)=>{const result=await query(sql,values);if(sql.includes('provision_oauth_client(')){writes++;throw Error('synthetic lost committed reply');}return result;}};
  const unknown=createOAuthClientStore(unknownPool,createEncryptedVault({pool:unknownPool,keyProvider:keys}));
  await assert.rejects(unknown.provision(unknownInput,secret));assert.equal(writes,1);
  assert.ok(await store.receipt(unknownInput));assert.deepEqual(await store.provision(unknownInput,secret),await store.receipt(unknownInput));
  await query(`INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,client_id,
    client_secret_ref,access_token_ref,capabilities,scopes,status) VALUES($1,$2,3,'https://canvas.example.test','client',$3,'live-access',ARRAY['catalog'],ARRAY['read'],'connected')`,[org,platform,second.clientSecretRef]);
  assert.equal(await store.provision({...input,expectedVersion:3,operationId:randomUUID()},secret),null);
  await query('UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id=$1 AND id=$2',[org,platform]);
  assert.equal(await store.inspect(scope),null);assert.equal(await repo.configuredClient(org,platform,3),null);
  assert.equal(await store.provision({...input,expectedVersion:4,operationId:randomUUID()},secret),null);
  console.log('Actual TLS PG/OpenBao encrypted client provisioning/current-key rotation/historical-key replay/changed-secret conflict/8-way concurrency/no orphans/audit rollback/unknown reply/version fencing passed');
}
