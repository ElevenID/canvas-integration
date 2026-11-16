// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createPlatformAdminStore} from '../src/platform-admin.mjs';
import {createConnectionAdminStore} from '../src/connection-admin.mjs';
export async function platformAdministrationContract(pool,{ownerQuery}={}) {
  const query=(sql,values=[])=>pool.query(sql,values),owner=ownerQuery??query,store=createPlatformAdminStore(pool);
  const organizationId='platform-admin-'+randomUUID(),platformId='platform',scope={organizationId,platformId};
  const create={...scope,operationId:randomUUID(),actorId:'operator',action:'create',canvasOrigin:'https://canvas.example.test'};
  const created=await store.apply(create);assert.equal(created.configVersion,1);assert.equal(created.enabled,false);
  assert.deepEqual(await store.apply(create),created);assert.deepEqual(await store.receipt(create),created);
  assert.equal(await store.apply({...create,operationId:randomUUID()}),null);
  assert.equal(await store.apply({...create,actorId:'different'}),null);
  assert.equal(await store.apply({...create,canvasOrigin:'https://different.example.test'}),null);
  assert.equal(await store.receipt({...create,organizationId:'foreign'}),null);
  const change=(expectedVersion,enabled,archived=false)=>({...scope,operationId:randomUUID(),actorId:'operator',action:'change',expectedVersion,enabled,archived});
  const enabledValue=change(1,true),enabled=await store.apply(enabledValue);assert.equal(enabled.configVersion,2);
  assert.equal(await store.apply(change(1,false)),null);
  assert.equal(await store.apply(change(2,true)),null);
  await query(`INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,
    client_id,client_secret_ref,access_token_ref,capabilities,scopes,status)
    VALUES($1,$2,2,'https://canvas.example.test','client','client-secret','access',ARRAY['catalog'],ARRAY['read'],'connected')`,[organizationId,platformId]);
  assert.equal((await store.apply(change(2,false))).configVersion,3);
  assert.equal(await store.apply(change(3,true)),null);assert.equal(await store.apply(change(3,false,true)),null);
  const connections=createConnectionAdminStore(pool),connection=(await connections.inspect(scope)).connection;
  const disconnect=await connections.disconnect({...scope,connectionId:connection.connectionId,expectedRevision:connection.revision,operationId:randomUUID(),actorId:'operator'});
  assert.equal(await store.apply(change(3,true)),null);
  // Synthetic guard-state probe only: there are no token rows/provider calls.
  await query('UPDATE canvas_connector.revocation_jobs SET provider_revoked_at=clock_timestamp(),completed_at=clock_timestamp() WHERE id=$1',[disconnect.revocationJobId]);
  const refreshId=randomUUID();
  await query(`INSERT INTO canvas_connector.refresh_attempts(id,organization_id,platform_id,connection_revision,config_version,
    canvas_origin,client_id,client_secret_ref,access_token_ref,refresh_token_ref,phase,lease_until)
    VALUES($1,$2,$3,1,2,'https://canvas.example.test','client','client-secret','access','refresh','exchanging',clock_timestamp()-interval '1 second')`,[refreshId,organizationId,platformId]);
  assert.equal(await store.apply(change(3,true)),null);assert.equal(await store.apply(change(3,false,true)),null);
  await query("UPDATE canvas_connector.refresh_attempts SET phase='claimed' WHERE id=$1",[refreshId]);
  assert.equal((await store.apply(change(3,true))).configVersion,4);
  assert.equal((await store.apply(change(4,false))).configVersion,5);
  const authorizationHash='f'.repeat(64);
  await query(`INSERT INTO canvas_connector.authorization_attempts(authorization_hash,organization_id,platform_id,
    platform_config_version,canvas_origin,client_id,client_secret_ref,capabilities,scopes,redirect_uri,authorization_expires_at,phase)
    VALUES($1,$2,$3,5,'https://canvas.example.test','client','client-secret',ARRAY['catalog'],ARRAY['read'],
      'https://connector.example.test/oauth/callback',clock_timestamp()+interval '5 minutes','exchanging')`,[authorizationHash,organizationId,platformId]);
  assert.equal(await store.apply(change(5,true)),null);assert.equal(await store.apply(change(5,false,true)),null);
  await query("UPDATE canvas_connector.authorization_attempts SET phase='abandoned' WHERE authorization_hash=$1",[authorizationHash]);
  const archived=await store.apply(change(5,false,true));assert.equal(archived.configVersion,6);assert.equal(archived.archived,true);
  assert.equal(await store.apply(change(6,true)),null);
  assert.deepEqual(await store.apply(enabledValue),enabled);assert.equal((await store.inspect(scope)).archived,true);
  for(const sql of ['UPDATE canvas_connector.platform_operation_audit SET actor_id=actor_id WHERE organization_id=$1',
    'DELETE FROM canvas_connector.platform_operation_audit WHERE organization_id=$1']) await assert.rejects(query(sql,[organizationId]));
  const concurrent={...create,platformId:'concurrent'};
  const results=await Promise.all(Array.from({length:8},()=>store.apply({...concurrent,operationId:randomUUID()})));
  assert.equal(results.filter(Boolean).length,1);
  const retries={...create,platformId:'exact-retry'};
  const retried=await Promise.all(Array.from({length:8},()=>store.apply(retries)));
  assert.ok(retried.every(receipt=>JSON.stringify(receipt)===JSON.stringify(retried[0])));
  const pageOrg=organizationId+'-page';
  for(let i=0;i<25;i++) await store.apply({...create,organizationId:pageOrg,platformId:'p'+String(i).padStart(2,'0'),operationId:randomUUID()});
  const firstPage=await store.catalog({organizationId:pageOrg});assert.equal(firstPage.platforms.length,20);assert.equal(firstPage.nextCursor,'p19');
  const secondPage=await store.catalog({organizationId:pageOrg,afterId:firstPage.nextCursor});assert.equal(secondPage.platforms.length,5);assert.equal(secondPage.nextCursor,null);
  assert.equal(new Set([...firstPage.platforms,...secondPage.platforms].map(p=>p.platformId)).size,25);
  assert.deepEqual(await store.catalog({organizationId:'foreign'}),{platforms:[],nextCursor:null});
  await owner(`CREATE FUNCTION canvas_connector.platform_admin_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.actor_id='synthetic-fault' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER platform_admin_test_fault BEFORE INSERT ON canvas_connector.platform_operation_audit
      FOR EACH ROW EXECUTE FUNCTION canvas_connector.platform_admin_test_fault();`);
  try {
    await assert.rejects(store.apply({...create,platformId:'rolled-back',actorId:'synthetic-fault',operationId:randomUUID()}));
    assert.equal(await store.inspect({...scope,platformId:'rolled-back'}),null);
    await assert.rejects(store.apply({...change(1,true),platformId:'concurrent',actorId:'synthetic-fault'}));
    assert.equal((await store.inspect({...scope,platformId:'concurrent'})).configVersion,1);
  } finally {await owner('DROP TRIGGER platform_admin_test_fault ON canvas_connector.platform_operation_audit; DROP FUNCTION canvas_connector.platform_admin_test_fault();');}
  const lostValue={...create,platformId:'unknown-reply',operationId:randomUUID()};let calls=0;
  const lost=createPlatformAdminStore({query:async(sql,values)=>{calls++;await query(sql,values);throw Error('synthetic lost committed reply');}});
  await assert.rejects(lost.apply(lostValue));assert.equal(calls,1);
  assert.equal((await store.receipt(lostValue)).platformId,lostValue.platformId);
  assert.deepEqual(await store.apply(lostValue),await store.receipt(lostValue));
  console.log('Actual PostgreSQL platform CRUD/CAS/provider-work fences/8 concurrent create+replay/bounded tenant catalog/immutable audit/rollback/unknown reply passed');
}
