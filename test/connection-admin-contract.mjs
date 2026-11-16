// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createConnectionAdminStore} from '../src/connection-admin.mjs';
export async function connectionAdministrationContract(pool,{ownerQuery}={}) {
  const query=(sql,values=[])=>pool.query(sql,values),owner=ownerQuery??query,store=createConnectionAdminStore(pool);
  const org='connection-admin-'+randomUUID(),platform='platform',scope={organizationId:org,platformId:platform};
  await query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES($1,$2,$3,true)',[org,platform,'https://canvas.example.test']);
  let serial=0;
  async function connect() {
    const suffix=++serial;
    await query(`INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,
      client_id,client_secret_ref,access_token_ref,refresh_token_ref,capabilities,scopes,status)
      VALUES($1,$2,1,'https://canvas.example.test','client','client-secret',$3,$4,ARRAY['catalog'],ARRAY['read'],'connected')`,
      [org,platform,'access-'+suffix,'refresh-'+suffix]);
    await query(`INSERT INTO canvas_connector.oauth_status(organization_id,platform_id,status) VALUES($1,$2,'connected')
      ON CONFLICT(organization_id,platform_id) DO UPDATE SET status='connected'`,[org,platform]);
    return (await store.inspect(scope)).connection;
  }
  const mutation=connection=>({...scope,connectionId:connection.connectionId,expectedRevision:connection.revision,
    operationId:randomUUID(),actorId:'current-operator'});
  const first=await connect(),value=mutation(first);
  const receipt=await store.disconnect(value);
  assert.equal(receipt.status,'disconnected');assert.equal(receipt.connectionId,first.connectionId);
  assert.deepEqual(await store.disconnect(value),receipt);
  assert.deepEqual(await store.receipt(value),receipt);
  assert.equal((await store.inspect(scope)).connection,null);
  assert.equal((await store.inspect(scope)).pendingRevocation,true);
  const refs=(await query('SELECT access_token_ref,refresh_token_ref FROM canvas_connector.revocation_jobs WHERE id=$1',[receipt.revocationJobId])).rows[0];
  assert.deepEqual(refs,{access_token_ref:'access-1',refresh_token_ref:'refresh-1'});
  const replacement=await connect();assert.notEqual(replacement.connectionId,first.connectionId);assert.equal(replacement.revision,1);
  assert.deepEqual(await store.disconnect(value),receipt);
  assert.equal((await store.inspect(scope)).connection.connectionId,replacement.connectionId);
  assert.equal(await store.disconnect({...value,operationId:randomUUID()}),null);
  assert.equal(await store.disconnect({...value,actorId:'other-operator'}),null);
  assert.equal(await store.receipt({...value,organizationId:'foreign-org'}),null);
  await assert.rejects(query('UPDATE canvas_connector.connections SET connection_id=$1 WHERE organization_id=$2',[randomUUID(),org]));
  for(const sql of ['UPDATE canvas_connector.connection_operation_audit SET actor_id=actor_id WHERE organization_id=$1',
    'DELETE FROM canvas_connector.connection_operation_audit WHERE organization_id=$1']) await assert.rejects(query(sql,[org]));
  const results=await Promise.all(Array.from({length:8},()=>store.disconnect(mutation(replacement))));
  assert.equal(results.filter(Boolean).length,1);
  assert.equal(Number((await query('SELECT count(*) FROM canvas_connector.connection_operation_audit WHERE organization_id=$1',[org])).rows[0].count),2);
  const rollback=await connect();
  await owner(`CREATE FUNCTION canvas_connector.connection_admin_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.actor_id='synthetic-fault' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER connection_admin_test_fault BEFORE INSERT ON canvas_connector.connection_operation_audit
      FOR EACH ROW EXECUTE FUNCTION canvas_connector.connection_admin_test_fault();`);
  try {
    await assert.rejects(store.disconnect({...mutation(rollback),actorId:'synthetic-fault'}));
    assert.equal((await store.inspect(scope)).connection.connectionId,rollback.connectionId);
    assert.equal(Number((await query("SELECT count(*) FROM canvas_connector.revocation_jobs WHERE organization_id=$1 AND access_token_ref='access-3'",[org])).rows[0].count),0);
    assert.equal((await query('SELECT status FROM canvas_connector.oauth_status WHERE organization_id=$1',[org])).rows[0].status,'connected');
  } finally {await owner('DROP TRIGGER connection_admin_test_fault ON canvas_connector.connection_operation_audit; DROP FUNCTION canvas_connector.connection_admin_test_fault();');}
  const lostValue=mutation(rollback);
  let calls=0;
  const lost=createConnectionAdminStore({query:async(sql,values)=>{
    calls++;const result=await query(sql,values);throw Error('synthetic lost committed reply');
  }});
  await assert.rejects(lost.disconnect(lostValue));assert.equal(calls,1);
  assert.equal((await store.receipt(lostValue)).connectionId,rollback.connectionId);
  assert.equal((await store.inspect(scope)).connection,null);
  const fenceOrg=org+'-fence',hash='e'.repeat(64),refreshId=randomUUID();
  await query('INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES($1,$2,$3,true)',[fenceOrg,platform,'https://canvas.example.test']);
  await query(`INSERT INTO canvas_connector.authorization_attempts(authorization_hash,organization_id,platform_id,
    platform_config_version,canvas_origin,client_id,client_secret_ref,capabilities,scopes,redirect_uri,authorization_expires_at)
    VALUES($1,$2,$3,1,'https://canvas.example.test','client','client-secret',ARRAY['catalog'],ARRAY['read'],
      'https://connector.example.test/oauth/callback',clock_timestamp()+interval '5 minutes')`,[hash,fenceOrg,platform]);
  await query(`INSERT INTO canvas_connector.refresh_attempts(id,organization_id,platform_id,connection_revision,config_version,
    canvas_origin,client_id,client_secret_ref,access_token_ref,refresh_token_ref)
    VALUES($1,$2,$3,1,1,'https://canvas.example.test','client','client-secret','old-access','old-refresh')`,[refreshId,fenceOrg,platform]);
  const admit=()=>query("UPDATE canvas_connector.authorization_attempts SET phase='exchanging' WHERE authorization_hash=$1",[hash]);
  await assert.rejects(admit());
  await query("UPDATE canvas_connector.refresh_attempts SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",[refreshId]);
  assert.equal((await store.inspect({organizationId:fenceOrg,platformId:platform})).pendingRefresh,false);
  await admit();
  await query("UPDATE canvas_connector.authorization_attempts SET phase='consumed' WHERE authorization_hash=$1",[hash]);
  for(const phase of ['exchanging','reconciliation_required']) {
    await query('UPDATE canvas_connector.refresh_attempts SET phase=$2 WHERE id=$1',[refreshId,phase]);
    await assert.rejects(admit());
  }
  await query("UPDATE canvas_connector.refresh_attempts SET phase='abandoned' WHERE id=$1",[refreshId]);
  await query(`INSERT INTO canvas_connector.revocation_jobs(organization_id,platform_id,canvas_origin,access_token_ref)
    VALUES($1,$2,'https://canvas.example.test','pending-access')`,[fenceOrg,platform]);
  await assert.rejects(admit());
  // This case proves queue creation, not provider cleanup. Keep its jobs and
  // receipts, but exclude only these synthetic rows from later global-worker cases.
  await query("UPDATE canvas_connector.revocation_jobs SET available_at=clock_timestamp()+interval '1 day' WHERE organization_id IN ($1,$2)",[org,fenceOrg]);
  console.log('Actual PostgreSQL connection generation/CAS/eight concurrent disconnects/immutable receipts/reconnect replay/audit rollback/unknown reply contracts passed');
}
