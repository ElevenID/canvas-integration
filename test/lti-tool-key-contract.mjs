// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createLtiToolKeyStore } from '../src/lti-tool-key-store.mjs';

export async function ltiToolKeyContract(pool,{keyProvider,ownerQuery}) {
  const organizationId='tool-key-org',platformId='tool-key-platform',registrationId=randomUUID();
  await ownerQuery(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES('${organizationId}','${platformId}','https://canvas.example.test',true);
    INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,environment,target_link_uri,enabled)
    VALUES('${registrationId}','${organizationId}','${platformId}','tool-client','deployment','hosted_global','production',
    'https://tool.example.test/lti/registrations/${registrationId}/resource',true);`);
  const store=createLtiToolKeyStore({pool,keyProvider});
  const input={organizationId,platformId,registrationId,operationId:randomUUID(),actorId:'operator',action:'provision',
    expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:null};
  const selections={organizationId,platformId,registrationId,expectedPlatformVersion:1,expectedRegistrationVersion:1,expectedKeyVersion:1};
  for(const [relation,assignment] of [['lti_tool_key_configurations','NEW.current_kid:=NULL;'],['lti_tool_key_operation_audit',"NEW.actor_id:='rewritten';"]]) {
    await ownerQuery(`CREATE FUNCTION canvas_connector.synthetic_tool_key_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN ${assignment} RETURN NEW; END; $$;
      CREATE TRIGGER synthetic_tool_key_rewrite BEFORE INSERT ON canvas_connector.${relation}
       FOR EACH ROW EXECUTE FUNCTION canvas_connector.synthetic_tool_key_rewrite();`);
    try {
      await assert.rejects(store.administer(input),/lti_tool_key_store_unavailable/,'postimage changes must roll back all key material');
      for(const name of ['lti_tool_keys','lti_tool_key_configurations','lti_tool_key_operation_audit'])
        assert.equal((await pool.query(`SELECT count(*)::float8 AS count FROM canvas_connector.${name} WHERE organization_id=$1`,[organizationId])).rows[0].count,0);
    } finally {
      await ownerQuery(`DROP TRIGGER synthetic_tool_key_rewrite ON canvas_connector.${relation};DROP FUNCTION canvas_connector.synthetic_tool_key_rewrite();`);
    }
  }
  const receipts=await Promise.all(Array.from({length:4},()=>store.administer(input)));
  for(const item of receipts)assert.deepEqual(item,receipts[0]);const first=receipts[0];
  assert.equal(first.version,1);assert.equal(first.action,'provision');assert.equal(first.publicJwk.kid,first.kid);
  assert.deepEqual(Object.keys(first.publicJwk).sort(),['alg','e','kid','kty','n','use']);
  const material=await store.current(selections);assert.equal(material.kid,first.kid);assert.match(material.privateKeyPem,/BEGIN PRIVATE KEY/);
  const persisted=(await pool.query('SELECT ciphertext FROM canvas_connector.lti_tool_keys WHERE kid=$1::uuid',[first.kid])).rows[0];
  assert.equal(persisted.ciphertext.includes(Buffer.from('PRIVATE KEY')),false);
  for(const change of [{actorId:'other'},{registrationId:randomUUID()},{expectedPlatformVersion:2}])
    assert.equal(await store.administer({...input,...change}),null,'same operation with changed intent conflicts');
  assert.equal(await store.current({...selections,organizationId:'foreign'}),null);
  assert.equal(await store.current({...selections,expectedKeyVersion:2}),null);
  const corrupt=createLtiToolKeyStore({keyProvider,pool:{async query(sql,values){
    const result=await pool.query(sql,values);
    if(sql.startsWith('SELECT k.kid'))return{rows:result.rows.map(row=>({...row,toolOrigin:'https://foreign.example.test'}))};
    return result;
  }}});
  await assert.rejects(corrupt.current(selections),/lti_tool_key_store_unavailable/);
  const wrongKey=createLtiToolKeyStore({pool,keyProvider:{current:keyProvider.current,byId:async()=>Buffer.alloc(32,0)}});
  await assert.rejects(wrongKey.current(selections),/lti_tool_key_store_unavailable/);
  await assert.rejects(pool.query('UPDATE canvas_connector.lti_tool_keys SET ciphertext=$1 WHERE kid=$2::uuid',[Buffer.from('tamper'),first.kid]));
  await assert.rejects(pool.query('DELETE FROM canvas_connector.lti_tool_key_operation_audit WHERE organization_id=$1',[organizationId]));
  const rotate={...input,operationId:randomUUID(),action:'rotate',expectedKeyVersion:1};
  const candidates=await Promise.all([store.administer(rotate),store.administer({...rotate,operationId:randomUUID()})]);
  assert.equal(candidates.filter(Boolean).length,1,'only one writer may advance the same revision');
  const second=candidates.find(Boolean);assert.equal(second.version,2);assert.notEqual(second.kid,first.kid);
  assert.equal(await store.current(selections),null);
  assert.equal((await store.current({...selections,expectedKeyVersion:2})).kid,second.kid);
  let dropped=false;
  const lossy=createLtiToolKeyStore({keyProvider,pool:{async query(sql,values){
    const result=await pool.query(sql,values);
    if(!dropped&&sql.includes('SELECT canvas_connector.administer_lti_tool_key')){dropped=true;throw Error('synthetic lost committed reply');}
    return result;
  }}});
  const uncertain={...rotate,operationId:randomUUID(),expectedKeyVersion:2};
  await assert.rejects(lossy.administer(uncertain),/lti_tool_key_store_unavailable/);
  const recovered=await lossy.administer(uncertain);assert.equal(recovered.version,3);
  assert.deepEqual(await store.administer(uncertain),recovered,'retry reconciles original receipt without another key');
  const delayed=createLtiToolKeyStore({pool,keyProvider:{current:keyProvider.current,async byId(id){
    await ownerQuery(`UPDATE canvas_connector.platforms SET enabled=false WHERE organization_id='${organizationId}' AND id='${platformId}';`);
    return keyProvider.byId(id);
  }}});
  assert.equal(await delayed.current({...selections,expectedKeyVersion:3}),null,'disable during Bao lookup fences private material release');
  assert.equal(await store.current({...selections,expectedKeyVersion:3}),null,'platform drift fences private key access');
  const disabled=await store.administer({...input,operationId:randomUUID(),action:'deactivate',expectedPlatformVersion:null,
    expectedRegistrationVersion:null,expectedKeyVersion:3});
  assert.equal(disabled.version,4);assert.equal(disabled.kid,null);assert.equal(disabled.publicJwk,null);
  assert.equal((await pool.query('SELECT count(*)::float8 AS count FROM canvas_connector.lti_tool_keys WHERE organization_id=$1',[organizationId])).rows[0].count,3);
  assert.deepEqual(await store.administer(input),first,'historical receipt is stable after disable and platform drift');
  console.log('LTI tool key actual PostgreSQL/OpenBao encrypted custody, CAS, history, lost reply, context fences and deactivation PASS');
}
