// SPDX-License-Identifier: AGPL-3.0-only
// Server-only durable producer intent. Only the public Gateway can interpret its authority.
import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';

const fail=()=>{throw Error('lti_association_store_unavailable');};
const uuid=v=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v)&&v!=='00000000-0000-0000-0000-000000000000';
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
const version=v=>Number.isSafeInteger(v)&&v>=1;
const hash=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function exact(value,names) {
 if(value===null||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail();
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
 if(keys.length!==names.length||keys.some(key=>!names.includes(key)||!Object.hasOwn(descriptors[key],'value')||!descriptors[key].enumerable))fail();
 return Object.freeze(Object.fromEntries(keys.map(key=>[key,descriptors[key].value])));
}
const fields=['challenge_id','operation_id','launch_id','identity_id','source_id','source_grant_id','binding_id',
 'source_revision','binding_revision','provider_revision','provider_reference','code_hash','expires_at_ms','wrapping_key_id'];
const aad=row=>Buffer.from(JSON.stringify(['canvas-lti-association-code/v1',...fields.map(key=>row[key])]));
const digest=value=>createHash('sha256').update(value).digest();
function keyCopy(value) {if(!Buffer.isBuffer(value)||value.length!==32)fail();return Buffer.from(value);}
function decode(row) {
 if(!row||!['challenge_id','operation_id','launch_id','identity_id','source_grant_id'].every(k=>uuid(row[k]))
  ||!['source_id','binding_id','wrapping_key_id'].every(k=>id(row[k]))
  ||!['source_revision','binding_revision','provider_revision','expires_at_ms'].every(k=>version(row[k]))
  ||!hash(row.provider_reference)||!hash(row.code_hash)
  ||![['ciphertext',32],['nonce',12],['tag',16]].every(([k,n])=>Buffer.isBuffer(row[k])&&row[k].length===n))fail();
 return row;
}
// Must run inside the caller's transaction. Locks pin launch, provider, registration and
// platform until persistence; the clock and signed claims are checked again before commit.
const proofSql=`SELECT s.launch_id,i.id AS identity_id,i.revision::float8 AS provider_revision,
 floor(LEAST(extract(epoch FROM s.expires_at)*1000,
  (s.protocol_claims->>'expiresAt')::numeric*1000,extract(epoch FROM clock_timestamp())*1000+120000))::float8 AS expires_at_ms
 FROM canvas_connector.lti_launch_states s
 JOIN canvas_connector.lti_launch_receipts a ON a.state_hash=s.state_hash AND a.launch_id=s.launch_id AND a.token_hash=s.token_hash
 JOIN canvas_connector.lti_registrations r ON r.id=s.registration_id
 JOIN canvas_connector.platforms p ON p.organization_id=s.organization_id AND p.id=s.platform_id
 JOIN canvas_connector.lti_provider_identities i ON i.organization_id=s.organization_id AND i.platform_id=s.platform_id
  AND i.issuer=s.protocol_claims->>'issuer' AND i.client_id=s.protocol_claims->>'clientId'
  AND i.deployment_id=s.protocol_claims->>'deploymentId' AND i.subject=s.protocol_claims->>'subject'
 WHERE s.registration_id=$1::uuid AND s.state_hash=$2 AND s.browser_hash=$3 AND s.phase='accepted'
  AND p.enabled AND NOT p.archived AND r.enabled AND r.organization_id=s.organization_id AND r.platform_id=s.platform_id
  AND p.config_version=s.platform_version AND r.version=s.registration_version AND s.expires_at>clock_timestamp()
  AND i.status IN ('subject_observed','numeric_linked')
  AND canvas_connector.lti_claims_match(s.protocol_claims,r,p,s.nonce)
 FOR SHARE OF s,r,p,i`;
const selected=fields.map(k=>['source_revision','binding_revision','provider_revision','expires_at_ms'].includes(k)?`${k}::float8 AS ${k}`:k).join(',')+',ciphertext,nonce,tag';

export function createLtiAssociationStore({pool,keyProvider,configuration}={}) {
 if(typeof globalThis.window!=='undefined'||typeof pool?.connect!=='function'
  ||typeof keyProvider?.current!=='function'||typeof keyProvider?.byId!=='function')fail();
 const config=exact(configuration,['registrationId','sourceId','sourceGrantId','bindingId','sourceRevision','bindingRevision']);
 if(!uuid(config.registrationId)||!uuid(config.sourceGrantId)||!id(config.sourceId)||!id(config.bindingId)
  ||!version(config.sourceRevision)||!version(config.bindingRevision))fail();
 async function run(value,create,claim=false) {
  const proof=exact(value,['stateHash','browserHash']);if(!hash(proof.stateHash)||!hash(proof.browserHash))fail();
  let connection,key,plain,inTransaction=false;
  try {
   connection=await pool.connect();await connection.query('BEGIN');inTransaction=true;
   await connection.query("SET LOCAL statement_timeout='5s'");
   await connection.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   // Serialize competing prepares without ever generating a second durable intent.
   await connection.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
    [JSON.stringify(['canvas-association',config.registrationId,proof.stateHash,config.sourceId,config.bindingId])]);
   const args=[config.registrationId,proof.stateHash,proof.browserHash];
   const current=(await connection.query(proofSql,args)).rows;
   if(current?.length!==1)fail();const identity=current[0];
   if(!uuid(identity.launch_id)||!uuid(identity.identity_id)||!version(identity.provider_revision)||!version(identity.expires_at_ms))fail();
   let rows=(await connection.query(`SELECT ${selected} FROM canvas_connector.lti_association_attempts
    WHERE launch_id=$1::uuid AND source_id=$2 AND binding_id=$3`,[identity.launch_id,config.sourceId,config.bindingId])).rows;
   if(!Array.isArray(rows)||rows.length>1)fail();
   if(rows.length===0&&create) {
    const selectedKey=await keyProvider.current();if(!id(selectedKey?.id))fail();key=keyCopy(selectedKey.key);
    plain=randomBytes(32);const nonce=randomBytes(12);
    const row={challenge_id:randomUUID(),operation_id:randomUUID(),launch_id:identity.launch_id,identity_id:identity.identity_id,
     source_id:config.sourceId,source_grant_id:config.sourceGrantId,binding_id:config.bindingId,
     source_revision:config.sourceRevision,binding_revision:config.bindingRevision,provider_revision:identity.provider_revision,
     provider_reference:digest(JSON.stringify(['canvas-provider-reference/v1',config.sourceId,identity.identity_id])).toString('hex'),
     code_hash:digest(plain).toString('hex'),expires_at_ms:identity.expires_at_ms,wrapping_key_id:selectedKey.id};
    const cipher=createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad(row));
    const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]),tag=cipher.getAuthTag();
    rows=(await connection.query(`INSERT INTO canvas_connector.lti_association_attempts
     (${fields.join(',')},ciphertext,nonce,tag) VALUES (${Array.from({length:17},(_,i)=>'$'+(i+1)).join(',')}) RETURNING ${selected}`,
     [...fields.map(k=>row[k]),ciphertext,nonce,tag])).rows;
    key.fill(0);key=undefined;plain.fill(0);plain=undefined;
   }
   if(rows.length===0){await connection.query('COMMIT');inTransaction=false;return null;}
   if(rows.length!==1)fail();const row=decode(rows[0]);
   if(row.launch_id!==identity.launch_id||row.identity_id!==identity.identity_id||row.provider_revision!==identity.provider_revision
    ||row.source_id!==config.sourceId||row.source_grant_id!==config.sourceGrantId||row.binding_id!==config.bindingId
    ||row.source_revision!==config.sourceRevision||row.binding_revision!==config.bindingRevision)fail();
   key=keyCopy(await keyProvider.byId(row.wrapping_key_id));
   const decipher=createDecipheriv('aes-256-gcm',key,row.nonce);decipher.setAAD(aad(row));decipher.setAuthTag(row.tag);
   plain=Buffer.concat([decipher.update(row.ciphertext),decipher.final()]);
   if(plain.length!==32||!timingSafeEqual(digest(plain),Buffer.from(row.code_hash,'hex')))fail();
   const fresh=(await connection.query(proofSql,args)).rows;
   if(fresh?.length!==1||fresh[0].identity_id!==row.identity_id||fresh[0].provider_revision!==row.provider_revision)fail();
   const clockStart=performance.now();
   const now=(await connection.query('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::float8 AS now')).rows;
   if(now?.length!==1||!version(now[0].now)||row.expires_at_ms<=now[0].now)fail();
   let dispatchGranted;
   if(claim) {
    const dispatch=await connection.query(`INSERT INTO canvas_connector.lti_association_dispatches(challenge_id)
     VALUES ($1::uuid) ON CONFLICT DO NOTHING RETURNING challenge_id`,[row.challenge_id]);
    if(!Array.isArray(dispatch.rows)||dispatch.rows.length>1)fail();dispatchGranted=dispatch.rows.length===1;
   }
   await connection.query('COMMIT');inTransaction=false;
   // COMMIT (or dispatch insertion) may have crossed expiry. Use the DB clock
   // plus conservative monotonic elapsed time, including the query round trip.
   // A failure here preserves the committed intent/claim and never retries it.
   if(row.expires_at_ms<=Math.max(Date.now(),now[0].now+performance.now()-clockStart))fail();
   // Kept server-side. Only an explicit consent page may receive the code via fragment.
   const attempt=Object.freeze({challengeId:row.challenge_id,bindingId:row.binding_id,code:plain.toString('base64url'),
    body:Object.freeze({operation_id:row.operation_id,expected_source_revision:row.source_revision,
     expected_binding_revision:row.binding_revision,provider_reference:row.provider_reference,
     provider_revision:row.provider_revision,code_hash:row.code_hash,expires_at_ms:row.expires_at_ms})});
   return claim?Object.freeze({attempt,dispatchGranted}):attempt;
  }catch{if(inTransaction)try{await connection.query('ROLLBACK');}catch{}fail();}
  finally{key?.fill(0);plain?.fill(0);connection?.release();}
 }
 return Object.freeze({prepare:value=>run(value,true),current:value=>run(value,false),claimDispatch:value=>run(value,true,true)});
}
