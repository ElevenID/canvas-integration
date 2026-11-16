// SPDX-License-Identifier: AGPL-3.0-only
import { randomUUID } from 'node:crypto';
import { exactRecord,canvasId } from './canvas-rest-contract.mjs';
import { ltiUuid,ltiVersion } from './lti-registration-contract.mjs';
const fail=()=>{throw Error('lti_provider_identity_unavailable');};
const hash=value=>typeof value==='string' && /^[a-f0-9]{64}$/.test(value);
const statuses=['subject_observed','numeric_linked','quarantined'];
function request(value) {
 exactRecord(value,['registrationId','stateHash','browserHash'],'invalid_lti_identity');
 if(!ltiUuid(value.registrationId) || !hash(value.stateHash) || !hash(value.browserHash)) fail();
 return Object.freeze({...value});
}
function receipt(value,registrationId) {
 exactRecord(value,['launchId','registrationId','identityId','status','identityRevision','numericIdSupplied','recordedAtMs'],'invalid_lti_identity');
 if(Object.keys(value).length!==7 || value.registrationId!==registrationId || !ltiUuid(value.launchId) || !ltiUuid(value.identityId)
   || !statuses.includes(value.status) || !ltiVersion(value.identityRevision) || typeof value.numericIdSupplied!=='boolean'
   || !Number.isSafeInteger(value.recordedAtMs) || value.recordedAtMs<1) fail();
 return Object.freeze({...value});
}
export function createLtiProviderIdentityStore(pool) {
 if(typeof globalThis.window!=='undefined' || typeof pool?.query!=='function') fail();
 async function query(statement,values,decode) {
  try {
   const result=await pool.query(statement,values);
   if(result?.rows?.length!==1 || Object.keys(result.rows[0]).join(',')!=='result' || result.rows[0].result===undefined) fail();
   return result.rows[0].result===null?null:decode(result.rows[0].result);
  }catch{fail();}
 }
 return Object.freeze({
  async observe(value) {
   value=request(value);
   // No automatic retry after an uncertain write. A caller must replay the same
   // launch and proof; the proposed local UUID is ignored by original history.
   return query('SELECT canvas_connector.observe_lti_provider_identity($1::uuid,$2,$3,$4::uuid) AS result',
    [value.registrationId,value.stateHash,value.browserHash,randomUUID()],item=>receipt(item,value.registrationId));
  },
  async current(value) {
   value=request(value);
   return query(`SELECT (SELECT jsonb_build_object('identityId',i.id,'status',i.status,'identityRevision',i.revision,
      'canvasUserId',CASE WHEN i.status='numeric_linked' THEN i.canvas_user_id ELSE NULL END)
     FROM canvas_connector.lti_launch_states s
     JOIN canvas_connector.lti_launch_receipts a ON a.state_hash=s.state_hash AND a.launch_id=s.launch_id AND a.token_hash=s.token_hash
     JOIN canvas_connector.lti_registrations r ON r.id=s.registration_id
     JOIN canvas_connector.platforms p ON p.organization_id=s.organization_id AND p.id=s.platform_id
     JOIN canvas_connector.lti_provider_identities i ON i.organization_id=s.organization_id AND i.platform_id=s.platform_id
       AND i.issuer=s.protocol_claims->>'issuer' AND i.client_id=s.protocol_claims->>'clientId'
       AND i.deployment_id=s.protocol_claims->>'deploymentId' AND i.subject=s.protocol_claims->>'subject'
     WHERE s.state_hash=$2 AND s.registration_id=$1::uuid AND s.browser_hash=$3 AND s.phase='accepted'
       AND p.enabled AND NOT p.archived AND r.enabled AND r.organization_id=s.organization_id AND r.platform_id=s.platform_id
       AND p.config_version=s.platform_version AND r.version=s.registration_version AND s.expires_at>clock_timestamp()
       AND canvas_connector.lti_claims_match(s.protocol_claims,r,p,s.nonce)) AS result`,
    [value.registrationId,value.stateHash,value.browserHash],item=>{
      exactRecord(item,['identityId','status','identityRevision','canvasUserId'],'invalid_lti_identity');
      if(Object.keys(item).length!==4 || !ltiUuid(item.identityId) || !statuses.includes(item.status) || !ltiVersion(item.identityRevision)
        || (item.status==='numeric_linked'?typeof item.canvasUserId!=='string' || canvasId(item.canvasUserId)!==item.canvasUserId:item.canvasUserId!==null)) fail();
      return Object.freeze({...item});
    });
  },
 });
}
