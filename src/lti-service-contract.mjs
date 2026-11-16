// SPDX-License-Identifier: AGPL-3.0-only
import { exactRecord } from './canvas-rest-contract.mjs';
import { ltiId,ltiUuid,ltiVersion } from './lti-registration-contract.mjs';

export const ltiServiceReadScopes=Object.freeze({
 results:'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
 lineitems:'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',
 memberships:'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly',
});
const invalid=()=>{throw Error('invalid_lti_service_attempt');};
export function ltiServiceExact(value,names) {
 exactRecord(value,names,'invalid_lti_service_attempt');if(Object.keys(value).length!==names.length)invalid();
}
export function ltiServiceScopes(value) {
 if(!Array.isArray(value)||!value.length||value.length>3||new Set(value).size!==value.length
  ||value.some(item=>!Object.values(ltiServiceReadScopes).includes(item)))invalid();
 return Object.freeze([...value].sort());
}
export function ltiServiceHandle(value,dispatch=false) {
 ltiServiceExact(value,['organizationId','operationId',...(dispatch?['dispatchId']:[])]);
 if(!ltiId(value.organizationId)||!ltiUuid(value.operationId)||(dispatch&&!ltiUuid(value.dispatchId)))invalid();
 return Object.freeze({...value});
}
export function ltiServiceCommand(value) {
 ltiServiceExact(value,['organizationId','platformId','registrationId','operationId','actorId',
  'expectedPlatformVersion','expectedRegistrationVersion','expectedKeyVersion','scopes']);
 if(!ltiId(value.organizationId)||!ltiId(value.platformId)||!ltiUuid(value.registrationId)||!ltiUuid(value.operationId)||!ltiId(value.actorId)
  ||![value.expectedPlatformVersion,value.expectedRegistrationVersion,value.expectedKeyVersion].every(ltiVersion))invalid();
 return Object.freeze({...value,scopes:ltiServiceScopes(value.scopes)});
}
function origin(value) {const url=new URL(value);if(typeof value!=='string'||url.protocol!=='https:'||url.origin!==value)invalid();}
export function ltiServiceReceipt(value,a) {
 ltiServiceExact(value,['operationId','actorId','platformId','registrationId','kid','keyVersion','tokenReference','scopes','expiresAtMs']);
 if(value.operationId!==a.operationId||value.actorId!==a.actorId||value.platformId!==a.platformId||value.registrationId!==a.registrationId
  ||value.kid!==a.kid||value.keyVersion!==a.keyVersion||!ltiUuid(value.tokenReference)||value.tokenReference!==a.tokenReference
  ||!Number.isSafeInteger(value.expiresAtMs)||value.expiresAtMs<=a.issuedAt*1000||value.expiresAtMs>(a.issuedAt+86400)*1000)invalid();
 const scopes=ltiServiceScopes(value.scopes);if(scopes.some(item=>!a.scopes.includes(item)))invalid();
 return Object.freeze({...value,scopes});
}
export function ltiServiceAttempt(value) {
 ltiServiceExact(value,['organizationId','operationId','platformId','registrationId','actorId','platformVersion','registrationVersion',
  'keyVersion','kid','clientId','canvasOrigin','toolOrigin','scopes','phase','dispatchId','issuedAt','expiresAt','tokenReference','receipt']);
 if(!ltiId(value.organizationId)||!ltiId(value.platformId)||!ltiId(value.actorId)||!ltiUuid(value.operationId)||!ltiUuid(value.registrationId)||!ltiUuid(value.kid)
  ||![value.platformVersion,value.registrationVersion,value.keyVersion].every(ltiVersion)||typeof value.clientId!=='string'||!/^[\x21-\x7e]{1,255}$/.test(value.clientId)
  ||!['prepared','exchanging','uncertain','staged','published','resolved'].includes(value.phase))invalid();
 origin(value.canvasOrigin);origin(value.toolOrigin);const scopes=ltiServiceScopes(value.scopes);
 if(JSON.stringify(scopes)!==JSON.stringify(value.scopes))invalid();
 if(value.dispatchId===null ? value.issuedAt!==null||value.expiresAt!==null
  : !ltiUuid(value.dispatchId)||!Number.isSafeInteger(value.issuedAt)||value.issuedAt<1||value.expiresAt!==value.issuedAt+120)invalid();
 if(value.phase==='prepared'&&value.dispatchId!==null||!['prepared','resolved'].includes(value.phase)&&value.dispatchId===null)invalid();
 if(['staged','published'].includes(value.phase)?!ltiUuid(value.tokenReference):value.tokenReference!==null)invalid();
 const a={...value,scopes};
 if(value.phase==='published')a.receipt=ltiServiceReceipt(value.receipt,a);else if(value.receipt!==null)invalid();
 return Object.freeze(a);
}
