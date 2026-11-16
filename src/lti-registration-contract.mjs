// SPDX-License-Identifier: AGPL-3.0-only
import { exactRecord } from './canvas-rest-contract.mjs';
import { canvasLtiTrustProfile } from './canvas-lti-platform.mjs';

export const ltiId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
export const ltiUuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
export const ltiVersion = value => Number.isSafeInteger(value) && value >= 1 && value <= 9007199254740991;
const invalid = () => { throw Error('invalid_lti_registration'); };
function keys(value, names) {
  exactRecord(value,names,'invalid_lti_registration');if(Object.keys(value).length!==names.length) invalid();
}
function identifier(value) {
  if(typeof value!=='string' || !/^[\x21-\x7e]{1,255}$/.test(value)) invalid();return value;
}
export function ltiRegistrationDefinition(value,registrationId) {
  keys(value,['clientId','deploymentId','trustProfile','environment','targetLinkUri']);
  if(!ltiUuid(registrationId)) invalid();
  const clientId=identifier(value.clientId),deploymentId=identifier(value.deploymentId);
  if(!(value.trustProfile==='hosted_global' && ['production','beta','test'].includes(value.environment)) &&
     !(value.trustProfile==='self_managed_same_origin' && value.environment===null)) invalid();
  let target;try{target=new URL(value.targetLinkUri);}catch{invalid();}
  if(typeof value.targetLinkUri!=='string' || value.targetLinkUri.length>2048 || target.protocol!=='https:' || target.username || target.password ||
    value.targetLinkUri!==target.origin+`/lti/registrations/${registrationId}/resource`) invalid();
  return Object.freeze({clientId,deploymentId,trustProfile:value.trustProfile,environment:value.environment,targetLinkUri:value.targetLinkUri});
}
export function prepareLtiRegistrationDefinition(value,{registrationId,publicOrigin}) {
  keys(value,['clientId','deploymentId','trustProfile','environment']);
  let origin;try{origin=new URL(publicOrigin);}catch{invalid();}
  if(origin.protocol!=='https:' || origin.origin!==publicOrigin) invalid();
  return ltiRegistrationDefinition({...value,targetLinkUri:publicOrigin+`/lti/registrations/${registrationId}/resource`},registrationId);
}
export function validateLtiRegistrationPolicy(value,{registrationId,publicOrigin,platformOrigin,selfManagedOriginAllowlist}) {
  const definition=ltiRegistrationDefinition(value,registrationId);
  if(definition.targetLinkUri!==publicOrigin+`/lti/registrations/${registrationId}/resource`) invalid();
  canvasLtiTrustProfile({canvasOrigin:platformOrigin,trustProfile:definition.trustProfile,environment:definition.environment??undefined,
    selfManagedOriginAllowlist:definition.trustProfile==='self_managed_same_origin'?selfManagedOriginAllowlist:undefined});
  return definition;
}
export function ltiRegistrationIntent(value,registrationId) {
  keys(value,['action','expectedPlatformVersion','expectedRegistrationVersion','definition']);
  if(!['create','replace','activate','deactivate'].includes(value.action)) invalid();
  if(value.action==='deactivate' ? value.expectedPlatformVersion!==null : !ltiVersion(value.expectedPlatformVersion)) invalid();
  if(value.action==='create' ? value.expectedRegistrationVersion!==null :
    (!ltiVersion(value.expectedRegistrationVersion) || value.expectedRegistrationVersion>=9007199254740991)) invalid();
  const definition=['create','replace'].includes(value.action)?ltiRegistrationDefinition(value.definition,registrationId):null;
  if(definition===null && value.definition!==null) invalid();
  return Object.freeze({action:value.action,expectedPlatformVersion:value.expectedPlatformVersion,
    expectedRegistrationVersion:value.expectedRegistrationVersion,definition});
}
