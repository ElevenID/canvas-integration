// SPDX-License-Identifier: AGPL-3.0-only
import {ltiId,ltiUuid,ltiVersion} from './lti-registration-contract.mjs';
import {ltiServiceExact} from './lti-service-contract.mjs';
import {prepareLtiCaptureRouteIntent} from './lti-capture-contract.mjs';
const fail=()=>{throw Error('lti_capture_admin_unavailable');};
const actions=['create','replace','activate','deactivate','schedule'];
export function ltiCaptureAdminScope(value) {
 if(!ltiId(value?.organizationId)||!ltiId(value.platformId)||!ltiUuid(value.registrationId)||!ltiId(value.routeId))fail();
 return {organizationId:value.organizationId,platformId:value.platformId,registrationId:value.registrationId,routeId:value.routeId};
}
export function ltiCaptureAdminCommand(value) {
 try {
  const scope=ltiCaptureAdminScope(value),action=value.action,create=action==='create',disable=action==='deactivate',defined=['create','replace'].includes(action);
  ltiServiceExact(value,['organizationId','platformId','registrationId','routeId','operationId','actorId','action',
   ...create?[]:['expectedRouteVersion'],...disable?[]:['expectedPlatformVersion','expectedRegistrationVersion','expectedKeyVersion','serviceOperationId'],...defined?['definition']:[]]);
  if(!actions.includes(action)||!ltiUuid(value.operationId)||!ltiId(value.actorId)||!create&&!ltiVersion(value.expectedRouteVersion)
   ||!disable&&(![value.expectedPlatformVersion,value.expectedRegistrationVersion,value.expectedKeyVersion].every(ltiVersion)||!ltiUuid(value.serviceOperationId)))fail();
  const definition=defined?prepareLtiCaptureRouteIntent(value.definition):null;
  if(definition!==null&&(definition.platformId!==scope.platformId||definition.registrationId!==scope.registrationId))fail();
  const request=Object.freeze({expectedPlatformVersion:disable?null:value.expectedPlatformVersion,expectedRegistrationVersion:disable?null:value.expectedRegistrationVersion,
   expectedKeyVersion:disable?null:value.expectedKeyVersion,expectedRouteVersion:create?null:value.expectedRouteVersion,
   serviceOperationId:disable?null:value.serviceOperationId,definition});
  return Object.freeze({...scope,operationId:value.operationId,actorId:value.actorId,action,request});
 }catch{fail();}
}
export function ltiCaptureAdminReceipt(value,scope) {
 try {
  ltiServiceExact(value,['operationId','actorId','action','platformId','registrationId','routeId','version','enabled','serviceOperationId','captureId']);
  if(!ltiUuid(value.operationId)||value.operationId!==scope.operationId||!ltiId(value.actorId)||!actions.includes(value.action)
   ||value.platformId!==scope.platformId||value.registrationId!==scope.registrationId||value.routeId!==scope.routeId
   ||!ltiVersion(value.version)||typeof value.enabled!=='boolean'||!ltiUuid(value.serviceOperationId)
   ||(value.action==='schedule'?value.captureId!==value.operationId:value.captureId!==null)
   ||value.enabled!==['activate','schedule'].includes(value.action))fail();
  return Object.freeze({...value});
 }catch{fail();}
}
