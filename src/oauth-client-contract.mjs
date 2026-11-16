// SPDX-License-Identifier: AGPL-3.0-only
export const clientId=value=>typeof value==='string' && value.isWellFormed() && value.length>=1 && value.length<=512 && value.trim()===value
  && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
export const clientSecret=value=>typeof value==='string' && value.isWellFormed() && value.length>=1 && value.length<=4096
  && Buffer.byteLength(value)<=16384 && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid=value=>typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
export function clientProvisioningInput(value) {
  return id(value?.organizationId) && id(value?.platformId) && id(value?.actorId) && uuid(value?.operationId)
    && Number.isSafeInteger(value?.expectedVersion) && value.expectedVersion>=1 && clientId(value?.clientId);
}
export function clientProvisioningReceipt(value,input) {
  return value!==null && typeof value==='object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',')==='actorId,clientId,clientSecretRef,configVersion,operationId,platformId'
    && id(value.platformId) && id(value.actorId) && uuid(value.operationId) && uuid(value.clientSecretRef)
    && clientId(value.clientId) && Number.isSafeInteger(value.configVersion) && value.configVersion>=2
    && (input===undefined || (value.platformId===input.platformId && value.actorId===input.actorId
      && value.operationId===input.operationId && value.clientId===input.clientId && value.configVersion===input.expectedVersion+1));
}
