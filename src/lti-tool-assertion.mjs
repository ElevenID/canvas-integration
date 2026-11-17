// SPDX-License-Identifier: AGPL-3.0-only
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, constants } from 'node:crypto';
import { exactRecord } from './canvas-rest-contract.mjs';

const unavailable = () => { throw Error('lti_tool_key_unavailable'); };
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const text = value => typeof value === 'string' && /^[\x21-\x7e]{1,255}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value > 0;
function origin(value) {
  const url = new URL(value);
  if (typeof value !== 'string' || url.protocol !== 'https:' || url.origin !== value || url.username || url.password) unavailable();
  return url.origin;
}

// Internal key codec only. Production provisioning generates a fresh connector
// key and encrypts it before publication; no general remote signing interface.
export function prepareLtiToolKey(value) {
  try {
    if (typeof globalThis.window !== 'undefined') unavailable();
    exactRecord(value, ['kid','privateKeyPem'], 'invalid_tool_key');
    if (Object.keys(value).length !== 2 || !uuid(value.kid) || typeof value.privateKeyPem !== 'string'
      || Buffer.byteLength(value.privateKeyPem) > 8192 || !/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PRIVATE KEY-----\r?\n?$/.test(value.privateKeyPem)) unavailable();
    const key = createPrivateKey({key:value.privateKeyPem,format:'pem',type:'pkcs8'});
    if (key.type !== 'private' || key.asymmetricKeyType !== 'rsa' || ![2048,3072,4096].includes(key.asymmetricKeyDetails?.modulusLength)) unavailable();
    const publicKey = createPublicKey(key).export({format:'jwk'});
    if (publicKey.kty !== 'RSA' || publicKey.e !== 'AQAB' || typeof publicKey.n !== 'string') unavailable();
    const jwk = Object.freeze({kty:'RSA',n:publicKey.n,e:'AQAB',kid:value.kid,alg:'RS256',use:'sig'});
    return Object.freeze({key,kid:value.kid,publicJwk:jwk});
  } catch {unavailable();}
}

export function generateLtiToolKey() {
  try {
    if (typeof globalThis.window !== 'undefined') unavailable();
    const pair=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
    const value={kid:randomUUID(),privateKeyPem:pair.privateKey.export({type:'pkcs8',format:'pem'})};
    const prepared=prepareLtiToolKey(value);
    return Object.freeze({...value,publicJwk:prepared.publicJwk});
  }catch{unavailable();}
}

// The durable caller supplies the original attempt UUID and timestamps. This
// primitive neither regenerates identity nor retries an uncertain exchange.
export function signLtiClientAssertion(prepared, input) {
  try {
    if (typeof globalThis.window !== 'undefined') unavailable();
    exactRecord(input,['toolOrigin','clientId','tokenEndpoint','requestId','issuedAt','expiresAt'],'invalid_tool_assertion');
    const toolOrigin=origin(input.toolOrigin), endpoint=new URL(input.tokenEndpoint);
    if (endpoint.protocol!=='https:' || endpoint.username || endpoint.password || endpoint.hash || endpoint.search
      || endpoint.pathname!=='/login/oauth2/token' || endpoint.href!==input.tokenEndpoint || !text(input.clientId)
      || !uuid(input.requestId) || !integer(input.issuedAt) || !integer(input.expiresAt)
      || input.expiresAt<=input.issuedAt || input.expiresAt-input.issuedAt>120 || !uuid(prepared?.kid)
      || prepared?.key?.type!=='private' || prepared.key.asymmetricKeyType!=='rsa'
      || ![2048,3072,4096].includes(prepared.key.asymmetricKeyDetails?.modulusLength)
      || prepared.key.asymmetricKeyDetails?.publicExponent!==65537n) unavailable();
    const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
    const header=encode({typ:'JWT',alg:'RS256',kid:prepared.kid});
    const payload=encode({iss:toolOrigin,sub:input.clientId,aud:input.tokenEndpoint,iat:input.issuedAt,exp:input.expiresAt,jti:input.requestId});
    const bytes=Buffer.from(header+'.'+payload,'ascii');
    return bytes.toString('ascii')+'.'+sign('RSA-SHA256',bytes,{key:prepared.key,padding:constants.RSA_PKCS1_PADDING}).toString('base64url');
  }catch{unavailable();}
}
