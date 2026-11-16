// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
const PROOF=/^[A-Za-z0-9_-]{43}$/;
function validProof(value) {
  return typeof value==='string' && PROOF.test(value)
    && Buffer.from(value,'base64url').toString('base64url')===value;
}
export function createOAuthBrowserBinding() {
  if (typeof globalThis.window!=='undefined') throw Error('server_only');
  return randomBytes(32).toString('base64url');
}
export function hashOAuthBrowserBinding(proof) {
  if (!validProof(proof)) throw Error('invalid_oauth_browser_binding');
  return createHash('sha256').update(proof).digest('hex');
}
export function matchesOAuthBrowserBindingHash(expected,proof) {
  if (typeof expected!=='string' || !/^[0-9a-f]{64}$/.test(expected) || !validProof(proof)) return false;
  return timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(hashOAuthBrowserBinding(proof),'hex'));
}
export function oauthBrowserBindingCookieName(state) {
  if (typeof state!=='string' || !PROOF.test(state)) throw Error('invalid_oauth_state');
  return '__Host-canvas_oauth_'+createHash('sha256').update(state).digest('hex');
}
export function oauthBrowserBindingCookie(state,proof) {
  if (!validProof(proof)) throw Error('invalid_oauth_browser_binding');
  return `${oauthBrowserBindingCookieName(state)}=${proof}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`;
}
export function expireOAuthBrowserBindingCookie(state) {
  return `${oauthBrowserBindingCookieName(state)}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}
export function readOAuthBrowserBinding(request,state) {
  const raw=request.headers.cookie;
  if (typeof raw!=='string' || Buffer.byteLength(raw)>8192
      || request.rawHeaders.filter((v,i)=>i%2===0 && v.toLowerCase()==='cookie').length!==1) return null;
  const name=oauthBrowserBindingCookieName(state);
  let proof;
  for (const pair of raw.split(';')) {
    const separator=pair.indexOf('=');
    if (separator<0 || pair.slice(0,separator).trim()!==name) continue;
    if (proof!==undefined) return null;
    proof=pair.slice(separator+1).trim();
  }
  return validProof(proof)?proof:null;
}
