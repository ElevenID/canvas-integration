// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createOAuthBrowserBinding, hashOAuthBrowserBinding, matchesOAuthBrowserBindingHash,
  oauthBrowserBindingCookieName, oauthBrowserBindingCookie,expireOAuthBrowserBindingCookie,readOAuthBrowserBinding } from '../src/oauth-browser-binding.mjs';
test('browser proof is random, hash-only in storage and held in a host-only transaction cookie',()=>{
  const proof=createOAuthBrowserBinding();const other=createOAuthBrowserBinding();
  assert.notEqual(proof,other);assert.equal(Buffer.from(proof,'base64url').length,32);
  const hash=hashOAuthBrowserBinding(proof);assert.equal(hash.length,64);
  assert.equal(matchesOAuthBrowserBindingHash(hash,proof),true);
  assert.equal(matchesOAuthBrowserBindingHash(hash,other),false);
  assert.equal(matchesOAuthBrowserBindingHash(null,proof),false);
  const state='a'.repeat(43);const cookie=oauthBrowserBindingCookie(state,proof);
  assert.match(cookie,/^__Host-canvas_oauth_[0-9a-f]{64}=/);
  assert.match(cookie,/; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/);
  assert.doesNotMatch(cookie,/Domain=/i);assert.notEqual(oauthBrowserBindingCookieName(state),oauthBrowserBindingCookieName('b'.repeat(43)));
  assert.match(expireOAuthBrowserBindingCookie(state),/Max-Age=0$/);
  const name=oauthBrowserBindingCookieName(state);
  assert.equal(readOAuthBrowserBinding({headers:{cookie:`${name}=${proof}`},rawHeaders:['Cookie',`${name}=${proof}`]},state),proof);
  assert.equal(readOAuthBrowserBinding({headers:{cookie:`${name}=${proof}`},rawHeaders:['Cookie','one','Cookie','two']},state),null);
});
