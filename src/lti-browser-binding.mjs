// SPDX-License-Identifier: AGPL-3.0-only
import { createHash } from 'node:crypto';
function proof(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, 'base64url').toString('base64url') === value;
}
export function ltiBrowserCookieName(state) {
  if (!proof(state)) throw new Error('invalid_lti_state');
  return '__Host-canvas_lti_' + createHash('sha256').update(state).digest('hex');
}
export function ltiBrowserCookie(state, value) {
  if (!proof(value)) throw new Error('invalid_lti_browser_proof');
  return `${ltiBrowserCookieName(state)}=${value}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=300`;
}
export function readLtiBrowserCookie(request, state) {
  const headers = request.rawHeaders.filter((value, index) => index % 2 === 1 && request.rawHeaders[index - 1].toLowerCase() === 'cookie');
  if (!headers.length) return Object.freeze({ kind: 'absent' });
  if (headers.length !== 1 || Buffer.byteLength(headers[0]) > 8192) return Object.freeze({ kind: 'invalid' });
  const name = ltiBrowserCookieName(state), values = headers[0].split(';').map(value => value.trim())
    .filter(value => value.slice(0, value.indexOf('=')) === name);
  if (!values.length) return Object.freeze({ kind: 'absent' });
  const value = values[0].slice(values[0].indexOf('=') + 1);
  return values.length === 1 && proof(value) ? Object.freeze({ kind: 'present', proof: value }) : Object.freeze({ kind: 'invalid' });
}
