// SPDX-License-Identifier: AGPL-3.0-only
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { CanvasReadError, fail } from './canvas-rest-contract.mjs';

const privateV4 = new BlockList();
const privateV6 = new BlockList();
for (const [address, prefix] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8]]) privateV4.addSubnet(address, prefix, 'ipv4');
privateV6.addAddress('::1', 'ipv6');
privateV6.addSubnet('fc00::', 7, 'ipv6');
const metadataV6 = new BlockList();
metadataV6.addSubnet('fd00:ec2::', 32, 'ipv6');
const blockedV4 = new BlockList();
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]]) blockedV4.addSubnet(address, prefix, 'ipv4');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
const blockedV6 = new BlockList();
for (const [address, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) blockedV6.addSubnet(address, prefix, 'ipv6');
function privateAddress(address) {
  const family = isIP(address);
  return family === 4 ? privateV4.check(address, 'ipv4')
    : family === 6 && privateV6.check(address, 'ipv6') && !metadataV6.check(address, 'ipv6');
}
export function approvedPrivateAddresses(input = []) {
  if (!Array.isArray(input) || input.length > 16 || new Set(input).size !== input.length
      || input.some(address => typeof address !== 'string' || !privateAddress(address))) fail('invalid_private_address_allowlist');
  return Object.freeze([...input]);
}
export function canvasOrigin(value) {
  if (typeof value !== 'string' || /[\s\\%]/.test(value)) fail('invalid_canvas_origin');
  let url;
  try { url = new URL(value); } catch { fail('invalid_canvas_origin'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/'
      || url.hostname.endsWith('.')
      || (value !== url.origin && value !== `${url.origin}/`)
      || /^(?:gateway|issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(url.hostname)
      || /(?:\.svc|\.cluster\.local|\.internal)$/i.test(url.hostname)) fail('invalid_canvas_origin');
  return url.origin;
}
export function validateAddresses(records, allowedPrivate = []) {
  if (!Array.isArray(records) || !records.length || records.length > 64) fail('address_denied');
  for (const entry of records) {
    const family = isIP(entry.address);
    if (!family || family !== entry.family) fail('address_denied');
    const publicAddress = family === 4 ? !blockedV4.check(entry.address, 'ipv4')
      : globalV6.check(entry.address, 'ipv6') && !blockedV6.check(entry.address, 'ipv6');
    if (!publicAddress && !(privateAddress(entry.address) && allowedPrivate.includes(entry.address))) fail('address_denied');
  }
  const selected = records.find(entry => entry.family === 4) ?? records[0];
  return Object.freeze({ address: selected.address, family: selected.family });
}
export function pinnedLookup(hostname, selected) {
  const { address, family } = selected;
  return (requestedHost, options, callback) => {
    if (requestedHost !== hostname) return callback(new CanvasReadError('address_denied'));
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}
export async function resolveAddress(origin, allowedPrivate, signal) {
  if (signal.aborted) fail('timeout');
  const hostname = new URL(origin).hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname)) return validateAddresses([{ address: hostname, family: isIP(hostname) }], allowedPrivate);
  let onAbort;
  try {
    const records = await Promise.race([
      lookup(hostname, { all: true, verbatim: true }),
      new Promise((_, reject) => {
        onAbort = () => reject(new CanvasReadError('timeout'));
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
      }),
    ]);
    if (signal.aborted) fail('timeout');
    return validateAddresses(records, allowedPrivate);
  } catch (error) {
    if (error instanceof CanvasReadError) throw error;
    fail('dns_unavailable');
  } finally { if (onAbort) signal.removeEventListener('abort', onAbort); }
}
