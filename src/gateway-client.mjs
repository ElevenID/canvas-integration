// SPDX-License-Identifier: AGPL-3.0-only
import { request } from 'node:https';
import { OPERATIONS, READ_OPERATIONS } from './operations.mjs';

export class GatewayError extends Error {
  constructor(code, status) {
    super(`Canvas Gateway request failed: ${code}`);
    this.name = 'GatewayError';
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}
const fail = code => { throw new GatewayError(code); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
function keys(value, allowed, code) {
  if (!record(value) || Object.keys(value).some(key => !allowed.includes(key))) fail(code);
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('invalid_limits');
  return value;
}
function origin(value) {
  if (typeof value !== 'string' || value !== value.trim() || /[\s\\]/.test(value)) fail('invalid_gateway_origin');
  let parsed;
  try { parsed = new URL(value); } catch { fail('invalid_gateway_origin'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
      || parsed.pathname !== '/' || !parsed.hostname
      || /^(?:issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(parsed.hostname)
      || /(?:\.svc|\.cluster\.local|\.internal)$/i.test(parsed.hostname)
      || parsed.hostname === '169.254.169.254') fail('invalid_gateway_origin');
  return parsed.origin;
}
function jsonValue(value, depth = 0) {
  if (depth > 20) fail('invalid_body');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string' && value.length <= 16384) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value) && value.length <= 256) return value.map(item => jsonValue(item, depth + 1));
  if (!record(value) || Object.keys(value).length > 128) fail('invalid_body');
  const output = Object.create(null);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!('value' in descriptor) || ['__proto__', 'constructor', 'prototype', 'toJSON',
      'organization_id', 'organizationId', 'issuer_key', 'signing_key'].includes(key)) fail('invalid_body');
    output[key] = jsonValue(descriptor.value, depth + 1);
  }
  return output;
}
function prepare(operation, organizationId, args) {
  keys(args, ['id', 'query', 'body', 'idempotencyKey'], 'invalid_arguments');
  let path = operation.path.replace('{organization_id}', organizationId);
  if (path.includes('{id}')) {
    if (!identifier(args.id)) fail('invalid_resource_id');
    path = path.replace('{id}', args.id);
  } else if (args.id !== undefined) fail('unexpected_resource_id');
  const query = args.query ?? {};
  keys(query, operation.query, 'invalid_query');
  const search = new URLSearchParams();
  if (operation.organizationQuery) search.set('organization_id', organizationId);
  for (const [key, value] of Object.entries(query)) {
    if (typeof value !== 'string' || !value.length || value.length > 512 || /[\x00-\x1f\x7f]/.test(value)) fail('invalid_query');
    search.set(key, value);
  }
  if (search.size) path += `?${search}`;
  let payload;
  if (operation.fields !== undefined) {
    keys(args.body ?? {}, operation.fields, 'invalid_body');
    payload = Buffer.from(JSON.stringify(jsonValue(args.body ?? {})));
    if (payload.length > 65536) fail('request_too_large');
  } else if (args.body !== undefined) fail('unexpected_body');
  if (operation.idempotent) {
    if (typeof args.idempotencyKey !== 'string' || !/^[A-Za-z0-9_.-]{16,128}$/.test(args.idempotencyKey)) fail('idempotency_key_required');
  } else if (args.idempotencyKey !== undefined) fail('unexpected_idempotency_key');
  return { path, payload, idempotencyKey: args.idempotencyKey };
}
function decode(data, shape) {
  let value;
  try { value = JSON.parse(data); } catch { fail('invalid_json'); }
  if (shape === 'list') {
    if (Array.isArray(value)) return value;
    if (record(value) && Array.isArray(value.items)) return value.items;
    fail('invalid_response_shape');
  }
  if (!record(value)) fail('invalid_response_shape');
  return value;
}

/** Creates a server-only client. No arbitrary URL, headers, method or transport is accepted.
 * allowedOperations REPLACES the read-only default; it never grants a Gateway permission.
 * The Gateway must independently enforce key validity, tenant ownership and scopes.
 */
export function createGatewayClient(configuration) {
  keys(configuration, ['gatewayOrigin', 'organizationId', 'apiKey', 'allowedOperations',
    'ca', 'timeoutMs', 'maxResponseBytes'], 'invalid_configuration');
  if (typeof globalThis.window !== 'undefined') fail('server_only');
  const gatewayOrigin = origin(configuration.gatewayOrigin);
  const organizationId = configuration.organizationId;
  if (!identifier(organizationId)) fail('invalid_organization');
  const apiKey = configuration.apiKey;
  if (typeof apiKey !== 'string' || !/^[A-Za-z0-9._~-]{32,512}$/.test(apiKey)) fail('invalid_api_key');
  const allowed = configuration.allowedOperations ?? READ_OPERATIONS;
  if (!Array.isArray(allowed) || !allowed.length || allowed.some(name => typeof name !== 'string'
      || !Object.hasOwn(OPERATIONS, name)) || new Set(allowed).size !== allowed.length) fail('invalid_operations');
  const allowedSet = new Set(allowed);
  const timeoutMs = integer(configuration.timeoutMs ?? 15000, 50, 120000);
  const maxResponseBytes = integer(configuration.maxResponseBytes ?? 1048576, 128, 8388608);
  const ca = configuration.ca;
  if (ca !== undefined && (typeof ca !== 'string' || ca.length > 65536
      || !ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(ca))) fail('invalid_ca');

  return Object.freeze({
    async execute(name, args = {}) {
      if (!allowedSet.has(name)) fail('operation_not_allowed');
      const operation = OPERATIONS[name];
      const prepared = prepare(operation, organizationId, args);
      const url = new URL(prepared.path, gatewayOrigin);
      if (url.origin !== gatewayOrigin) fail('origin_mismatch');
      const headers = { Accept: 'application/json', 'Accept-Encoding': 'identity',
        'X-API-Key': apiKey, 'X-Organization-ID': organizationId };
      if (prepared.payload) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = prepared.payload.length;
      }
      if (prepared.idempotencyKey) headers['Idempotency-Key'] = prepared.idempotencyKey;
      return new Promise((resolve, reject) => {
        let settled = false;
        let timer;
        let req;
        const finish = (error, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (error) { reject(error); req?.destroy(); } else resolve(value);
        };
        try {
          // A fresh direct HTTPS agent avoids global proxy agents. Redirects are never followed.
          req = request(url, { method: operation.method, headers, agent: false,
            rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 16384,
            ...(ca === undefined ? {} : { ca }) }, res => {
            const status = res.statusCode ?? 0;
            res.on('error', () => finish(new GatewayError('transport_error')));
            res.on('aborted', () => finish(new GatewayError('transport_error')));
            if (status >= 300 && status < 400) return finish(new GatewayError('redirect_denied', status));
            if (status < 200 || status >= 300) return finish(new GatewayError('gateway_rejected', status));
            if (status === 204 && operation.response === 'optional') {
              res.resume();
              res.on('end', () => finish(null, null));
              return;
            }
            const type = String(res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
            if (!(type === 'application/json' || /^application\/[a-z0-9.+-]+\+json$/.test(type))
                || !['', 'identity'].includes(String(res.headers['content-encoding'] ?? ''))) {
              return finish(new GatewayError('invalid_content_type'));
            }
            const chunks = [];
            let size = 0;
            res.on('data', chunk => {
              size += chunk.length;
              if (size > maxResponseBytes) return finish(new GatewayError('response_too_large'));
              if (!settled) chunks.push(chunk);
            });
            res.on('end', () => {
              if (settled) return;
              try { finish(null, decode(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), operation.response)); }
              catch (error) { finish(error instanceof GatewayError ? error : new GatewayError('invalid_json')); }
            });
          });
          req.on('error', () => finish(new GatewayError('transport_error')));
          // Absolute deadline covers DNS, connection, TLS, headers and the whole body.
          timer = setTimeout(() => finish(new GatewayError('timeout')), timeoutMs);
          req.end(prepared.payload);
        } catch { finish(new GatewayError('transport_error')); }
      });
    },
  });
}
