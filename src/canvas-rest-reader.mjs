// SPDX-License-Identifier: AGPL-3.0-only
import { request } from 'node:https';
import { CanvasReadError, fail, exactRecord, prepareRequirement, validateSubmission, normalizeObservation } from './canvas-rest-contract.mjs';
import { canvasOrigin, approvedPrivateAddresses, resolveAddress, pinnedLookup } from './canvas-rest-network.mjs';

function limit(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('invalid_limits');
  return value;
}
function retryAfter(value) {
  if (typeof value !== 'string') return undefined;
  if (/^\d{1,10}$/.test(value)) return Math.min(Number(value), 86400);
  if (/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) {
    const date = Date.parse(value);
    if (Number.isFinite(date)) return Math.min(86400, Math.max(0, Math.ceil((date - Date.now()) / 1000)));
  }
  return undefined;
}
function readJson(url, accessToken, ca, pinned, signal, maxBytes) {
  return new Promise((resolve, reject) => {
    let req;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) { reject(error); req?.destroy(); } else resolve(value);
    };
    try {
      req = request(url, {
        method: 'GET', agent: false, rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 16384,
        family: pinned.family, autoSelectFamily: false,
        lookup: pinnedLookup(url.hostname.replace(/^\[|\]$/g, ''), pinned), signal,
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json+canvas-string-ids',
          'Accept-Encoding': 'identity' },
        ...(ca === undefined ? {} : { ca }),
      }, response => {
        response.on('error', () => finish(new CanvasReadError(signal.aborted ? 'timeout' : 'transport_error')));
        response.on('aborted', () => finish(new CanvasReadError('transport_error')));
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) return finish(new CanvasReadError('redirect_denied', status));
        if (status !== 200) {
          const code = ({ 401: 'reauthorization_required', 403: 'access_denied', 404: 'resource_unavailable', 429: 'rate_limited' })[status]
            ?? (status >= 500 ? 'provider_unavailable' : 'unexpected_status');
          return finish(new CanvasReadError(code, status, status === 429 ? retryAfter(response.headers['retry-after']) : undefined));
        }
        const type = String(response.headers['content-type'] ?? '').toLowerCase();
        const parts = type.split(';').map(part => part.trim());
        if (!['application/json', 'application/json+canvas-string-ids'].includes(parts[0])
            || parts.slice(1).some(part => !/^charset=(?:"?utf-8"?)$/.test(part))
            || !['', 'identity'].includes(String(response.headers['content-encoding'] ?? ''))) return finish(new CanvasReadError('invalid_content_type'));
        if (response.headers.link !== undefined) return finish(new CanvasReadError('unexpected_pagination'));
        const chunks = [];
        let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > maxBytes) return finish(new CanvasReadError('response_too_large'));
          if (!settled) chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          try {
            const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
            if (value === null || typeof value !== 'object' || Array.isArray(value)) return finish(new CanvasReadError('invalid_payload'));
            finish(null, value);
          } catch { finish(new CanvasReadError('invalid_json')); }
        });
      });
      req.on('error', () => finish(new CanvasReadError(signal.aborted ? 'timeout' : 'transport_error')));
      req.end();
    } catch { finish(new CanvasReadError(signal.aborted ? 'timeout' : 'transport_error')); }
  });
}
/** Canvas-side read-only provider. Its token is not an ElevenID credential.
 * No arbitrary URLs, HTTP methods, transport hooks, persistence or issuance calls.
 * Bind user IDs from a verified launch/server-owned mapping before calling.
 */
export function createCanvasRestReader(configuration) {
  exactRecord(configuration, ['canvasOrigin', 'accessToken', 'ca', 'allowedPrivateAddresses', 'timeoutMs', 'maxResponseBytes'], 'invalid_configuration');
  if (typeof globalThis.window !== 'undefined') fail('server_only');
  const origin = canvasOrigin(configuration.canvasOrigin);
  const accessToken = configuration.accessToken;
  if (typeof accessToken !== 'string' || !/^[A-Za-z0-9._~+/-]{16,4096}={0,2}$/.test(accessToken)) fail('invalid_access_token');
  const allowedPrivate = approvedPrivateAddresses(configuration.allowedPrivateAddresses);
  const timeoutMs = limit(configuration.timeoutMs ?? 15000, 50, 120000);
  const maxBytes = limit(configuration.maxResponseBytes ?? 1048576, 128, 8388608);
  const ca = configuration.ca;
  if (ca !== undefined && (typeof ca !== 'string' || ca.length > 65536
      || !ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(ca))) fail('invalid_ca');
  return Object.freeze({
    async readRequirement(input) {
      const plan = prepareRequirement(input);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        // Resolve once per complete observation, validate all answers, and pin both reads.
        const pinned = await resolveAddress(origin, allowedPrivate, controller.signal);
        const record = await readJson(new URL(plan.path, origin), accessToken, ca, pinned, controller.signal, maxBytes);
        let assignment;
        if (plan.assignmentPath) {
          validateSubmission(record, plan.scope);
          assignment = await readJson(new URL(plan.assignmentPath, origin), accessToken, ca, pinned, controller.signal, maxBytes);
        }
        if (controller.signal.aborted) fail('timeout');
        return normalizeObservation(plan, record, assignment, origin);
      } finally { clearTimeout(timer); }
    },
  });
}

export { CanvasReadError };
