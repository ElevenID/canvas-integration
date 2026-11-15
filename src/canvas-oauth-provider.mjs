// SPDX-License-Identifier: AGPL-3.0-only
import { request } from 'node:https';
import {
  approvedPrivateAddresses, canvasOrigin, pinnedLookup, resolveAddress,
} from './canvas-rest-network.mjs';

export class CanvasOAuthProviderError extends Error {
  constructor(code, retryAfterSeconds) {
    super(`Canvas OAuth provider failed: ${code}`);
    this.name = 'CanvasOAuthProviderError';
    this.code = code;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}
const fail = code => { throw new CanvasOAuthProviderError(code); };
function boundedInteger(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}
function retryAfter(value) {
  if (typeof value !== 'string') return undefined;
  if (/^\d{1,6}$/.test(value)) return Math.min(Number(value), 3600);
  return undefined;
}
function validateTokenResponse(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || typeof value.access_token !== 'string' || value.access_token.length < 1
      || value.access_token.length > 4096 || /[\u0000-\u001f\u007f-\u009f]/.test(value.access_token)
      || (value.refresh_token !== undefined && value.refresh_token !== null
        && (typeof value.refresh_token !== 'string' || value.refresh_token.length < 1
          || value.refresh_token.length > 4096 || /[\u0000-\u001f\u007f-\u009f]/.test(value.refresh_token)))
      || (value.expires_in !== undefined && value.expires_in !== null
        && (!Number.isSafeInteger(value.expires_in) || value.expires_in < 0 || value.expires_in > 315360000))
      || (value.token_type !== undefined && String(value.token_type).toLowerCase() !== 'bearer')) {
    fail('invalid_token_response');
  }
  return Object.freeze({
    accessToken: value.access_token,
    ...(value.refresh_token ? { refreshToken: value.refresh_token } : {}),
    ...(value.expires_in === undefined ? {} : { expiresInSeconds: value.expires_in }),
  });
}
function requestToken(origin, form, options, signal, pinned) {
  const url = new URL('/login/oauth2/token', origin);
  const payload = Buffer.from(new URLSearchParams(form).toString(), 'utf8');
  return new Promise((resolve, reject) => {
    let settled = false;
    let req;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) { reject(error); req?.destroy(); } else resolve(value);
    };
    try {
      req = request(url, {
        method: 'POST',
        agent: false,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        maxHeaderSize: 16384,
        family: pinned.family,
        autoSelectFamily: false,
        lookup: pinnedLookup(url.hostname.replace(/^\[|\]$/g, ''), pinned),
        signal,
        headers: {
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': payload.length,
        },
        ...(options.ca === undefined ? {} : { ca: options.ca }),
      }, response => {
        response.on('error', () => finish(new CanvasOAuthProviderError(signal.aborted ? 'timeout' : 'transport_error')));
        response.on('aborted', () => finish(new CanvasOAuthProviderError('transport_error')));
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) return finish(new CanvasOAuthProviderError('redirect_denied'));
        if (status !== 200) {
          const code = status === 429 ? 'rate_limited'
            : status === 400 || status === 401 || status === 403 ? 'provider_rejected'
              : status >= 500 ? 'provider_unavailable' : 'unexpected_status';
          return finish(new CanvasOAuthProviderError(code, status === 429
            ? retryAfter(response.headers['retry-after']) : undefined));
        }
        const type = String(response.headers['content-type'] ?? '').toLowerCase().split(';');
        if (!['application/json', 'application/json+canvas-string-ids'].includes(type[0].trim())
            || type.slice(1).some(part => !/^\s*charset=(?:"?utf-8"?)\s*$/.test(part))
            || !['', 'identity'].includes(String(response.headers['content-encoding'] ?? '').toLowerCase())) {
          return finish(new CanvasOAuthProviderError('invalid_content_type'));
        }
        const chunks = [];
        let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > options.maxResponseBytes) return finish(new CanvasOAuthProviderError('response_too_large'));
          if (!settled) chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          let value;
          try {
            value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
          } catch { return finish(new CanvasOAuthProviderError('invalid_json')); }
          try { finish(null, validateTokenResponse(value)); }
          catch (error) { finish(error instanceof CanvasOAuthProviderError ? error : new CanvasOAuthProviderError('invalid_token_response')); }
        });
      });
      req.on('error', () => finish(new CanvasOAuthProviderError(signal.aborted ? 'timeout' : 'transport_error')));
      req.end(payload);
    } catch { finish(new CanvasOAuthProviderError(signal.aborted ? 'timeout' : 'transport_error')); }
  });
}

/** Canvas OAuth token exchange. It owns only Canvas HTTPS and never sees Gateway credentials.
 * Canvas origins are validated and DNS-pinned per request; redirects and retries are disabled.
 */
export function createCanvasOAuthProvider(configuration) {
  if (configuration === null || typeof configuration !== 'object' || Array.isArray(configuration)
      || Object.keys(configuration).some(key => !['allowedPrivateAddresses', 'ca', 'timeoutMs', 'maxResponseBytes'].includes(key))) {
    fail('invalid_configuration');
  }
  if (typeof globalThis.window !== 'undefined') fail('server_only');
  const allowedPrivateAddresses = approvedPrivateAddresses(configuration.allowedPrivateAddresses);
  const timeoutMs = boundedInteger(configuration.timeoutMs ?? 15000, 50, 120000, 'invalid_limits');
  const maxResponseBytes = boundedInteger(configuration.maxResponseBytes ?? 65536, 128, 1048576, 'invalid_limits');
  const ca = configuration.ca;
  if (ca !== undefined && (typeof ca !== 'string' || ca.length > 65536
      || !ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(ca))) fail('invalid_ca');
  const options = Object.freeze({ ca, maxResponseBytes });

  async function execute(input, grantType) {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) fail('invalid_request');
    const origin = canvasOrigin(input.canvasOrigin);
    const required = grantType === 'authorization_code'
      ? ['clientId', 'clientSecret', 'code', 'redirectUri']
      : ['clientId', 'clientSecret', 'refreshToken'];
    if (required.some(key => typeof input[key] !== 'string' || !input[key] || input[key].length > 4096
        || /[\u0000-\u001f\u007f-\u009f]/.test(input[key]))) fail('invalid_request');
    const form = {
      grant_type: grantType,
      client_id: input.clientId,
      client_secret: input.clientSecret,
      ...(grantType === 'authorization_code'
        ? { code: input.code, redirect_uri: input.redirectUri }
        : { refresh_token: input.refreshToken }),
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const pinned = await resolveAddress(origin, allowedPrivateAddresses, controller.signal);
      if (controller.signal.aborted) fail('timeout');
      return await requestToken(origin, form, options, controller.signal, pinned);
    } catch (error) {
      if (error instanceof CanvasOAuthProviderError) throw error;
      if (controller.signal.aborted) fail('timeout');
      fail('transport_error');
    } finally {
      clearTimeout(timer);
    }
  }

  return Object.freeze({
    exchange(input) { return execute(input, 'authorization_code'); },
    refresh(input) { return execute(input, 'refresh_token'); },
  });
}
