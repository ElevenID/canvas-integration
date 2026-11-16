// SPDX-License-Identifier: AGPL-3.0-only
import { request } from 'node:https';
import { canvasOrigin, approvedPrivateAddresses, resolveAddress, pinnedLookup } from './canvas-rest-network.mjs';
import { exactRecord } from './canvas-rest-contract.mjs';
import { validateCanvasResourceLinkLaunch } from './canvas-lti-launch.mjs';

const configurationError = () => { throw new Error('invalid_lti_configuration'); };
function ascii(value, max = 255) {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value) || value.length > max) configurationError();
  return value;
}
function target(value) {
  ascii(value, 2048);
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || /[\\]/.test(value)) configurationError();
  return value;
}

// This is operator policy, never metadata obtained from an unsigned login or JWT.
export function canvasLtiTrustProfile(configuration) {
  try {
    exactRecord(configuration, ['canvasOrigin', 'trustProfile', 'environment', 'selfManagedOriginAllowlist'], 'invalid_lti_configuration');
    const origin = canvasOrigin(configuration.canvasOrigin), kind = configuration.trustProfile;
    let environment, issuer, sso;
    if (kind === 'hosted_global') {
      environment = configuration.environment;
      if (!['production', 'beta', 'test'].includes(environment) || configuration.selfManagedOriginAllowlist !== undefined) configurationError();
      const suffix = environment === 'production' ? '' : `.${environment}`;
      issuer = `https://canvas${suffix}.instructure.com`;
      sso = `https://sso${suffix}.canvaslms.com`;
      // Prevent obvious environment mistakes; custom hosted domains require an
      // explicit operator environment because hostname inference is insufficient.
      const host = new URL(origin).hostname;
      const inferred = /(?:^|\.)beta\.instructure\.com$/.test(host) ? 'beta'
        : /(?:^|\.)test\.instructure\.com$/.test(host) ? 'test'
        : /(?:^|\.)instructure\.com$/.test(host) ? 'production' : null;
      if (inferred !== null && inferred !== environment) configurationError();
    } else if (kind === 'self_managed_same_origin') {
      if (configuration.environment !== undefined) configurationError();
      const allowlist = configuration.selfManagedOriginAllowlist;
      if (!Array.isArray(allowlist) || !allowlist.length || allowlist.length > 32 ||
          !allowlist.map(value => canvasOrigin(value)).includes(origin)) configurationError();
      environment = 'self_managed'; issuer = origin; sso = origin;
    } else configurationError();
    return Object.freeze({ canvasOrigin: origin, trustProfile: kind, environment, issuer,
      authorizationEndpoint: `${sso}/api/lti/authorize_redirect`,
      jwksUri: `${sso}/api/lti/security/jwks`, tokenEndpoint: `${origin}/login/oauth2/token` });
  } catch { configurationError(); }
}

function readKeys(url, pinned, ca, signal) {
  return new Promise((resolve, reject) => {
    let req, settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) { reject(new Error('canvas_lti_platform_unavailable')); req?.destroy(); }
      else resolve(value);
    };
    try {
      req = request(url, { method: 'GET', agent: false, rejectUnauthorized: true,
        minVersion: 'TLSv1.2', maxHeaderSize: 16384, family: pinned.family, autoSelectFamily: false,
        lookup: pinnedLookup(url.hostname.replace(/^\[|\]$/g, ''), pinned), signal,
        headers: { Accept: 'application/json', 'Accept-Encoding': 'identity' },
        ...(ca === undefined ? {} : { ca }),
      }, response => {
        response.on('error', () => finish(true)); response.on('aborted', () => finish(true));
        if (response.statusCode !== 200) return finish(true); // No redirects or automatic retries.
        const countHeader = name => response.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === name).length;
        if (countHeader('content-type') !== 1 || countHeader('content-encoding') > 1 ||
            countHeader('content-length') > 1 || countHeader('link') !== 0) return finish(true);
        const parts = String(response.headers['content-type'] ?? '').toLowerCase().split(';').map(part => part.trim());
        if (!['application/json', 'application/jwk-set+json'].includes(parts[0]) ||
            parts.slice(1).some(part => !/^charset=(?:"?utf-8"?)$/.test(part)) ||
            !['', 'identity'].includes(String(response.headers['content-encoding'] ?? '')) ||
            response.headers.link !== undefined) return finish(true);
        const length = response.headers['content-length'];
        if (length !== undefined && (!/^\d{1,9}$/.test(length) || Number(length) > 131072)) return finish(true);
        const chunks = []; let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > 131072) return finish(true);
          if (!settled) chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          try { finish(false, new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
          catch { finish(true); }
        });
      });
      req.on('error', () => finish(true)); req.end();
    } catch { finish(true); }
  });
}

// Internal server-owned registration reader. This does not consume state, create
// a session, associate a Marty learner or admit an observation.
export function createCanvasLtiPlatformReader(configuration) {
  let profile, allowedPrivate, ca, timeoutMs, registration;
  try {
    if (typeof globalThis.window !== 'undefined') configurationError();
    exactRecord(configuration, ['canvasOrigin', 'trustProfile', 'environment', 'selfManagedOriginAllowlist',
      'clientId', 'deploymentId', 'targetLinkUri', 'trustedAdditionalAudiences',
      'allowedPrivateAddresses', 'ca', 'timeoutMs'], 'invalid_lti_configuration');
    profile = canvasLtiTrustProfile({ canvasOrigin: configuration.canvasOrigin, trustProfile: configuration.trustProfile,
      environment: configuration.environment, selfManagedOriginAllowlist: configuration.selfManagedOriginAllowlist });
    const audiences = configuration.trustedAdditionalAudiences ?? [];
    if (!Array.isArray(audiences) || audiences.length > 16) configurationError();
    registration = Object.freeze({ issuer: profile.issuer, clientId: ascii(configuration.clientId),
      deploymentId: ascii(configuration.deploymentId), targetLinkUri: target(configuration.targetLinkUri),
      trustedAdditionalAudiences: Object.freeze(audiences.map(value => ascii(value))) });
    allowedPrivate = approvedPrivateAddresses(configuration.allowedPrivateAddresses);
    ca = configuration.ca;
    if (ca !== undefined && (typeof ca !== 'string' || ca.length > 65536 ||
        !ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(ca))) configurationError();
    timeoutMs = configuration.timeoutMs ?? 15000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 120000) configurationError();
  } catch { configurationError(); }
  return Object.freeze({ profile,
    async validateResourceLink(input) {
      let token, nonce;
      try {
        exactRecord(input, ['token', 'nonce'], 'invalid_lti_request');
        token = input.token; nonce = input.nonce;
        if (typeof token !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token) || token.length > 65536 ||
            typeof nonce !== 'string' || !/^[\x21-\x7e]{32,512}$/.test(nonce)) throw new Error();
      } catch { throw new Error('invalid_lti_request'); }
      const deadline = performance.now() + timeoutMs;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        let keys;
        try {
          const url = new URL(profile.jwksUri);
          const pinned = await resolveAddress(url.origin, allowedPrivate, controller.signal);
          keys = await readKeys(url, pinned, ca, controller.signal);
          if (controller.signal.aborted || performance.now() >= deadline) throw new Error();
        } catch { throw new Error('canvas_lti_platform_unavailable'); }
        const result = validateCanvasResourceLinkLaunch({ token, jwksText: keys, expected: { ...registration, nonce },
          nowSeconds: Math.floor(Date.now() / 1000) });
        if (controller.signal.aborted || performance.now() >= deadline) throw new Error('canvas_lti_platform_unavailable');
        const finalNow = Math.floor(Date.now() / 1000);
        if (finalNow >= result.expiresAt || finalNow - result.issuedAt > 300 ||
            result.issuedAt > finalNow + 30 || (result.notBefore !== null && result.notBefore > finalNow)) {
          throw new Error('invalid_lti_launch');
        }
        return result;
      } finally { clearTimeout(timer); }
    },
  });
}
