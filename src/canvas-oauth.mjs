// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes as secureRandomBytes } from 'node:crypto';
import { canvasOrigin } from './canvas-rest-network.mjs';

const AUTHORIZATION_TTL_MS = 10 * 60 * 1000;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const TOKEN = /^[A-Za-z0-9._~+/-]{16,4096}={0,2}$/;
const CAPABILITY_SCOPES = Object.freeze({
  catalog: [
    'url:GET|/api/v1/courses',
    'url:GET|/api/v1/courses/:course_id/assignments',
    'url:GET|/api/v1/courses/:course_id/modules',
  ],
  native_activity_scores: [
    'url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id',
    'url:GET|/api/v1/courses/:course_id/assignments/:id',
  ],
  course_completion: ['url:GET|/api/v1/courses/:course_id/users/:user_id/progress'],
  module_completion: ['url:GET|/api/v1/courses/:course_id/modules/:id'],
  background_roster: [
    'url:GET|/api/v1/courses/:course_id/users',
    'url:GET|/api/v1/courses/:course_id/enrollments',
    'url:GET|/api/v1/courses/:course_id/bulk_user_progress',
  ],
});
const CAPABILITY_ALIASES = Object.freeze({
  'scope_catalog.read': 'catalog',
  'assignment_submission.read': 'native_activity_scores',
  'quiz_submission.read': 'native_activity_scores',
  'course_progress.read': 'course_completion',
  'module_progress.read': 'module_completion',
});

export class CanvasOAuthError extends Error {
  constructor(code) {
    super(`Canvas OAuth lifecycle failed: ${code}`);
    this.name = 'CanvasOAuthError';
    this.code = code;
  }
}
const fail = code => { throw new CanvasOAuthError(code); };
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const validId = value => typeof value === 'string' && IDENTIFIER.test(value);
const safeText = (value, max) => typeof value === 'string' && value.length > 0
  && value.length <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(value);

function requireMethods(value, methods, code) {
  if (!isRecord(value) || methods.some(name => typeof value[name] !== 'function')) fail(code);
}
function normalizeCapabilities(values) {
  if (!Array.isArray(values) || values.length > 32) fail('invalid_capabilities');
  const result = [];
  for (const raw of values) {
    if (typeof raw !== 'string') fail('invalid_capabilities');
    const trimmed = raw.trim();
    const candidate = CAPABILITY_ALIASES[trimmed] ?? trimmed;
    if (!candidate || !Object.hasOwn(CAPABILITY_SCOPES, candidate)) fail('unsupported_capability');
    if (!result.includes(candidate)) result.push(candidate);
  }
  if (!result.length) fail('capabilities_required');
  return Object.freeze(result);
}
function scopesForCapabilities(capabilities) {
  const result = [];
  for (const capability of capabilities) {
    for (const scope of CAPABILITY_SCOPES[capability]) if (!result.includes(scope)) result.push(scope);
  }
  return Object.freeze(result);
}
function stateHash(state) {
  return createHash('sha256').update(state, 'utf8').digest('hex');
}
function fixedHttpsUrl(value, code, allowPath) {
  if (typeof value !== 'string' || value !== value.trim() || /[\s\\]/.test(value)) fail(code);
  let parsed;
  try { parsed = new URL(value); } catch { fail(code); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash
      || parsed.hostname.endsWith('.') || (!allowPath && (parsed.pathname !== '/' || parsed.search))) fail(code);
  return parsed;
}
function callbackUrl(publicOrigin) {
  return new URL('/oauth/callback', publicOrigin).href;
}
function authorizationUrl(platformOrigin, clientId, redirectUri, state, scopes) {
  const endpoint = new URL('/login/oauth2/auth', platformOrigin);
  endpoint.searchParams.set('client_id', clientId);
  endpoint.searchParams.set('response_type', 'code');
  endpoint.searchParams.set('redirect_uri', redirectUri);
  endpoint.searchParams.set('state', state);
  endpoint.searchParams.set('scope', scopes.join(' '));
  return endpoint.href;
}
function tokenExpiry(now, seconds) {
  if (seconds === undefined || seconds === null) return null;
  if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > 315360000) fail('invalid_token_expiry');
  const expiresAt = now + seconds * 1000;
  if (!Number.isSafeInteger(expiresAt)) fail('invalid_token_expiry');
  return expiresAt;
}
function completionLocation(base, outcome, platformId, errorCode) {
  const result = new URL(base.href);
  result.searchParams.set('outcome', outcome);
  if (platformId) result.searchParams.set('platform_id', platformId);
  if (errorCode) result.searchParams.set('error_code', errorCode);
  return result.href;
}
function validateTokenBundle(bundle) {
  if (!isRecord(bundle) || !TOKEN.test(bundle.accessToken)
      || (bundle.refreshToken !== undefined && bundle.refreshToken !== null && !TOKEN.test(bundle.refreshToken))
      || (bundle.expiresInSeconds !== undefined && bundle.expiresInSeconds !== null
          && (!Number.isSafeInteger(bundle.expiresInSeconds) || bundle.expiresInSeconds < 0
            || bundle.expiresInSeconds > 315360000))) fail('invalid_provider_response');
}

export function createCanvasOAuthLifecycle(configuration) {
  if (!isRecord(configuration) || Object.keys(configuration).some(key => ![
    'publicOrigin', 'completionUrl', 'repository', 'secretVault', 'provider', 'clock', 'randomBytes',
  ].includes(key))) fail('invalid_configuration');
  if (typeof globalThis.window !== 'undefined') fail('server_only');
  const publicOrigin = canvasOrigin(configuration.publicOrigin);
  const completionBase = fixedHttpsUrl(configuration.completionUrl, 'invalid_completion_url', true);
  requireMethods(configuration.repository, [
    'getPlatform', 'connection', 'saveAuthorization', 'markAuthorizationPending',
    'consumeAuthorization', 'cancelAuthorization', 'publishConnection', 'markConnected', 'markReauthorizationRequired',
  ], 'invalid_repository');
  requireMethods(configuration.secretVault, ['metadata', 'get', 'put', 'delete'], 'invalid_secret_vault');
  requireMethods(configuration.provider, ['exchange'], 'invalid_provider');
  const repository = configuration.repository;
  const vault = configuration.secretVault;
  const provider = configuration.provider;
  const clock = configuration.clock ?? Date.now;
  const random = configuration.randomBytes ?? secureRandomBytes;
  if (typeof clock !== 'function' || typeof random !== 'function') fail('invalid_configuration');
  const redirectUri = callbackUrl(publicOrigin);

  async function cleanupTokens(organizationId, references) {
    for (const reference of references) {
      if (typeof reference !== 'string' || !reference) continue;
      try { await vault.delete(organizationId, reference); } catch { /* cleanup is best-effort */ }
    }
  }
  async function bestEffortRevoke(platformOrigin, accessToken) {
    if (typeof provider.revoke !== 'function') return;
    try { await provider.revoke({ canvasOrigin: platformOrigin, accessToken }); } catch { /* never expose provider response */ }
  }

  return Object.freeze({
    async start(input) {
      if (!isRecord(input) || Object.keys(input).some(key => ![
        'organizationId', 'platformId', 'clientId', 'clientSecretRef', 'capabilities',
      ].includes(key))) fail('invalid_start_request');
      const { organizationId, platformId } = input;
      if (!validId(organizationId) || !validId(platformId)) fail('invalid_tenant_or_platform');
      const platform = await repository.getPlatform(organizationId, platformId);
      if (!isRecord(platform) || platform.organizationId !== organizationId
          || platform.id !== platformId || platform.archived === true || platform.enabled !== true) {
        fail('platform_unavailable');
      }
      const origin = canvasOrigin(platform.canvasOrigin);
      if (!Number.isSafeInteger(platform.configVersion) || platform.configVersion < 1) fail('invalid_platform_config');
      if (await repository.connection(organizationId, platformId)) fail('connection_exists');
      if (!safeText(input.clientId, 512) || input.clientId.trim() !== input.clientId) fail('invalid_client_id');
      if (!safeText(input.clientSecretRef, 256)) fail('invalid_client_secret_reference');
      const metadata = await vault.metadata(organizationId, input.clientSecretRef);
      if (!isRecord(metadata) || metadata.organizationId !== organizationId || metadata.enabled !== true
          || metadata.provider !== 'canvas' || metadata.purpose !== 'oauth_client_secret') fail('client_secret_unavailable');
      const capabilities = normalizeCapabilities(input.capabilities);
      const scopes = scopesForCapabilities(capabilities);
      const bytes = random(32);
      if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('secure_random_unavailable');
      const state = bytes.toString('base64url');
      const now = clock();
      if (!Number.isSafeInteger(now) || now <= 0) fail('clock_unavailable');
      const authorization = Object.freeze({
        authorizationId: stateHash(state),
        organizationId,
        platformId,
        canvasOrigin: origin,
        platformConfigVersion: platform.configVersion,
        clientId: input.clientId,
        clientSecretRef: input.clientSecretRef,
        stateHash: stateHash(state),
        capabilities,
        scopes,
        redirectUri,
        expiresAt: now + AUTHORIZATION_TTL_MS,
        createdAt: now,
      });
      const url = authorizationUrl(origin, input.clientId, redirectUri, state, scopes);
      const saved = await repository.saveAuthorization(authorization);
      if (saved !== true) fail('authorization_store_conflict');
      const patched = await repository.markAuthorizationPending(
        organizationId, platformId, platform.configVersion, authorization.authorizationId,
      );
      if (patched !== true) {
        try { await repository.cancelAuthorization(authorization.stateHash); } catch { /* expires after the short authorization TTL */ }
        fail('platform_configuration_changed');
      }
      return Object.freeze({ authorizationUrl: url, redirectUri, scopes });
    },

    async callback(input) {
      if (!isRecord(input) || Object.keys(input).some(key => !['state', 'code', 'error'].includes(key))
          || typeof input.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.state)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', undefined, 'oauth_state_invalid') });
      }
      const now = clock();
      if (!Number.isSafeInteger(now) || now <= 0) fail('clock_unavailable');
      const authorization = await repository.consumeAuthorization(stateHash(input.state), now);
      if (!isRecord(authorization) || authorization.stateHash !== stateHash(input.state)
          || !Number.isSafeInteger(authorization.expiresAt) || authorization.expiresAt <= now) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', undefined, 'oauth_state_invalid') });
      }
      let capabilities;
      let scopes;
      try {
        capabilities = normalizeCapabilities(authorization.capabilities);
        scopes = scopesForCapabilities(capabilities);
      } catch {
        return Object.freeze({ location: completionLocation(completionBase, 'error', authorization.platformId, 'oauth_configuration_changed') });
      }
      if (JSON.stringify(capabilities) !== JSON.stringify(authorization.capabilities)
          || JSON.stringify(scopes) !== JSON.stringify(authorization.scopes)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', authorization.platformId, 'oauth_configuration_changed') });
      }
      const platformId = authorization.platformId;
      const organizationId = authorization.organizationId;
      if (!validId(platformId) || !validId(organizationId)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', undefined, 'oauth_platform_invalid') });
      }
      const platform = await repository.getPlatform(organizationId, platformId);
      if (!isRecord(platform) || platform.organizationId !== organizationId || platform.id !== platformId
          || platform.archived === true || platform.enabled !== true) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_platform_invalid') });
      }
      const origin = canvasOrigin(platform.canvasOrigin);
      if (origin !== authorization.canvasOrigin || platform.configVersion !== authorization.platformConfigVersion
          || authorization.redirectUri !== redirectUri) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      const code = typeof input.code === 'string' ? input.code.trim() : '';
      if ((typeof input.error === 'string' && input.error.trim()) || !safeText(code, 4096)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_authorization_denied') });
      }
      const metadata = await vault.metadata(organizationId, authorization.clientSecretRef);
      if (!isRecord(metadata) || metadata.organizationId !== organizationId || metadata.enabled !== true
          || metadata.provider !== 'canvas' || metadata.purpose !== 'oauth_client_secret') {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      const clientSecret = await vault.get(organizationId, authorization.clientSecretRef);
      if (!safeText(clientSecret, 4096)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      if (await repository.connection(organizationId, platformId)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_authorization_conflict') });
      }
      let tokenBundle;
      try {
        tokenBundle = await provider.exchange({
          canvasOrigin: origin,
          clientId: authorization.clientId,
          clientSecret,
          code,
          redirectUri: authorization.redirectUri,
        });
        validateTokenBundle(tokenBundle);
      } catch {
        if (typeof repository.recordAuthorizationError === 'function') {
          try { await repository.recordAuthorizationError(organizationId, platformId, 'oauth_token_exchange_failed'); } catch { /* best-effort */ }
        }
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_token_exchange_failed') });
      }
      const expiresAt = tokenExpiry(now, tokenBundle.expiresInSeconds);
      const references = [];
      let connection;
      try {
        const accessRef = await vault.put(organizationId, {
          platformId, provider: 'canvas', purpose: 'oauth_access_token',
        }, tokenBundle.accessToken);
        if (!safeText(accessRef, 256) || accessRef === authorization.clientSecretRef) fail('secret_store_failed');
        references.push(accessRef);
        let refreshRef = null;
        if (tokenBundle.refreshToken) {
          refreshRef = await vault.put(organizationId, {
            platformId, provider: 'canvas', purpose: 'oauth_refresh_token',
          }, tokenBundle.refreshToken);
          if (!safeText(refreshRef, 256) || references.includes(refreshRef)
              || refreshRef === authorization.clientSecretRef) fail('secret_store_failed');
          references.push(refreshRef);
        }
        connection = Object.freeze({
          organizationId, platformId, canvasOrigin: origin,
          platformConfigVersion: authorization.platformConfigVersion,
          clientId: authorization.clientId, clientSecretRef: authorization.clientSecretRef,
          capabilities: authorization.capabilities, scopes: authorization.scopes,
          accessTokenRef: accessRef, refreshTokenRef: refreshRef, tokenExpiresAt: expiresAt,
          status: 'connected', createdAt: now, updatedAt: now,
        });
      } catch {
        await cleanupTokens(organizationId, references);
        await bestEffortRevoke(origin, tokenBundle.accessToken);
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_secret_storage_failed') });
      }

      // A failed publication acknowledgment has an unknown commit outcome.
      // Preserve token refs for reconciliation; deleting them could break a committed connection.
      let published;
      try {
        published = await repository.publishConnection(connection, authorization.platformConfigVersion);
      } catch {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_connection_reconciliation_required') });
      }
      if (published !== true) {
        await cleanupTokens(organizationId, references);
        await bestEffortRevoke(origin, tokenBundle.accessToken);
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_authorization_conflict') });
      }

      let connected = false;
      try {
        connected = await repository.markConnected(
          organizationId, platformId, authorization.platformConfigVersion,
          authorization.clientId, authorization.capabilities, authorization.scopes,
        );
      } catch { /* connection is durable; mark it for reauthorization below */ }
      if (connected !== true) {
        if (typeof repository.markReauthorizationRequired === 'function') {
          try { await repository.markReauthorizationRequired(organizationId, platformId, now); } catch { /* reconciliation required */ }
        }
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      return Object.freeze({ location: completionLocation(completionBase, 'connected', platformId) });
    },
  });
}

export const CANVAS_OAUTH_AUTHORIZATION_TTL_MS = AUTHORIZATION_TTL_MS;
