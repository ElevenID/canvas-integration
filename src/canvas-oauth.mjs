// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes as secureRandomBytes } from 'node:crypto';
import { canvasOrigin } from './canvas-rest-network.mjs';
import { hashOAuthBrowserBinding, matchesOAuthBrowserBindingHash } from './oauth-browser-binding.mjs';

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
    'publicOrigin', 'completionUrl', 'repository', 'secretVault', 'provider', 'clock', 'randomBytes','requireConfiguredClient',
  ].includes(key))) fail('invalid_configuration');
  if (typeof globalThis.window !== 'undefined') fail('server_only');
  const publicOrigin = canvasOrigin(configuration.publicOrigin);
  const completionBase = fixedHttpsUrl(configuration.completionUrl, 'invalid_completion_url', true);
  requireMethods(configuration.repository, [
    'getPlatform', 'connection', 'saveAuthorization', 'markAuthorizationPending',
    'consumeAuthorizationAttempt', 'beginAuthorizationExchange', 'requireAuthorizationReconciliation',
    'cancelAuthorization', 'publishAuthorizationConnection', 'markConnected', 'markReauthorizationRequired',
  ], 'invalid_repository');
  requireMethods(configuration.secretVault, ['metadata', 'get', 'stageAuthorizationResult'], 'invalid_secret_vault');
  requireMethods(configuration.provider, ['exchange'], 'invalid_provider');
  const repository = configuration.repository;
  if(configuration.requireConfiguredClient!==undefined && typeof configuration.requireConfiguredClient!=='boolean') fail('invalid_configuration');
  if(configuration.requireConfiguredClient===true) requireMethods(repository,['configuredClient'],'invalid_repository');
  const vault = configuration.secretVault;
  const provider = configuration.provider;
  const clock = configuration.clock ?? Date.now;
  const random = configuration.randomBytes ?? secureRandomBytes;
  if (typeof clock !== 'function' || typeof random !== 'function') fail('invalid_configuration');
  const redirectUri = callbackUrl(publicOrigin);

  async function reconcile(authorization) {
    try { await repository.requireAuthorizationReconciliation(
      authorization.authorizationId, authorization.organizationId, authorization.platformId,
    ); } catch { /* durable attempt remains; never repeat the external exchange */ }
  }

  return Object.freeze({
    async start(input) {
      if (!isRecord(input) || Object.keys(input).some(key => ![
        'organizationId', 'platformId', 'clientId', 'clientSecretRef', 'capabilities', 'browserBinding',
      ].includes(key))) fail('invalid_start_request');
      const browserBindingHash=hashOAuthBrowserBinding(input.browserBinding);
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
      const configured=configuration.requireConfiguredClient===true
        ?await repository.configuredClient(organizationId,platformId,platform.configVersion):null;
      if(configuration.requireConfiguredClient===true && !configured) fail('client_configuration_required');
      const clientId=configured?configured.clientId:input.clientId;
      const clientSecretRef=configured?configured.clientSecretRef:input.clientSecretRef;
      if(configured && ((input.clientId!==undefined && input.clientId!==clientId)
        || (input.clientSecretRef!==undefined && input.clientSecretRef!==clientSecretRef))) fail('client_configuration_changed');
      if (!safeText(clientId, 512) || clientId.trim() !== clientId) fail('invalid_client_id');
      if (!safeText(clientSecretRef, 256)) fail('invalid_client_secret_reference');
      const metadata = await vault.metadata(organizationId, clientSecretRef);
      if (!isRecord(metadata) || metadata.organizationId !== organizationId || metadata.platformId !== platformId || metadata.enabled !== true
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
        clientId,
        clientSecretRef,
        stateHash: stateHash(state),
        browserBindingHash,
        capabilities,
        scopes,
        redirectUri,
        expiresAt: now + AUTHORIZATION_TTL_MS,
        createdAt: now,
      });
      const url = authorizationUrl(origin, clientId, redirectUri, state, scopes);
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
      if (!isRecord(input) || Object.keys(input).some(key => !['state', 'code', 'error', 'browserBinding'].includes(key))
          || typeof input.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.state)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', undefined, 'oauth_state_invalid') });
      }
      let browserBindingHash;
      try {browserBindingHash=hashOAuthBrowserBinding(input.browserBinding);} catch {
        return Object.freeze({location:completionLocation(completionBase,'error',undefined,'oauth_state_invalid')});
      }
      const now = clock();
      if (!Number.isSafeInteger(now) || now <= 0) fail('clock_unavailable');
      // Repository must compare both hashes atomically before consuming state.
      let authorization;
      try { authorization = await repository.consumeAuthorizationAttempt(stateHash(input.state), browserBindingHash); }
      catch {
        return Object.freeze({ location: completionLocation(completionBase, 'error', undefined, 'oauth_connection_reconciliation_required') });
      }
      if (!isRecord(authorization) || !matchesOAuthBrowserBindingHash(authorization.browserBindingHash,input.browserBinding)
          || authorization.stateHash !== stateHash(input.state) || authorization.authorizationId !== authorization.stateHash
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
      if (!isRecord(metadata) || metadata.organizationId !== organizationId || metadata.platformId !== platformId || metadata.enabled !== true
          || metadata.provider !== 'canvas' || metadata.purpose !== 'oauth_client_secret') {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      const clientSecret = await vault.get(organizationId, authorization.clientSecretRef, {platformId,provider:'canvas',purpose:'oauth_client_secret'});
      if (!safeText(clientSecret, 4096)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_configuration_changed') });
      }
      if (await repository.connection(organizationId, platformId)) {
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_authorization_conflict') });
      }
      // A successful, committed begin is mandatory before sending the code.
      // A lost begin reply may mean exchanging committed: do not call Canvas.
      let begun;
      try { begun = await repository.beginAuthorizationExchange(authorization.authorizationId, organizationId, platformId); }
      catch {
        await reconcile(authorization);
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_connection_reconciliation_required') });
      }
      if (begun !== true) {
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
        await reconcile(authorization);
        if (typeof repository.recordAuthorizationError === 'function') {
          try { await repository.recordAuthorizationError(organizationId, platformId, 'oauth_token_exchange_failed'); } catch { /* best-effort */ }
        }
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_token_exchange_failed') });
      }
      const expiresAt = tokenExpiry(now, tokenBundle.expiresInSeconds);
      // The vault commits both ciphertexts and attempt references atomically.
      // On any failure the outcome may be unknown; preserve custody and never
      // delete tokens, revoke inline or repeat exchange from this callback.
      try {
        const refs = await vault.stageAuthorizationResult(authorization, tokenBundle, expiresAt);
        if (!safeText(refs?.accessTokenRef, 256) || refs.accessTokenRef === authorization.clientSecretRef
            || (refs.refreshTokenRef !== null && (!safeText(refs.refreshTokenRef, 256)
              || refs.refreshTokenRef === refs.accessTokenRef || refs.refreshTokenRef === authorization.clientSecretRef))) {
          fail('secret_store_failed');
        }
      } catch {
        await reconcile(authorization);
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_connection_reconciliation_required') });
      }
      let published;
      try { published = await repository.publishAuthorizationConnection(authorization.authorizationId, organizationId, platformId); }
      catch {
        await reconcile(authorization);
        return Object.freeze({ location: completionLocation(completionBase, 'error', platformId, 'oauth_connection_reconciliation_required') });
      }
      if (published !== true) {
        await reconcile(authorization);
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
