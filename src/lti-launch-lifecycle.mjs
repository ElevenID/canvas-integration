// SPDX-License-Identifier: AGPL-3.0-only
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { exactRecord } from './canvas-rest-contract.mjs';
import { canvasOrigin, approvedPrivateAddresses } from './canvas-rest-network.mjs';
import { createCanvasLtiPlatformReader } from './canvas-lti-platform.mjs';

const fail = code => { throw new Error(code); };
const digest = value => createHash('sha256').update(value).digest('hex');
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const proof = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
  && Buffer.from(value, 'base64url').toString('base64url') === value;
function hint(value, required = false) {
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'string' || !value.length || !value.isWellFormed() || Buffer.byteLength(value) > 8192 ||
      /[\x00-\x1f\x7f]/.test(value)) fail('invalid_lti_request');
  return value;
}
function stateRequest(input, fields) {
  exactRecord(input, fields, 'invalid_lti_request');
  if (!uuid(input.registrationId) || !proof(input.state)) fail('invalid_lti_request');
  return digest(input.state);
}
function live(context) {
  const { state, registration: r, nowMs } = context;
  return r.enabled && r.platformEnabled && !r.platformArchived && state.expiresAtMs > nowMs &&
    state.registrationVersion === r.version && state.platformVersion === r.platformVersion;
}
function matchesProof(saved, candidate) {
  return proof(candidate) && timingSafeEqual(Buffer.from(saved, 'hex'), Buffer.from(digest(candidate), 'hex'));
}

// Protocol lifecycle only. The production composition must supply the actual
// connector repository; no network/verification replacement hook is accepted.
export function createLtiLaunchLifecycle(configuration) {
  exactRecord(configuration, ['repository','publicOrigin','platformPolicy'], 'invalid_lti_lifecycle');
  const repository = configuration.repository;
  let origin;
  try { origin = new URL(configuration.publicOrigin); } catch { fail('invalid_lti_lifecycle'); }
  if (typeof globalThis.window !== 'undefined' || origin.protocol !== 'https:' || origin.origin !== configuration.publicOrigin ||
      !['registration','context','begin','stage','confirm'].every(name => typeof repository?.[name] === 'function')) fail('invalid_lti_lifecycle');
  const policy = configuration.platformPolicy ?? {};
  exactRecord(policy, ['selfManagedOriginAllowlist','allowedPrivateAddresses','ca','timeoutMs'], 'invalid_lti_lifecycle');
  const origins = policy.selfManagedOriginAllowlist ?? [];
  if (!Array.isArray(origins) || origins.length > 32) fail('invalid_lti_lifecycle');
  const allowlist = Object.freeze(origins.map(value => canvasOrigin(value)));
  if (policy.ca !== undefined && (typeof policy.ca !== 'string' || policy.ca.length > 65536 ||
      !policy.ca.includes('-----BEGIN CERTIFICATE-----') || /PRIVATE KEY/.test(policy.ca))) fail('invalid_lti_lifecycle');
  if (policy.timeoutMs !== undefined && (!Number.isSafeInteger(policy.timeoutMs) ||
      policy.timeoutMs < 50 || policy.timeoutMs > 120000)) fail('invalid_lti_lifecycle');
  const network = Object.freeze({ allowedPrivateAddresses: approvedPrivateAddresses(policy.allowedPrivateAddresses),
    ca: policy.ca, timeoutMs: policy.timeoutMs });
  const resourceUrl = id => `${origin.origin}/lti/registrations/${id}/resource`;
  function reader(definition, id) {
    if (definition.targetLinkUri !== resourceUrl(id)) fail('lti_registration_unavailable');
    return createCanvasLtiPlatformReader({ ...network,
      // Explicitly select public provider configuration; never forward local
      // organization/status/revision fields into the provider reader.
      canvasOrigin: definition.canvasOrigin, trustProfile: definition.trustProfile,
      environment: definition.environment ?? undefined,
      selfManagedOriginAllowlist: definition.trustProfile === 'self_managed_same_origin' ? allowlist : undefined,
      clientId: definition.clientId, deploymentId: definition.deploymentId, targetLinkUri: definition.targetLinkUri });
  }
  function definition(r) {
    return { canvasOrigin: r.canvasOrigin, trustProfile: r.trustProfile, environment: r.environment,
      clientId: r.clientId, deploymentId: r.deploymentId, targetLinkUri: r.targetLinkUri };
  }
  async function context(input, fields) {
    const stateHash = stateRequest(input, fields), request = Object.freeze({ ...input });
    const saved = await repository.context(stateHash);
    if (!saved || saved.state.registrationId !== request.registrationId) fail('lti_launch_unavailable');
    return { saved, stateHash, request };
  }
  return Object.freeze({
    async begin(input) {
      exactRecord(input, ['registrationId','issuer','loginHint','messageHint','storageTarget','targetLinkUri','clientId','deploymentId'], 'invalid_lti_request');
      const request = Object.freeze({ ...input });
      if (!uuid(request.registrationId) || (request.storageTarget !== undefined && !['_parent','post_message_forwarding'].includes(request.storageTarget))) fail('invalid_lti_request');
      const loginHint = hint(request.loginHint, true), messageHint = hint(request.messageHint);
      const found = await repository.registration(request.registrationId), r = found?.registration;
      if (!r?.enabled || !r.platformEnabled || r.platformArchived) fail('lti_registration_unavailable');
      for (const name of ['targetLinkUri','clientId','deploymentId']) {
        if (request[name] !== undefined && request[name] !== r[name]) fail('invalid_lti_request');
      }
      const provider = reader(definition(r), r.registrationId);
      if (request.issuer !== provider.profile.issuer) fail('invalid_lti_request');
      const state = randomBytes(32).toString('base64url'), nonce = randomBytes(32).toString('base64url');
      const browserProof = randomBytes(32).toString('base64url'), launchId = randomUUID();
      const created = await repository.begin({ registrationId: r.registrationId, platformVersion: r.platformVersion,
        registrationVersion: r.version, stateHash: digest(state), browserHash: digest(browserProof), nonce, launchId });
      if (!created || created.launchId !== launchId || created.stateHash !== digest(state) || created.browserHash !== digest(browserProof) ||
          created.nonce !== nonce || created.registrationId !== r.registrationId || created.phase !== 'pending') fail('lti_launch_unavailable');
      const url = new URL(provider.profile.authorizationEndpoint);
      url.search = new URLSearchParams({ scope: 'openid', response_type: 'id_token', response_mode: 'form_post', prompt: 'none',
        client_id: r.clientId, redirect_uri: `${origin.origin}/lti/registrations/${r.registrationId}/launch`,
        state, nonce, login_hint: loginHint, ...(messageHint === undefined ? {} : { lti_message_hint: messageHint }) }).toString();
      return Object.freeze({ registrationId: r.registrationId, launchId, state, browserProof,
        authorizationUrl: url.href, storageOrigin: new URL(provider.profile.authorizationEndpoint).origin, canvasOrigin: provider.profile.canvasOrigin,
        storageTarget: request.storageTarget ?? null });
    },
    async stage(input) {
      const { saved, stateHash, request } = await context(input, ['registrationId','state','token']);
      if (typeof request.token !== 'string' || request.token.length > 65536 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(request.token)) fail('invalid_lti_request');
      const token = request.token, tokenHash = digest(token);
      if (saved.state.tokenHash !== null && saved.state.tokenHash !== tokenHash) fail('lti_launch_conflict');
      const provider = reader(saved.state.registrationSnapshot, saved.state.registrationId);
      if (saved.state.phase === 'pending') {
        if (!live(saved)) fail('lti_launch_unavailable');
        const protocolClaims = await provider.validateResourceLink({ token, nonce: saved.state.nonce });
        const staged = await repository.stage({ stateHash, tokenHash, protocolClaims });
        if (!staged || staged.launchId !== saved.state.launchId || staged.tokenHash !== tokenHash ||
            !['staged','accepted'].includes(staged.phase)) fail('lti_launch_unavailable');
      }
      // This is a confirmation plan, never an authenticated session/identity.
      return Object.freeze({ registrationId: saved.state.registrationId, launchId: saved.state.launchId,
        state: request.state, tokenHash, storageOrigin: new URL(provider.profile.authorizationEndpoint).origin, canvasOrigin: provider.profile.canvasOrigin });
    },
    async browserContext(input) {
      const { saved } = await context(input, ['registrationId','state']);
      const provider = reader(saved.state.registrationSnapshot, saved.state.registrationId);
      return Object.freeze({ registrationId: saved.state.registrationId, launchId: saved.state.launchId,
        storageOrigin: new URL(provider.profile.authorizationEndpoint).origin, canvasOrigin: provider.profile.canvasOrigin,
        phase: saved.state.phase, current: live(saved) });
    },
    async confirm(input) {
      const { saved, stateHash, request } = await context(input, ['registrationId','state','tokenHash','browserProof']);
      if (typeof request.tokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(request.tokenHash) || !matchesProof(saved.state.browserHash, request.browserProof)) fail('invalid_lti_browser_proof');
      const accepted = await repository.confirm({ stateHash, tokenHash: request.tokenHash, browserHash: digest(request.browserProof) });
      if (!accepted || accepted.launchId !== saved.state.launchId || accepted.registrationId !== saved.state.registrationId) fail('lti_launch_unavailable');
      return accepted; // Immutable historical receipt; active() remains a separate check.
    },
    async active(input) {
      const { saved, request } = await context(input, ['registrationId','state','browserProof']);
      if (!matchesProof(saved.state.browserHash, request.browserProof) || !live(saved) || saved.state.phase !== 'accepted' || !saved.receipt) fail('lti_launch_unavailable');
      const claims = saved.state.protocolClaims, now = Math.floor(saved.nowMs / 1000);
      if (claims.expiresAt <= now || claims.issuedAt > now + 30 || now - claims.issuedAt > 300 ||
          (claims.notBefore !== null && claims.notBefore > now)) fail('lti_launch_unavailable');
      return Object.freeze({ receipt: saved.receipt, protocolClaims: claims });
    },
  });
}
