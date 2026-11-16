// SPDX-License-Identifier: AGPL-3.0-only
// Internal resource-link primitive. The caller owns trusted registration, browser
// binding, current configuration, fresh pinned JWKS and atomic nonce consumption.
import { createPublicKey, verify, constants } from 'node:crypto';
import { parsePrivateJson } from './private-json.mjs';

const CLAIM = 'https://purl.imsglobal.org/spec/lti/claim/';
const VOCAB = 'http://purl.imsglobal.org/vocab/';
const knownRoles = new Set();
for (const [path, names] of Object.entries({
  'lis/v2/system/person': 'Administrator None AccountAdmin Creator SysAdmin SysSupport User',
  'lis/v2/institution/person': 'Administrator Faculty Guest None Other Staff Student Alumni Instructor Learner Member Mentor Observer ProspectiveStudent',
  'lis/v2/membership': 'Administrator ContentDeveloper Instructor Learner Mentor Manager Member Officer',
  'lis/v2/membership/Administrator': 'Administrator Developer ExternalDeveloper ExternalSupport ExternalSystemAdministrator Support SystemAdministrator',
  'lis/v2/membership/ContentDeveloper': 'ContentDeveloper ContentExpert ExternalContentExpert Librarian',
  'lis/v2/membership/Instructor': 'ExternalInstructor Grader GuestInstructor Lecturer PrimaryInstructor SecondaryInstructor TeachingAssistant TeachingAssistantGroup TeachingAssistantOffering TeachingAssistantSection TeachingAssistantSectionAssociation TeachingAssistantTemplate',
  'lis/v2/membership/Learner': 'ExternalLearner GuestLearner Instructor Learner NonCreditLearner',
  'lis/v2/membership/Manager': 'AreaManager CourseCoordinator ExternalObserver Manager Observer',
  'lis/v2/membership/Member': 'Member',
  'lis/v2/membership/Mentor': 'Advisor Auditor ExternalAdvisor ExternalAuditor ExternalLearningFacilitator ExternalMentor ExternalReviewer ExternalTutor LearningFacilitator Mentor Reviewer Tutor',
  'lis/v2/membership/Officer': 'Chair Communications Secretary Treasurer Vice-Chair',
})) for (const name of names.split(' ')) knownRoles.add(`${VOCAB}${path}#${name}`);
const own = (value, key) => Object.hasOwn(value, key);
const invalid = () => { throw new Error('invalid_lti_launch'); };
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value;
}
function text(value, max = 255) {
  if (typeof value !== 'string' || !value.length || value.length > max ||
      !/^[\x21-\x7e]+$/.test(value)) invalid();
  return value;
}
function https(value, issuer = false) {
  text(value, 2048);
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
      (issuer && url.search)) invalid();
  return value; // Exact registered spelling, never URL-normalized claim equality.
}
function base64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) invalid();
  return bytes;
}
function json(bytes, max) {
  if (!bytes.length || bytes.length > max) invalid();
  return object(parsePrivateJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
}
function integer(value) {
  if (!Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}
function publicKey(jwksText, kid) {
  if (typeof jwksText !== 'string' || jwksText.length > 131072) invalid();
  const jwks = json(Buffer.from(jwksText, 'utf8'), 131072);
  if (!Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 32) invalid();
  const ids = new Set();
  for (const candidate of jwks.keys) {
    object(candidate);
    // Never accept a private or symmetric key, even if it is not selected.
    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
      if (own(candidate, field)) invalid();
    }
    const id = text(candidate.kid);
    if (ids.has(id)) invalid();
    ids.add(id);
  }
  const key = jwks.keys.find(candidate => candidate.kid === kid);
  if (!key || key.kty !== 'RSA' || (own(key, 'alg') && key.alg !== 'RS256') ||
      (own(key, 'use') && key.use !== 'sig') || (own(key, 'key_ops') &&
       (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify'))) invalid();
  const n = base64url(key.n), e = base64url(key.e);
  if (n.length < 256 || n.length > 1024 || n[0] === 0 ||
      e.length > 4 || e[0] === 0) invalid();
  const exponent = e.reduce((sum, byte) => sum * 256 + byte, 0);
  if (exponent < 3 || exponent % 2 !== 1) invalid();
  // Import only public RSA fields; no certificates or URL-bearing key metadata.
  const imported = createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' });
  const bits = imported.asymmetricKeyDetails?.modulusLength;
  if (imported.asymmetricKeyType !== 'rsa' || bits < 2048 || bits > 8192) invalid();
  return { imported, bytes: Math.ceil(bits / 8) };
}

// Authenticates a protocol message only. It neither admits evidence nor links a
// Marty subject. No raw claims, roles, names, email or service URLs leave here.
export function validateCanvasResourceLinkLaunch({ token, jwksText, expected, nowSeconds }) {
  try {
    object(expected);
    const issuer = https(expected.issuer, true), clientId = text(expected.clientId);
    const deploymentId = text(expected.deploymentId), nonce = text(expected.nonce, 512);
    if (nonce.length < 32) invalid();
    const targetLinkUri = https(expected.targetLinkUri), now = integer(nowSeconds);
    const trusted = expected.trustedAdditionalAudiences ?? [];
    if (!Array.isArray(trusted) || trusted.length > 16) invalid();
    const trustedAudiences = new Set([clientId, ...trusted.map(value => text(value))]);
    if (typeof token !== 'string' || token.length > 65536) invalid();
    const parts = token.split('.');
    if (parts.length !== 3) invalid();
    const header = json(base64url(parts[0]), 4096);
    if (header.alg !== 'RS256' || (own(header, 'typ') && header.typ !== 'JWT')) invalid();
    // No key discovery, algorithm negotiation or extension semantics from JWTs.
    if (Object.keys(header).some(key => !['alg', 'typ', 'kid'].includes(key))) invalid();
    const kid = text(header.kid);
    const claims = json(base64url(parts[1]), 49152), signature = base64url(parts[2]);
    const key = publicKey(jwksText, kid);
    if (signature.length !== key.bytes || !verify('RSA-SHA256',
      Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
      { key: key.imported, padding: constants.RSA_PKCS1_PADDING }, signature)) invalid();
    if (claims.iss !== issuer || claims.nonce !== nonce) invalid();
    const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
    if (!Array.isArray(audiences) || !audiences.length || audiences.length > 17 ||
        new Set(audiences).size !== audiences.length || !audiences.includes(clientId) ||
        audiences.some(audience => !trustedAudiences.has(text(audience)))) invalid();
    if ((audiences.length > 1 || own(claims, 'azp')) && claims.azp !== clientId) invalid();
    const issuedAt = integer(claims.iat), expiresAt = integer(claims.exp);
    const notBefore = own(claims, 'nbf') ? integer(claims.nbf) : null;
    // Connector policy: five minute launch age, 30 second future-iat tolerance.
    // Expiry is strict; a platform's longer exp does not extend launch age.
    if (now >= expiresAt || issuedAt >= expiresAt || issuedAt > now + 30 || now - issuedAt > 300 ||
        (notBefore !== null && notBefore > now)) invalid();
    if (claims[CLAIM + 'version'] !== '1.3.0' ||
        claims[CLAIM + 'message_type'] !== 'LtiResourceLinkRequest' ||
        claims[CLAIM + 'deployment_id'] !== deploymentId ||
        claims[CLAIM + 'target_link_uri'] !== targetLinkUri) invalid();
    const resourceLinkId = text(object(claims[CLAIM + 'resource_link']).id);
    // This connector requires an identified learner; anonymous protocol launches
    // are unsupported. A signed sub is still not a canonical Marty identity.
    const subject = text(claims.sub);
    const roles = claims[CLAIM + 'roles'];
    if (!Array.isArray(roles) || roles.length > 64) invalid();
    for (const role of roles) {
      const url = new URL(text(role, 2048));
      if (!['https:', 'http:', 'urn:'].includes(url.protocol) || url.username || url.password) invalid();
    }
    if (roles.length && !roles.some(role => knownRoles.has(role))) invalid();
    const contextId = own(claims, CLAIM + 'context') ? text(object(claims[CLAIM + 'context']).id) : null;
    return Object.freeze({ issuer, clientId, deploymentId, subject, nonce, issuedAt, expiresAt, notBefore,
      targetLinkUri, resourceLinkId, contextId, messageType: 'LtiResourceLinkRequest', version: '1.3.0' });
  } catch {
    // Never reflect bearer claims, trusted configuration, keys or crypto errors.
    throw new Error('invalid_lti_launch');
  }
}
