// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, constants } from 'node:crypto';
import { validateCanvasResourceLinkLaunch } from '../src/canvas-lti-launch.mjs';

const C = 'https://purl.imsglobal.org/spec/lti/claim/';
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'key-1', alg: 'RS256', use: 'sig' };
const expected = { issuer: 'https://canvas.instructure.com', clientId: 'tool-client',
  deploymentId: 'deployment-1', nonce: 'n'.repeat(43), targetLinkUri: 'https://connector.example/lti/launch' };
const now = 1800000000;
function claims() {
  return { iss: expected.issuer, aud: expected.clientId, sub: 'canvas-subject',
    nonce: expected.nonce, iat: now - 10, exp: now + 3600,
    [C + 'version']: '1.3.0', [C + 'message_type']: 'LtiResourceLinkRequest',
    [C + 'deployment_id']: expected.deploymentId, [C + 'target_link_uri']: expected.targetLinkUri,
    [C + 'resource_link']: { id: 'resource-1' }, [C + 'context']: { id: 'course-1' },
    [C + 'roles']: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
    email: 'private@example.invalid', name: 'Private Learner', unknown_future_claim: { permitted: true } };
}
function token(body = claims(), header = { alg: 'RS256', kid: 'key-1', typ: 'JWT' },
  key = pair.privateKey, padding = constants.RSA_PKCS1_PADDING) {
  const encode = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode(header)}.${encode(body)}`;
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), { key, padding }).toString('base64url')}`;
}
function input(overrides = {}) {
  return { token: token(), jwksText: JSON.stringify({ keys: [publicJwk] }), expected, nowSeconds: now, ...overrides };
}
function denied(value) { assert.throws(() => validateCanvasResourceLinkLaunch(value), /^Error: invalid_lti_launch$/); }

test('valid resource launch returns only frozen protocol identifiers; ignores future claims', () => {
  const result = validateCanvasResourceLinkLaunch(input());
  assert.deepEqual(result, { issuer: expected.issuer, clientId: expected.clientId,
    deploymentId: expected.deploymentId, subject: 'canvas-subject', nonce: expected.nonce,
    issuedAt: now - 10, expiresAt: now + 3600, targetLinkUri: expected.targetLinkUri,
    resourceLinkId: 'resource-1', contextId: 'course-1', messageType: 'LtiResourceLinkRequest', version: '1.3.0' });
  assert.ok(Object.isFrozen(result));
  for (const sensitive of ['private@example.invalid', 'Private Learner', 'Learner', 'VERIFIED']) {
    assert.ok(!JSON.stringify(result).includes(sensitive));
  }
});
test('optional context and roles empty; exp lifetime does not replace five minute launch age', () => {
  const body = claims(); delete body[C + 'context']; body[C + 'roles'] = [];
  assert.equal(validateCanvasResourceLinkLaunch(input({ token: token(body) })).contextId, null);
  body.iat = now - 300;
  validateCanvasResourceLinkLaunch(input({ token: token(body) }));
  body.iat--;
  denied(input({ token: token(body) }));
});
test('multi audience requires explicit trusted audience and matching azp', () => {
  const body = claims(); body.aud = [expected.clientId, 'trusted']; body.azp = expected.clientId;
  denied(input({ token: token(body) }));
  const selected = { ...expected, trustedAdditionalAudiences: ['trusted'] };
  validateCanvasResourceLinkLaunch(input({ token: token(body), expected: selected }));
  delete body.azp;
  denied(input({ token: token(body), expected: selected }));
});
const claimMutations = {
  issuer: body => { body.iss += '/'; }, audience: body => { body.aud = 'other'; },
  duplicateAudience: body => { body.aud = [expected.clientId, expected.clientId]; },
  azp: body => { body.azp = 'other'; }, nonce: body => { body.nonce = 'wrong'; },
  missingNonce: body => { delete body.nonce; }, expired: body => { body.exp = now; },
  futureIat: body => { body.iat = now + 31; }, missingIat: body => { delete body.iat; },
  stringIat: body => { body.iat = String(now); }, fractionalExp: body => { body.exp += 0.5; },
  unsafeExp: body => { body.exp = 1e20; }, reversedTime: body => { body.exp = body.iat; },
  futureNbf: body => { body.nbf = now + 1; }, malformedNbf: body => { body.nbf = null; },
  deployment: body => { body[C + 'deployment_id'] = 'other'; },
  target: body => { body[C + 'target_link_uri'] += '?other'; },
  version: body => { body[C + 'version'] = '1.1.0'; },
  deepLink: body => { body[C + 'message_type'] = 'LtiDeepLinkingRequest'; },
  resource: body => { body[C + 'resource_link'] = {}; },
  oversizedResource: body => { body[C + 'resource_link'].id = 'r'.repeat(256); },
  anonymous: body => { delete body.sub; }, nonAsciiSub: body => { body.sub = 'é'; },
  roles: body => { body[C + 'roles'] = 'Instructor'; },
  roleUrl: body => { body[C + 'roles'] = ['javascript:alert(1)']; },
  context: body => { body[C + 'context'] = {}; },
};
for (const [name, mutate] of Object.entries(claimMutations)) test(`rejects signed invalid claim: ${name}`, () => {
  const body = claims(); mutate(body); denied(input({ token: token(body) }));
});
for (const [name, header] of Object.entries({ none: { alg: 'none', kid: 'key-1' },
  symmetric: { alg: 'HS256', kid: 'key-1' }, pss: { alg: 'PS256', kid: 'key-1' },
  unknownKey: { alg: 'RS256', kid: 'unknown' }, remoteKey: { alg: 'RS256', kid: 'key-1', jku: 'https://evil.invalid' },
  embeddedKey: { alg: 'RS256', kid: 'key-1', jwk: publicJwk },
  extension: { alg: 'RS256', kid: 'key-1', crit: [] },
  detached: { alg: 'RS256', kid: 'key-1', b64: false }, typ: { alg: 'RS256', kid: 'key-1', typ: 'at+jwt' } })) {
  test(`rejects header: ${name}`, () => denied(input({ token: token(claims(), header) })));
}
test('rejects wrong key, PSS signature, tampering and truncated signature', () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  denied(input({ token: token(claims(), undefined, other.privateKey) }));
  denied(input({ token: token(claims(), undefined, pair.privateKey, constants.RSA_PKCS1_PSS_PADDING) }));
  const valid = token(), parts = valid.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...claims(), sub: 'other' })).toString('base64url');
  denied(input({ token: parts.join('.') }));
  denied(input({ token: valid.slice(0, -4) }));
});
for (const [name, keys] of Object.entries({ duplicate: [publicJwk, publicJwk],
  private: [{ ...publicJwk, d: 'private' }], unusedPrivate: [publicJwk, { ...publicJwk, kid: 'other', k: 'secret' }],
  encryption: [{ ...publicJwk, use: 'enc' }], wrongAlg: [{ ...publicJwk, alg: 'RS512' }],
  wrongOps: [{ ...publicJwk, key_ops: ['sign', 'verify'] }],
  emptyModulus: [{ ...publicJwk, n: '' }], leadingZero: [{ ...publicJwk, n: `AA${publicJwk.n}` }],
  invalidExponent: [{ ...publicJwk, e: 'Ag' }], padded: [{ ...publicJwk, n: publicJwk.n + '=' }] })) {
  test(`rejects JWKS: ${name}`, () => denied(input({ jwksText: JSON.stringify({ keys }) })));
}
test('rejects weak RSA and ambiguous JSON, encoding, depth and size', () => {
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
  denied(input({ token: token(claims(), undefined, weak.privateKey),
    jwksText: JSON.stringify({ keys: [{ ...weak.publicKey.export({ format: 'jwk' }), kid: 'key-1' }] }) }));
  denied(input({ token: token(JSON.stringify(claims()).replace('"sub":', '"sub":"other","sub":')) }));
  denied(input({ token: token(claims(), '{"alg":"none","alg":"RS256","kid":"key-1"}') }));
  denied(input({ jwksText: '{"keys":[],"keys":' + JSON.stringify([publicJwk]) + '}' }));
  denied(input({ token: token({ ...claims(), unused: JSON.parse('['.repeat(17) + '0' + ']'.repeat(17)) }) }));
  const valid = token(), parts = valid.split('.'); parts[0] += '=';
  denied(input({ token: parts.join('.') }));
  parts[0] = Buffer.from([0xff]).toString('base64url'); denied(input({ token: parts.join('.') }));
  denied(input({ token: 'a'.repeat(65537) }));
  denied(input({ jwksText: ' '.repeat(131073) }));
});
test('trusted input must be complete, bounded and HTTPS; errors never reflect it', () => {
  for (const override of [{ nonce: '' }, { issuer: 'http://canvas.example' }, { targetLinkUri: 'javascript:x' },
    { clientId: '' }, { deploymentId: '' }, { issuer: 'https://user:secret@canvas.example' }]) {
    denied(input({ expected: { ...expected, ...override } }));
  }
  denied(input({ nowSeconds: NaN }));
});
