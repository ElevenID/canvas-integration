// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomBytes, randomUUID, generateKeyPairSync, sign } from 'node:crypto';
import { createLtiLaunchRepository } from '../src/lti-launch-repository.mjs';
import { createLtiLaunchLifecycle } from '../src/lti-launch-lifecycle.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const container = process.argv[2];
if (!/^canvas-lti-state-[a-f0-9]{32}$/.test(container)) throw new Error('owned_fixture_required');
const run = promisify(execFile);
const digest = value => createHash('sha256').update(value).digest('hex');
const literal = value => typeof value === 'number' ? String(value) : "'" + String(value).replaceAll("'", "''") + "'";
async function execute(sql, parameters) {
  const statement = sql.replace(/\$(\d+)/g, (_, index) => literal(parameters[Number(index) - 1]));
  const source = `SET ROLE lti_runtime; SELECT row_to_json(q) FROM (${statement}) q;`;
  const { stdout } = await run('docker', ['exec', container, 'psql', '-X', '-q', '-A', '-t',
    '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', source]);
  return { rows: stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) };
}
let loseBegin = true, loseConfirm = true;
const repository = createLtiLaunchRepository({ async query(sql, values) {
  const response = await execute(sql, values);
  if (loseBegin && sql.includes('begin_lti_launch')) { loseBegin = false;throw new Error('synthetic_reply_lost'); }
  if (loseConfirm && sql.includes('confirm_lti_launch') && response.rows[0]?.result !== null) { loseConfirm = false;throw new Error('synthetic_reply_lost'); }
  return response;
} });
const registrationId = '10000000-0000-4000-8000-000000000001';
const registered = await repository.registration(registrationId);
assert.equal(registered.registration.version, 3);assert.equal(registered.registration.platformVersion, 3);
const state = randomBytes(32).toString('base64url'), proof = randomBytes(32).toString('base64url');
const challenge = randomBytes(32).toString('base64url'), stateHash = digest(state), browserHash = digest(proof);
const begin = { registrationId, platformVersion: 3, registrationVersion: 3, stateHash, browserHash,
  nonce: challenge, launchId: randomUUID() };
await assert.rejects(repository.begin(begin), { message: 'lti_launch_repository_unavailable' });
const pending = await repository.begin(begin);
assert.equal(pending.launchId, begin.launchId);assert.equal(pending.nonce, challenge);
assert.equal(pending.registrationSnapshot.clientId, 'client-one');assert.equal(pending.phase, 'pending');
assert.ok(Object.isFrozen(pending.registrationSnapshot));
let context = await repository.context(stateHash);
assert.equal(context.state.phase, 'pending');assert.equal(context.receipt, null);
const now = Math.floor(context.nowMs / 1000), tokenHash = digest('synthetic-original-token');
const protocolClaims = { issuer: 'https://canvas.example', clientId: 'client-one', deploymentId: 'deployment-one',
  targetLinkUri: 'https://connector.example/lti/resource', nonce: challenge, subject: 'provider-subject',
  issuedAt: now - 1, expiresAt: now + 120, notBefore: null, messageType: 'LtiResourceLinkRequest',
  version: '1.3.0', resourceLinkId: 'resource-one', contextId: null };
assert.equal((await repository.stage({ stateHash, tokenHash, protocolClaims })).phase, 'staged');
assert.equal(await repository.confirm({ stateHash, tokenHash, browserHash: digest('wrong') }), null);
await assert.rejects(repository.confirm({ stateHash, tokenHash, browserHash }), { message: 'lti_launch_repository_unavailable' });
context = await repository.context(stateHash);
assert.equal(context.state.phase, 'accepted');assert.equal(context.receipt.launchId, begin.launchId);
assert.deepEqual(await repository.confirm({ stateHash, tokenHash, browserHash }), context.receipt);
assert.equal(await repository.confirm({ stateHash, tokenHash: digest('changed'), browserHash }), null);
assert.ok(Object.isFrozen(context.receipt));assert.ok(!Object.hasOwn(context.receipt, 'subject'));
console.log('Production LTI repository decoding, captured snapshots and original begin/confirm lost-reply reconciliation passed against PostgreSQL16');

const fixture = await httpsFixture();
async function owner(source) {
  await run('docker', ['exec', container, 'psql', '-X', '-q', '-h', '127.0.0.1', '-U', 'postgres',
    '-v', 'ON_ERROR_STOP=1', '-c', source]);
}
try {
  const secondId = '10000000-0000-4000-8000-000000000002';
  const publicOrigin = 'https://connector.example', target = `${publicOrigin}/lti/registrations/${secondId}/resource`;
  await owner(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled)
    VALUES('org-two','canvas-two',${literal(fixture.origin)},true);
    INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
    VALUES('${secondId}','org-two','canvas-two','client-two','deployment-two','self_managed_same_origin','${target}',true);`);
  const lifecycle = createLtiLaunchLifecycle({ repository, publicOrigin, platformPolicy: {
    selfManagedOriginAllowlist: [fixture.origin], allowedPrivateAddresses: ['127.0.0.1', '::1'], ca: fixture.ca } });
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'fixture-key' };
  const C = 'https://purl.imsglobal.org/spec/lti/claim/';
  const signed = (started, changes = {}) => {
    const now = Math.floor(Date.now() / 1000), auth = new URL(started.authorizationUrl);
    const claims = { iss: fixture.origin, aud: 'client-two', sub: 'provider-subject-two', nonce: auth.searchParams.get('nonce'),
      iat: now - 1, exp: now + 120, [C + 'version']: '1.3.0', [C + 'message_type']: 'LtiResourceLinkRequest',
      [C + 'deployment_id']: 'deployment-two', [C + 'target_link_uri']: target,
      [C + 'resource_link']: { id: 'resource-two' }, [C + 'roles']: [], ...changes };
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const body = `${encode({ alg: 'RS256', kid: jwk.kid })}.${encode(claims)}`;
    return `${body}.${sign('RSA-SHA256', Buffer.from(body), pair.privateKey).toString('base64url')}`;
  };
  const request = { registrationId: secondId, issuer: fixture.origin, loginHint: 'opaque-login-hint',
    messageHint: 'opaque-message-hint', storageTarget: 'post_message_forwarding' };
  const beginning = lifecycle.begin(request); request.issuer = 'https://attacker.invalid';
  const started = await beginning, auth = new URL(started.authorizationUrl);
  assert.equal(auth.origin, fixture.origin);assert.equal(auth.pathname, '/api/lti/authorize_redirect');
  assert.equal(auth.searchParams.get('redirect_uri'), `${publicOrigin}/lti/registrations/${secondId}/launch`);
  assert.equal(auth.searchParams.get('response_mode'), 'form_post');assert.equal(auth.searchParams.get('state'), started.state);
  assert.equal(started.storageOrigin, fixture.origin);assert.equal(started.storageTarget, 'post_message_forwarding');
  assert.notEqual(started.state, started.browserProof);
  fixture.setHandler(async (_req, res) => {
    try { await owner("UPDATE canvas_connector.platforms SET enabled=false WHERE id='canvas-two';");json(res, { keys: [jwk] }); }
    catch { res.writeHead(500);res.end(); }
  });
  await assert.rejects(lifecycle.stage({ registrationId: secondId, state: started.state, token: signed(started) }), { message: 'lti_launch_unavailable' });
  assert.equal((await repository.context(digest(started.state))).state.phase, 'pending');
  await owner("UPDATE canvas_connector.platforms SET enabled=true WHERE id='canvas-two';");
  fixture.setHandler((_req, res) => json(res, { keys: [jwk] }));
  await assert.rejects(lifecycle.stage({ registrationId: secondId, state: started.state, token: signed(started) }), { message: 'lti_launch_unavailable' });
  const fresh = await lifecycle.begin({ registrationId: secondId, issuer: fixture.origin, loginHint: 'opaque' });
  await assert.rejects(lifecycle.stage({ registrationId: secondId, state: fresh.state, token: signed(fresh, { nonce: 'wrong' }) }), { message: 'invalid_lti_launch' });
  const originalToken = signed(fresh), stageInput = { registrationId: secondId, state: fresh.state, token: originalToken };
  const staging = lifecycle.stage(stageInput); stageInput.token = signed(fresh, { sub: 'attacker' });
  const plan = await staging;
  assert.equal(plan.tokenHash, digest(originalToken));assert.ok(!JSON.stringify(plan).includes('provider-subject-two'));
  await assert.rejects(lifecycle.confirm({ registrationId: secondId, state: fresh.state,
    tokenHash: plan.tokenHash, browserProof: randomBytes(32).toString('base64url') }), { message: 'invalid_lti_browser_proof' });
  const accepted = await lifecycle.confirm({ registrationId: secondId, state: fresh.state, tokenHash: plan.tokenHash, browserProof: fresh.browserProof });
  const active = await lifecycle.active({ registrationId: secondId, state: fresh.state, browserProof: fresh.browserProof });
  assert.deepEqual(active.receipt, accepted);assert.equal(active.protocolClaims.subject, 'provider-subject-two');
  assert.ok(!Object.hasOwn(active, 'userId'));assert.ok(!Object.hasOwn(active, 'applicationId'));
  for (const seen of fixture.seen) {
    assert.equal(seen.url, '/api/lti/security/jwks');
    assert.equal(seen.headers.authorization, undefined);assert.equal(seen.headers.cookie, undefined);assert.equal(seen.headers['x-api-key'], undefined);
  }
  await owner("UPDATE canvas_connector.platforms SET enabled=false WHERE id='canvas-two';");
  assert.deepEqual(await lifecycle.confirm({ registrationId: secondId, state: fresh.state, tokenHash: plan.tokenHash, browserProof: fresh.browserProof }), accepted);
  await assert.rejects(lifecycle.active({ registrationId: secondId, state: fresh.state, browserProof: fresh.browserProof }), { message: 'lti_launch_unavailable' });
  await assert.rejects(lifecycle.stage({ registrationId: secondId, state: fresh.state, token: signed(fresh, { sub: 'changed' }) }), { message: 'lti_launch_conflict' });
  console.log('Real pinned Canvas HTTPS/JWT -> PostgreSQL staged launch -> browser-proof acceptance/receipt -> current resource context passed; drift and lost replies retain original state');
} finally { await fixture.close(); }
