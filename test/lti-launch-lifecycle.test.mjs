// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createLtiLaunchLifecycle } from '../src/lti-launch-lifecycle.mjs';
import { createLtiLaunchRepository } from '../src/lti-launch-repository.mjs';

const registrationId = '10000000-0000-4000-8000-000000000002';
const publicOrigin = 'https://connector.example';
const configuration = { registrationId, organizationId: 'org-two', platformId: 'canvas-two', version: 1,
  clientId: 'client-two', deploymentId: 'deployment-two', trustProfile: 'hosted_global', environment: 'production',
  targetLinkUri: `${publicOrigin}/lti/registrations/${registrationId}/resource`, enabled: true,
  platformVersion: 1, canvasOrigin: 'https://college.instructure.com', platformEnabled: true, platformArchived: false };
function repository() {
  return { registration: async () => ({ registration: configuration, nowMs: Date.now() }),
    context: async () => null, begin: async input => ({ ...input, phase: 'pending' }),
    stage: async () => null, confirm: async () => null };
}
test('lifecycle rejects caller credentials, authority and alternate verification/transport hooks', () => {
  for (const extra of [{ apiKey: 'private' }, { verify: () => true }, { userId: 'caller' }, { transport: () => {} }]) {
    assert.throws(() => createLtiLaunchLifecycle({ repository: repository(), publicOrigin, ...extra }));
  }
  for (const origin of ['http://connector.example', 'https://user:secret@connector.example', 'https://connector.example/path', 'invalid']) {
    assert.throws(() => createLtiLaunchLifecycle({ repository: repository(), publicOrigin: origin }), { message: 'invalid_lti_lifecycle' });
  }
});
test('invalid operator TLS/deadline policy fails before listening or provider access',()=>{
  for(const platformPolicy of [{ca:'invalid'},{ca:'-----BEGIN CERTIFICATE----- PRIVATE KEY'},
    {timeoutMs:49},{timeoutMs:120001},{timeoutMs:NaN},{selfManagedOriginAllowlist:['http://bad.example']}]) {
    assert.throws(()=>createLtiLaunchLifecycle({repository:repository(),publicOrigin,platformPolicy}));
  }
});

test('invalid public inputs cannot cause database writes or provider access', async () => {
  const repo = repository();let reads = 0;
  repo.registration = repo.context = async () => { reads++;throw Error('unexpected_read'); };
  const lifecycle = createLtiLaunchLifecycle({ repository: repo, publicOrigin });
  for (const input of [{ registrationId, issuer: 'https://canvas.instructure.com', loginHint: 'x', organizationId: 'caller' },
    { registrationId, issuer: 'https://canvas.instructure.com', loginHint: 'x', storageTarget: 'attacker-frame' },
    { registrationId, issuer: 'https://canvas.instructure.com', loginHint: 'x\r\nheader' }]) await assert.rejects(lifecycle.begin(input));
  for (const method of ['stage','confirm','active']) {
    await assert.rejects(lifecycle[method]({ registrationId, state: 'bad', userId: 'caller' }));
  }
  assert.equal(reads, 0);
});
test('authorization redirects retain server client/callback despite hostile opaque hints', async () => {
  const lifecycle = createLtiLaunchLifecycle({ repository: repository(), publicOrigin });
  const opaque = 'opaque&redirect_uri=https://attacker.invalid&client_id=attacker';
  const started = await lifecycle.begin({ registrationId, issuer: 'https://canvas.instructure.com', loginHint: opaque,
    messageHint: 'opaque-message', storageTarget: 'post_message_forwarding' });
  const url = new URL(started.authorizationUrl);
  assert.equal(url.origin, 'https://sso.canvaslms.com');assert.equal(url.pathname, '/api/lti/authorize_redirect');
  assert.equal(url.searchParams.get('client_id'), configuration.clientId);
  assert.equal(url.searchParams.get('redirect_uri'), `${publicOrigin}/lti/registrations/${registrationId}/launch`);
  assert.equal(url.searchParams.get('login_hint'), opaque);assert.equal(url.searchParams.getAll('client_id').length, 1);
  assert.equal(started.storageOrigin, 'https://sso.canvaslms.com');assert.notEqual(started.browserProof, started.state);
});
test('captured initiation inputs cannot change issuer or storage frame across a repository await', async () => {
  const repo = repository();let resolve;
  repo.registration = () => new Promise(done => { resolve = done; });
  const lifecycle = createLtiLaunchLifecycle({ repository: repo, publicOrigin });
  const request = { registrationId, issuer: 'https://canvas.instructure.com', loginHint: 'opaque', storageTarget: 'post_message_forwarding' };
  const pending = lifecycle.begin(request);request.issuer = 'https://attacker.invalid';request.storageTarget = 'attacker-frame';
  resolve({ registration: configuration, nowMs: Date.now() });
  assert.equal((await pending).storageTarget, 'post_message_forwarding');
});
test('disabled or cross-origin registration does not create launch state', async () => {
  for (const overrides of [{ enabled: false }, { platformEnabled: false }, { platformArchived: true },
    { targetLinkUri: 'https://attacker.invalid/resource' }]) {
    const repo = repository();let writes = 0;
    repo.registration = async () => ({ registration: { ...configuration, ...overrides }, nowMs: Date.now() });
    repo.begin = async () => { writes++;throw Error('unexpected_write'); };
    await assert.rejects(createLtiLaunchLifecycle({ repository: repo, publicOrigin }).begin({ registrationId, issuer: 'https://canvas.instructure.com', loginHint: 'opaque' }));
    assert.equal(writes, 0);
  }
});
test('repository never reflects database errors containing private material', async () => {
  const repo = createLtiLaunchRepository({ query: async () => { throw Error('private-token-and-sql'); } });
  await assert.rejects(repo.registration(registrationId), { message: 'lti_launch_repository_unavailable' });
});
test('unsigned target, client and deployment hints cannot replace registered values', async () => {
  for (const override of [{ targetLinkUri:'https://attacker.invalid' },{ clientId:'other' },{ deploymentId:'other' }]) {
    const repo=repository();let writes=0;repo.begin=async()=>{writes++;throw Error('unexpected_write');};
    await assert.rejects(createLtiLaunchLifecycle({repository:repo,publicOrigin}).begin({registrationId,
      issuer:'https://canvas.instructure.com',loginHint:'opaque',...override}),{message:'invalid_lti_request'});
    assert.equal(writes,0);
  }
  const started=await createLtiLaunchLifecycle({repository:repository(),publicOrigin}).begin({registrationId,
    issuer:'https://canvas.instructure.com',loginHint:'opaque',targetLinkUri:configuration.targetLinkUri,
    clientId:configuration.clientId,deploymentId:configuration.deploymentId,storageTarget:'_parent'});
  assert.equal(started.storageTarget,'_parent');
});
