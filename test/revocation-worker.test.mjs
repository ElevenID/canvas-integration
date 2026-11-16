// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRevocationWorker } from '../src/revocation-worker.mjs';

for (const failure of ['provider-outage', 'unconfirmed', 'lost-lease', 'uncertain-ack']) {
  test(`revocation ${failure} preserves vault references`, async () => {
    const deleted = [];
    const job = { id: 'job', leaseId: 'lease', organizationId: 'org', canvasOrigin: 'https://canvas.example.test',
      accessTokenRef: 'access', refreshTokenRef: 'refresh', revoked: false };
    const worker = createRevocationWorker({
      repository: {
        async claimRevocation() { return job; },
        async recordProviderRevocation() {
          if (failure === 'uncertain-ack') throw Error('database-private-detail');
          return failure !== 'lost-lease';
        },
        async finishRevocation() { assert.fail('must not finish'); },
        async retryRevocation(id, lease) { assert.equal(id, 'job'); assert.equal(lease, 'lease'); return true; },
      },
      secretVault: { async get() { return 'synthetic-token'; }, async delete(...args) { deleted.push(args); } },
      provider: { async revoke() {
        if (failure === 'provider-outage') throw Error('provider-private-detail');
        return failure !== 'unconfirmed';
      } },
    });
    assert.equal(await worker.runOnce(), failure === 'lost-lease' ? 'lease_lost' : 'retry');
    assert.deepEqual(deleted, []);
  });
}
test('claim failure is redacted without attempting provider work', async () => {
  const worker = createRevocationWorker({
    repository: { async claimRevocation() { throw Error('password=secret'); }, recordProviderRevocation() {},
      finishRevocation() {}, retryRevocation() {} },
    secretVault: { get() { assert.fail(); }, delete() { assert.fail(); } },
    provider: { revoke() { assert.fail(); } },
  });
  await assert.rejects(worker.runOnce(), /^Error: connector_revocation_unavailable$/);
});
