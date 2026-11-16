// SPDX-License-Identifier: AGPL-3.0-only
export function createRevocationWorker({ repository, secretVault, provider } = {}) {
  if (typeof globalThis.window !== 'undefined'
      || ['claimRevocation', 'recordProviderRevocation', 'finishRevocation', 'retryRevocation']
        .some(name => typeof repository?.[name] !== 'function')
      || ['get', 'delete'].some(name => typeof secretVault?.[name] !== 'function')
      || typeof provider?.revoke !== 'function') throw new Error('invalid_revocation_worker');
  return Object.freeze({
    async runOnce() {
      let job;
      try { job = await repository.claimRevocation(); }
      catch { throw new Error('connector_revocation_unavailable'); }
      if (!job) return 'idle';
      try {
        if (job.revoked !== true) {
          const accessToken = await secretVault.get(job.organizationId, job.accessTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_access_token'});
          // True means confirmed revocation (including an independently verified
          // already-revoked token), never a transport failure or assumed success.
          if (await provider.revoke({ canvasOrigin: job.canvasOrigin, accessToken }) !== true) {
            throw new Error('revocation_not_confirmed');
          }
          if (!await repository.recordProviderRevocation(job.id, job.leaseId)) return 'lease_lost';
        }
        // Durable provider confirmation lets a replacement worker resume
        // idempotent vault deletion even after the access token was deleted.
        await secretVault.delete(job.organizationId, job.accessTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_access_token'});
        if (job.refreshTokenRef) await secretVault.delete(job.organizationId, job.refreshTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_refresh_token'});
        return await repository.finishRevocation(job.id, job.leaseId) ? 'completed' : 'lease_lost';
      } catch {
        try { return await repository.retryRevocation(job.id, job.leaseId) ? 'retry' : 'lease_lost'; }
        catch { throw new Error('connector_revocation_reconciliation_required'); }
      }
    },
  });
}
