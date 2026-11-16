// SPDX-License-Identifier: AGPL-3.0-only
export function createRefreshWorker({ repository, secretVault, provider } = {}) {
  if (typeof globalThis.window !== 'undefined' || ['claimRefresh', 'beginRefreshExchange',
    'requireRefreshReconciliation', 'abandonUnstartedRefresh', 'publishRefresh']
    .some(name => typeof repository?.[name] !== 'function')
    || ['get', 'stageRefreshResult', 'delete'].some(name => typeof secretVault?.[name] !== 'function')
    || typeof provider?.refresh !== 'function') throw new Error('invalid_refresh_worker');
  return Object.freeze({
    async runOnce(org, platform) {
      let job;
      try { job = await repository.claimRefresh(org, platform); }
      catch { throw new Error('connector_refresh_unavailable'); }
      if (!job) return 'idle';
      let started = false;
      try {
        const clientSecret = await secretVault.get(job.organizationId, job.clientSecretRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_client_secret'});
        const refreshToken = await secretVault.get(job.organizationId, job.refreshTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_refresh_token'});
        // Persist before network I/O. A lost acknowledgment leaves the attempt
        // non-reclaimable; do not guess whether a prior exchange happened.
        if (!await repository.beginRefreshExchange(job.id, job.leaseId)) return 'lease_lost';
        started = true;
        const exchangeStartedAt = Date.now();
        const bundle = await provider.refresh({ canvasOrigin: job.canvasOrigin, clientId: job.clientId, clientSecret, refreshToken });
        const validToken = value => typeof value === 'string' && /^[A-Za-z0-9._~+/-]{16,4096}={0,2}$/.test(value);
        if (!validToken(bundle?.accessToken) || (bundle.refreshToken != null && !validToken(bundle.refreshToken))
            || !Number.isSafeInteger(bundle.expiresInSeconds) || bundle.expiresInSeconds < 1
            || bundle.expiresInSeconds > 315360000) throw new Error('invalid_refresh_bundle');
        const expiresAt = exchangeStartedAt + bundle.expiresInSeconds * 1000;
        const staged=await secretVault.stageRefreshResult(job,bundle,expiresAt);
        const refreshRef=staged.refreshTokenRef;
        if (!await repository.publishRefresh(job.id, job.leaseId)) {
          await repository.requireRefreshReconciliation(job.id, job.leaseId);
          return 'reconciliation_required';
        }
        // Never revoke the old access token here: doing so may revoke the same
        // Canvas authorization that issued the new token. Remove obsolete local
        // ciphertext only after definite publication; references remain in the
        // durable attempt for cleanup reconciliation.
        try {
          await secretVault.delete(job.organizationId, job.accessTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_access_token'});
          if (refreshRef !== job.refreshTokenRef) await secretVault.delete(job.organizationId, job.refreshTokenRef, {platformId:job.platformId,provider:'canvas',purpose:'oauth_refresh_token'});
        } catch { return 'published_cleanup_required'; }
        return 'published';
      } catch {
        try {
          if (!started && await repository.abandonUnstartedRefresh(job.id, job.leaseId)) return 'unavailable';
          await repository.requireRefreshReconciliation(job.id, job.leaseId);
        } catch { throw new Error('connector_refresh_reconciliation_required'); }
        return 'reconciliation_required';
      }
    },
  });
}
