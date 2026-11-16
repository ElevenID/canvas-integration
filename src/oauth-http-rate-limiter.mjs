// SPDX-License-Identifier: AGPL-3.0-only
const unavailable = () => new Error('connector_http_limit_unavailable');
// A database-wide budget shared by replicas. It never stores client addresses
// or creates attacker-selected keys. A lost commit consumes quota conservatively.
export function createOAuthHttpRateLimiter(pool) {
  if (typeof globalThis.window !== 'undefined' || typeof pool?.query !== 'function') throw unavailable();
  return Object.freeze({
    async consume() {
      try {
        const result = await pool.query('SELECT canvas_connector.consume_oauth_http_limit() AS allowed');
        if (result?.rows?.length !== 1 || typeof result.rows[0]?.allowed !== 'boolean') throw unavailable();
        return result.rows[0].allowed;
      } catch { throw unavailable(); }
    },
  });
}
