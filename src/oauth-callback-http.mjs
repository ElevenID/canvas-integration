// SPDX-License-Identifier: AGPL-3.0-only
// Incoming HTTP only. This adapter owns no provider credentials or transport.
export function createOAuthCallbackHandler({ lifecycle, rateLimiter, completionUrl } = {}) {
  if (typeof globalThis.window !== 'undefined' || typeof lifecycle?.callback !== 'function'
      || typeof rateLimiter?.consume !== 'function') throw new Error('invalid_callback_configuration');
  let completion;
  try { completion = new URL(completionUrl); } catch { throw new Error('invalid_completion_url'); }
  if (completion.protocol !== 'https:' || completion.username || completion.password
      || completion.search || completion.hash) throw new Error('invalid_completion_url');

  return async function callbackHandler(request, response) {
    const finish = (status, location) => {
      response.writeHead(status, {
        'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff', 'Content-Length': '0', Connection: 'close',
        ...(location ? { Location: location } : {}),
      });
      response.end();
    };
    // Do not log request.url: it contains the authorization code and state.
    const raw = request.url;
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > 8192) return finish(414);
    if (!raw.startsWith('/oauth/callback?') && raw !== '/oauth/callback') return finish(404);
    if (request.method !== 'GET') return finish(405);
    if (request.headers['transfer-encoding'] !== undefined
        || (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0')) {
      return finish(400);
    }
    let allowed;
    try { allowed = await rateLimiter.consume(request.socket.remoteAddress); }
    catch { return finish(503); }
    if (allowed !== true) return finish(429);
    // Reject bad escapes/UTF-8 rather than accepting URLSearchParams replacement characters.
    let query;
    try {
      query = raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : '';
      decodeURIComponent(query.replaceAll('+', ' '));
    } catch { return finish(400); }
    if (raw.includes('#')) return finish(400);
    const parameters = new URLSearchParams(query);
    const input = Object.create(null);
    for (const [key, value] of parameters) {
      if (!['state', 'code', 'error'].includes(key) || Object.hasOwn(input, key)
          || !value || /[\u0000-\u001f\u007f-\u009f]/.test(value)) return finish(400);
      input[key] = value;
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.state ?? '')
        || (Object.hasOwn(input, 'code') === Object.hasOwn(input, 'error'))
        || (input.code?.length ?? 0) > 4096 || (input.error?.length ?? 0) > 128) return finish(400);
    try {
      const result = await lifecycle.callback(input);
      const location = new URL(result.location);
      if (location.origin !== completion.origin || location.pathname !== completion.pathname
          || location.username || location.password || location.hash) return finish(503);
      const seen = new Set();
      for (const [key, value] of location.searchParams) {
        if (seen.has(key) || !['outcome', 'platform_id', 'error_code'].includes(key)) return finish(503);
        seen.add(key);
        if (key === 'outcome' && !['connected', 'error'].includes(value)) return finish(503);
        if (key === 'platform_id' && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value)) return finish(503);
        if (key === 'error_code' && !/^oauth_[a-z_]{1,80}$/.test(value)) return finish(503);
      }
      if (!seen.has('outcome')) return finish(503);
      return finish(303, location.href);
    } catch { return finish(503); }
  };
}
