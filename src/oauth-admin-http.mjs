// SPDX-License-Identifier: AGPL-3.0-only
import { createOAuthBrowserBinding, oauthBrowserBindingCookie } from './oauth-browser-binding.mjs';
// Inbound HTTP only. authenticateAndAuthorize must consult canonical Gateway
// authority, never request-supplied tenant or connector-side role mirrors.
export function createOAuthAdminHandler({ lifecycle, authenticateAndAuthorize, rateLimiter, adminOrigin } = {}) {
  if (typeof globalThis.window !== 'undefined' || typeof lifecycle?.start !== 'function'
      || typeof authenticateAndAuthorize !== 'function' || typeof rateLimiter?.consume !== 'function') {
    throw new Error('invalid_admin_configuration');
  }
  let origin;
  try { origin = new URL(adminOrigin); } catch { throw new Error('invalid_admin_origin'); }
  if (origin.protocol !== 'https:' || origin.origin !== adminOrigin) throw new Error('invalid_admin_origin');
  return async (request, response) => {
    let browserCookie;
    const finish = (status, value) => {
      const body = value ? JSON.stringify(value) : '';
      response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', Connection: 'close',
        ...(browserCookie ? {'Set-Cookie':browserCookie} : {}) });
      response.end(body);
    };
    const path = /^\/platforms\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})\/oauth\/start$/.exec(request.url ?? '');
    if (!path) return finish(404);
    if (request.method !== 'POST') return finish(405);
    // This browser-admin endpoint requires a same-origin request. Cookie/session
    // verification, CSRF token policy and canonical permission checks additionally
    // belong to the explicit authenticator. No CORS headers are emitted.
    const headerCount = name => request.rawHeaders.filter((_, index) => index % 2 === 0
      && request.rawHeaders[index].toLowerCase() === name).length;
    if (headerCount('origin') !== 1 || request.headers.origin !== adminOrigin) return finish(403);
    if (headerCount('content-type') !== 1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'])) return finish(415);
    let allowed;
    try { allowed = await rateLimiter.consume(request.socket.remoteAddress); } catch { return finish(503); }
    if (allowed !== true) return finish(429);
    let identity;
    try { identity = await authenticateAndAuthorize(request, { platformId: path[1], action: 'integration-connector:edit' }); }
    catch { return finish(503); }
    if (!identity) return finish(401);
    if (identity.authorized !== true || typeof identity.organizationId !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(identity.organizationId)) return finish(403);
    const chunks = []; let size = 0;
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 8192) return finish(413);
        chunks.push(chunk);
      }
    } catch { return finish(400); }
    let form;
    try {
      const body = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
      decodeURIComponent(body.replaceAll('+', ' '));
      form = new URLSearchParams(body);
    } catch { return finish(400); }
    const fields = Object.create(null);
    for (const [key, value] of form) {
      if (!['client_id', 'client_secret_ref', 'capabilities'].includes(key)
          || Object.hasOwn(fields, key) || !value) return finish(400);
      fields[key] = value;
    }
    if (!fields.client_id || !fields.client_secret_ref || !fields.capabilities) return finish(400);
    const capabilities = fields.capabilities.split(',');
    if (capabilities.length > 32 || new Set(capabilities).size !== capabilities.length
        || capabilities.some(value => !/^[A-Za-z0-9_.-]{1,128}$/.test(value))) return finish(400);
    try {
      const browserBinding=createOAuthBrowserBinding();
      const result = await lifecycle.start({ browserBinding, organizationId: identity.organizationId, platformId: path[1],
        clientId: fields.client_id, clientSecretRef: fields.client_secret_ref, capabilities });
      // Proof must return to this exact connector origin/path. No substituted
      // callback or ambiguous state may receive a browser binding cookie.
      const authorization=new URL(result.authorizationUrl);
      const redirectUri=new URL('/oauth/callback',origin).href;
      const state=authorization.searchParams.get('state');
      if(authorization.protocol!=='https:' || authorization.username || authorization.password || authorization.hash
          || authorization.pathname!=='/login/oauth2/auth'
          || authorization.searchParams.getAll('state').length!==1
          || !/^[A-Za-z0-9_-]{43}$/.test(state??'')
          || result.redirectUri!==redirectUri
          || authorization.searchParams.getAll('redirect_uri').length!==1
          || authorization.searchParams.get('redirect_uri')!==redirectUri) throw Error('invalid_start_result');
      browserCookie=oauthBrowserBindingCookie(state,browserBinding);
      // Return only the lifecycle's URL; no repository snapshots or secret refs.
      return finish(200, { authorizationUrl: result.authorizationUrl });
    } catch { return finish(409, { error: 'authorization_start_failed' }); }
  };
}
