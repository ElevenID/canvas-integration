// SPDX-License-Identifier: AGPL-3.0-only
import { request as httpsRequest } from 'node:https';

const fail = () => { throw new Error('gateway_admin_auth_unavailable'); };
export function createGatewayAdminAuthenticator({ gatewayOrigin, adminOrigin, sessionCookieName, ca, timeoutMs = 15000 } = {}) {
  let gateway; let admin;
  try { gateway = new URL(gatewayOrigin); admin = new URL(adminOrigin); } catch { fail(); }
  if (gateway.protocol !== 'https:' || gateway.username || gateway.password || gateway.search || gateway.hash
      || gateway.pathname !== '/' || gateway.origin !== gatewayOrigin
      || /^(?:issuance|issuance-native|postgres|redis|signing-keys|auth|organization)(?:\.|$)/i.test(gateway.hostname)
      || /(?:\.svc|\.cluster\.local|\.internal)$/i.test(gateway.hostname) || gateway.hostname === '169.254.169.254'
      || admin.protocol !== 'https:' || admin.origin !== adminOrigin
      || typeof sessionCookieName !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(sessionCookieName)
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 120000
      || (ca !== undefined && (typeof ca !== 'string' || !ca.includes('-----BEGIN CERTIFICATE-----')
        || ca.length > 65536 || /PRIVATE KEY/.test(ca))) || typeof globalThis.window !== 'undefined') fail();

  function read(path, cookie, signal) {
    return new Promise((resolve, reject) => {
      let req; let settled = false;
      const finish = (error, value) => {
        if (settled) return; settled = true;
        if (error) { req?.destroy(); reject(new Error('gateway_admin_auth_unavailable')); } else resolve(value);
      };
      req = httpsRequest(new URL(path, gateway), { method: 'GET', agent: false, rejectUnauthorized: true,
        minVersion: 'TLSv1.2', maxHeaderSize: 16384, signal,
        ...(ca === undefined ? {} : { ca }),
        headers: { Accept: 'application/json', 'Accept-Encoding': 'identity', Cookie: cookie },
      }, response => {
        response.on('error', () => finish(true)); response.on('aborted', () => finish(true));
        if ([401, 403].includes(response.statusCode)) {
          finish(false, null); response.destroy(); return;
        }
        if (response.statusCode !== 200) return finish(true);
        if (String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json'
            || !['', 'identity'].includes(String(response.headers['content-encoding'] ?? ''))) return finish(true);
        let size = 0; const chunks = [];
        response.on('data', chunk => {
          size += chunk.length;
          if (size > 65536) return finish(true);
          if (!settled) chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          try { finish(false, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
          catch { finish(true); }
        });
      });
      req.on('error', () => finish(true)); req.end();
    });
  }
  return async (incoming, operation) => {
    if (operation?.action !== 'integration-connector:edit'
        || typeof operation.platformId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(operation.platformId)) fail();
    const originValues = incoming.rawHeaders.filter((_, index) => index % 2 === 1
      && incoming.rawHeaders[index - 1].toLowerCase() === 'origin');
    if (originValues.length !== 1 || originValues[0] !== adminOrigin) return null;
    const cookies = incoming.rawHeaders.flatMap((value, index) => index % 2 === 1
      && incoming.rawHeaders[index - 1].toLowerCase() === 'cookie' ? value.split(';') : []);
    if (cookies.join(';').length > 8192) return null;
    const values = cookies.map(value => value.trim()).filter(value => value.split('=')[0] === sessionCookieName);
    if (values.length !== 1) return null;
    const token = values[0].slice(sessionCookieName.length + 1);
    if (!/^[A-Za-z0-9._~-]{16,1024}$/.test(token)) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const cookie = `${sessionCookieName}=${token}`;
      const session = await read('/v1/auth/me', cookie, controller.signal);
      if (!session || session.authenticated !== true) return null;
      const user = session.user;
      if (!user || typeof user.user_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(user.user_id) || user.organization_context_unavailable === true
          || typeof user.organization_id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(user.organization_id)) return null;
      const permissions = await read(`/v1/organizations/${user.organization_id}/members/me/permissions`, cookie, controller.signal);
      const authorized = permissions !== null && Array.isArray(permissions.permissions)
        && permissions.permissions.every(value => typeof value === 'string')
        && permissions.permissions.includes('integration-connector:edit');
      return Object.freeze({ organizationId: user.organization_id, actorId: user.user_id, authorized });
    } catch { fail(); } finally { clearTimeout(timer); }
  };
}
