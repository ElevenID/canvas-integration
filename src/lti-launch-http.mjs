// SPDX-License-Identifier: AGPL-3.0-only
import { randomBytes, randomUUID } from 'node:crypto';
import { ltiBrowserCookie, readLtiBrowserCookie } from './lti-browser-binding.mjs';
import { ltiBridgePage, ltiResourcePage } from './lti-browser-pages.mjs';

const route = /^\/lti\/registrations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/(login|launch|confirm|resource)$/;
const validState = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
  && Buffer.from(value, 'base64url').toString('base64url') === value;
const storage = value => value === undefined ? null : ['_parent','post_message_forwarding'].includes(value) ? value : false;
const rawHeaders = (request, name) => request.rawHeaders.filter((value, index) => index % 2 === 1 && request.rawHeaders[index - 1].toLowerCase() === name);
function parameters(source, allowed) {
  try {
  if (source.includes('#')) throw Error();
  decodeURIComponent(source.replaceAll('+', ' ')); // Reject replacement decoding of malformed percent/UTF-8.
  const result = Object.create(null);
  for (const [key, value] of new URLSearchParams(source)) {
    if (!allowed.includes(key) || Object.hasOwn(result, key) || !value || /[\u0000-\u001f\u007f-\u009f]/.test(value)) throw Error();
    result[key] = value;
  }
  return result;
  } catch { throw Error('invalid_lti_request'); }
}
async function form(request, max, allowed) {
  const type = rawHeaders(request, 'content-type'), length = rawHeaders(request, 'content-length');
  if (type.length !== 1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=(?:utf-8|"utf-8"))?$/i.test(type[0]) ||
      length.length !== 1 || !/^[1-9][0-9]{0,5}$/.test(length[0]) || Number(length[0]) > max ||
      rawHeaders(request, 'transfer-encoding').length || rawHeaders(request, 'content-encoding').length) throw Error('invalid_lti_request');
  const body = await new Promise((resolve, reject) => {
    const chunks = [];let size = 0, settled = false;
    const done = (error, value) => {
      if (settled) return;settled = true;clearTimeout(timer);
      request.removeListener('data', data);request.removeListener('end', end);request.removeListener('error', abort);request.removeListener('aborted', abort);
      if (error) { request.pause();reject(Error('invalid_lti_request')); } else resolve(value);
    };
    const data = chunk => { size += chunk.length;if (size > max) done(true);else chunks.push(chunk); };
    const end = () => {
      if (size !== Number(length[0])) return done(true);
      try { done(false, new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch { done(true); }
    };
    const abort = () => done(true), timer = setTimeout(abort, 5000);
    request.on('data', data);request.once('end', end);request.once('error', abort);request.once('aborted', abort);
  });
  return parameters(body, allowed);
}
export function createLtiLaunchHandler({ lifecycle, rateLimiter, publicOrigin } = {}) {
  let origin;
  try { origin = new URL(publicOrigin); } catch { throw Error('invalid_lti_http_configuration'); }
  if (typeof globalThis.window !== 'undefined' || origin.protocol !== 'https:' || origin.origin !== publicOrigin ||
      !['begin','stage','confirm','active','browserContext'].every(name => typeof lifecycle?.[name] === 'function') ||
      typeof rateLimiter?.consume !== 'function') throw Error('invalid_lti_http_configuration');
  return async function ltiHandler(request, response) {
    const finish = (status, options = {}) => {
      if (response.destroyed) return;
      const body = options.body ?? '', nonce = options.nonce;
      response.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': String(Buffer.byteLength(body)),
        // Form navigation under no-referrer emits Origin:null. Bridge pages
        // disclose only the public origin, preserving exact-origin confirmation
        // while excluding paths, state and proofs from referrers.
        'Cache-Control': 'no-store', 'Referrer-Policy': nonce ? 'origin' : 'no-referrer', 'X-Content-Type-Options': 'nosniff', Connection: 'close',
        'Content-Security-Policy': `default-src 'none'; base-uri 'none'; object-src 'none'; script-src ${nonce ? "'nonce-" + nonce + "'" : "'none'"}; form-action ${publicOrigin} ${options.context?.storageOrigin ?? publicOrigin}; frame-ancestors ${options.context ? "'self' " + options.context.canvasOrigin + ' ' + options.context.storageOrigin : "'none'"}`,
        ...(options.cookie ? { 'Set-Cookie': options.cookie } : {}), ...(options.location ? { Location: options.location } : {}) });
      response.end(body);
    };
    if (typeof request.url !== 'string' || Buffer.byteLength(request.url) > 8192) return finish(414);
    if (request.rawHeaders.length > 128) return finish(431);
    const hosts = rawHeaders(request, 'host');if (hosts.length !== 1 || hosts[0] !== origin.host) return finish(421);
    const [path, query, extra] = request.url.split('?'), matched = route.exec(path);
    if (!matched || extra !== undefined) return finish(404);
    const [, registrationId, action] = matched, base = `/lti/registrations/${registrationId}`;
    if (!((action === 'login' || action === 'resource') ? ['GET','POST'].includes(request.method) : request.method === 'POST')) return finish(405);
    if (request.method === 'POST' && query !== undefined) return finish(400);
    if (request.method === 'GET' && (rawHeaders(request, 'transfer-encoding').length ||
      rawHeaders(request, 'content-encoding').length || rawHeaders(request, 'content-length').length > 1 ||
      rawHeaders(request, 'content-length').some(value => value !== '0'))) return finish(400);
    const origins = rawHeaders(request, 'origin');
    if (origins.length > 1 || ((action === 'confirm' || (action === 'resource' && request.method === 'POST')) &&
      (origins.length !== 1 || origins[0] !== publicOrigin))) return finish(403);
    try { if (await rateLimiter.consume() !== true) return finish(429); } catch { return finish(503); }
    const bridge = (mode, plan, target) => {
      const nonce = randomBytes(24).toString('base64url');
      return finish(200, { body: ltiBridgePage({ ...plan, mode, storageTarget: target, messageId: randomUUID(),
        action: publicOrigin + base + (mode === 'confirm' ? '/confirm' : '/resource') }, nonce), nonce, context: plan,
        ...(mode === 'login' ? { cookie: ltiBrowserCookie(plan.state, plan.browserProof) } : {}) });
    };
    const location = (state, target) => base + '/resource?' + new URLSearchParams({ state, ...(target === null ? {} : { storage_target: target }) }).toString();
    try {
      if (action === 'login') {
        const fields = ['iss','login_hint','lti_message_hint','target_link_uri','client_id','deployment_id','lti_deployment_id','canvas_region','canvas_environment','lti_storage_target'];
        const values = request.method === 'GET' ? parameters(query ?? '', fields) : await form(request, 20000, fields);
        if (values.deployment_id !== undefined && values.lti_deployment_id !== undefined) return finish(400);
        if ((values.canvas_region?.length ?? 0) > 64 || (values.canvas_environment?.length ?? 0) > 64) return finish(400);
        const target = storage(values.lti_storage_target);if (target === false) return finish(400);
        const plan = await lifecycle.begin({ registrationId, issuer: values.iss, loginHint: values.login_hint,
          messageHint: values.lti_message_hint, storageTarget: target ?? undefined, targetLinkUri: values.target_link_uri,
          clientId: values.client_id, deploymentId: values.deployment_id ?? values.lti_deployment_id });
        return bridge('login', plan, target);
      }
      if (action === 'launch') {
        const values = await form(request, 98304, ['state','id_token','lti_storage_target']);
        if (!validState(values.state)) return finish(400);
        const target = storage(values.lti_storage_target);if (target === false) return finish(400);
        const context = await lifecycle.browserContext({ registrationId, state: values.state });
        if (origins.length !== 1 || ![context.canvasOrigin,context.storageOrigin].includes(origins[0])) return finish(403);
        const cookie = readLtiBrowserCookie(request, values.state);if (cookie.kind === 'invalid') return finish(400);
        if (cookie.kind === 'absent' && target === null) return finish(403);
        const plan = await lifecycle.stage({ registrationId, state: values.state, token: values.id_token });
        if (cookie.kind === 'present') {
          await lifecycle.confirm({ registrationId, state: values.state, tokenHash: plan.tokenHash, browserProof: cookie.proof });
          return finish(303, { location: location(values.state, target), cookie: ltiBrowserCookie(values.state, cookie.proof) });
        }
        return bridge('confirm', plan, target);
      }
      if (action === 'confirm') {
        const values = await form(request, 2048, ['state','browser_proof','token_hash','storage_target']);
        if (!validState(values.state) || !validState(values.browser_proof) || !/^[a-f0-9]{64}$/.test(values.token_hash ?? '')) return finish(400);
        const target = storage(values.storage_target);if (target === false) return finish(400);
        await lifecycle.confirm({ registrationId, state: values.state, tokenHash: values.token_hash, browserProof: values.browser_proof });
        return finish(303, { location: location(values.state, target), cookie: ltiBrowserCookie(values.state, values.browser_proof) });
      }
      const values = request.method === 'GET' ? parameters(query ?? '', ['state','storage_target']) :
        await form(request, 2048, ['state','browser_proof','storage_target']);
      if (!validState(values.state)) return finish(400);
      const target = storage(values.storage_target);if (target === false) return finish(400);
      let proof = values.browser_proof;
      if (request.method === 'GET') {
        const cookie = readLtiBrowserCookie(request, values.state);if (cookie.kind === 'invalid') return finish(400);
        if (cookie.kind === 'present') proof = cookie.proof;
        else {
          const context = await lifecycle.browserContext({ registrationId, state: values.state });
          if (!context.current || context.phase !== 'accepted' || target === null) return finish(403);
          return bridge('resource', { ...context, state: values.state }, target);
        }
      }
      if (!validState(proof)) return finish(403);
      await lifecycle.active({ registrationId, state: values.state, browserProof: proof });
      const context = await lifecycle.browserContext({ registrationId, state: values.state });
      if (!context.current || context.phase !== 'accepted') return finish(403);
      return finish(200, { body: ltiResourcePage(), context, cookie: ltiBrowserCookie(values.state, proof) });
    } catch (error) {
      return finish(['invalid_lti_request','invalid_lti_launch','invalid_lti_browser_proof'].includes(error?.message) ? 400 :
        ['lti_launch_unavailable','lti_registration_unavailable','lti_launch_conflict'].includes(error?.message) ? 403 : 503);
    }
  };
}
