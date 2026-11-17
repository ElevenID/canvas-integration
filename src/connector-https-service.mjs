// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from 'node:https';
import { createOAuthAdminHandler } from './oauth-admin-http.mjs';
import { createOAuthCallbackHandler } from './oauth-callback-http.mjs';
import { createOAuthAttemptRecoveryHandler } from './oauth-attempt-recovery.mjs';
import { createConnectionAdminHandler } from './connection-admin.mjs';
import { createPlatformAdminHandler } from './platform-admin.mjs';
import { createOAuthClientHandler } from './oauth-client-admin.mjs';
import { createCaptureRouteAdminHandler } from './capture-route-admin-http.mjs';
import { createLtiLaunchHandler } from './lti-launch-http.mjs';
import { createLtiRegistrationAdminHandler } from './lti-registration-admin-http.mjs';
import { createLtiProviderIdentityHandler } from './lti-provider-identity-http.mjs';
import { createLtiServiceAdminHandler } from './lti-service-admin-http.mjs';
import { createLtiCaptureAdminHandler } from './lti-capture-admin-http.mjs';
import { operatorPage, operatorScript, operatorStyles, operatorCompletionPage } from './operator-pages.mjs';

const invalid = () => new Error('invalid_connector_service_configuration');
const unavailable = () => new Error('connector_service_unavailable');
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const pem = value => (typeof value === 'string' || Buffer.isBuffer(value))
  && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= 65536;

// Incoming HTTPS only. Existing adapters retain all authorization, tenant,
// browser-binding and one-time-state checks. No outbound transport is added.
export function createConnectorHttpsService(configuration = {}) {
  if (typeof globalThis.window !== 'undefined' || !record(configuration)
      || Object.keys(configuration).some(key => !['publicOrigin', 'completionUrl', 'tls',
        'host', 'port', 'maxConcurrentRequests', 'lifecycle', 'authenticateAndAuthorize', 'rateLimiter','recoveryStore','connectionStore','platformStore','clientStore','captureStore','readBinding','ltiLifecycle','ltiRegistrationStore','ltiSelfManagedOriginAllowlist','ltiIdentityStore','ltiServices','ltiCaptureStore'].includes(key))) throw invalid();
  const { publicOrigin, completionUrl, tls, lifecycle, authenticateAndAuthorize, rateLimiter,
    host = '127.0.0.1', port = 8443, maxConcurrentRequests = 8 } = configuration;
  let origin;
  try { origin = new URL(publicOrigin); } catch { throw invalid(); }
  if (origin.protocol !== 'https:' || origin.origin !== publicOrigin
      || origin.username || origin.password || !['127.0.0.1', '0.0.0.0', '::1', '::'].includes(host)
      || !Number.isInteger(port) || port < 0 || port > 65535
      || !Number.isInteger(maxConcurrentRequests) || maxConcurrentRequests < 1 || maxConcurrentRequests > 32
      || !record(tls) || Object.keys(tls).sort().join(',') !== 'cert,key'
      || !pem(tls.cert) || !pem(tls.key)) throw invalid();
  let admin, callback, recovery, connections, platforms, clients, captures, lti, ltiAdmin, ltiIdentity, ltiServices, ltiCaptures, server;
  try {
    admin = createOAuthAdminHandler({ lifecycle, authenticateAndAuthorize, rateLimiter, adminOrigin: publicOrigin });
    callback = createOAuthCallbackHandler({ lifecycle, rateLimiter, completionUrl });
    if(configuration.ltiLifecycle!==undefined) lti=createLtiLaunchHandler({lifecycle:configuration.ltiLifecycle,rateLimiter,publicOrigin});
    if(configuration.ltiIdentityStore!==undefined) {
      if(configuration.ltiLifecycle===undefined)throw invalid();
      ltiIdentity=createLtiProviderIdentityHandler({store:configuration.ltiIdentityStore,rateLimiter,publicOrigin});
    }
    if(configuration.ltiRegistrationStore!==undefined) ltiAdmin=createLtiRegistrationAdminHandler({store:configuration.ltiRegistrationStore,
      authenticateAndAuthorize,rateLimiter,publicOrigin,selfManagedOriginAllowlist:configuration.ltiSelfManagedOriginAllowlist??[]});
    else if(configuration.ltiSelfManagedOriginAllowlist!==undefined) throw invalid();
    if(configuration.ltiServices!==undefined) {
      if(!record(configuration.ltiServices)||Object.keys(configuration.ltiServices).sort().join(',')!=='keyStore,lifecycle,recoveryStore,store')throw invalid();
      ltiServices=createLtiServiceAdminHandler({...configuration.ltiServices,authenticateAndAuthorize,rateLimiter,publicOrigin});
    }
    if(configuration.recoveryStore!==undefined) recovery=createOAuthAttemptRecoveryHandler({store:configuration.recoveryStore,
      authenticateAndAuthorize,rateLimiter,adminOrigin:publicOrigin});
    if(configuration.connectionStore!==undefined) connections=createConnectionAdminHandler({store:configuration.connectionStore,
      authenticateAndAuthorize,rateLimiter,adminOrigin:publicOrigin});
    if(configuration.platformStore!==undefined) platforms=createPlatformAdminHandler({store:configuration.platformStore,
      authenticateAndAuthorize,rateLimiter,adminOrigin:publicOrigin});
    if(configuration.clientStore!==undefined) clients=createOAuthClientHandler({store:configuration.clientStore,
      authenticateAndAuthorize,rateLimiter,adminOrigin:publicOrigin});
    if((configuration.captureStore!==undefined||configuration.ltiCaptureStore!==undefined)!==(configuration.readBinding!==undefined)) throw invalid();
    if(configuration.ltiCaptureStore!==undefined)ltiCaptures=createLtiCaptureAdminHandler({store:configuration.ltiCaptureStore,readBinding:configuration.readBinding,
      authenticateAndAuthorize,rateLimiter,publicOrigin});
    if(configuration.captureStore!==undefined) captures=createCaptureRouteAdminHandler({store:configuration.captureStore,readBinding:configuration.readBinding,
      authenticateAndAuthorize,rateLimiter,adminOrigin:publicOrigin});
    server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2',
      handshakeTimeout: 5000, maxHeaderSize: 16384, headersTimeout: 10000,
      requestTimeout: 15000, connectionsCheckingInterval: 1000 }, incoming);
  } catch { throw invalid(); }
  let state = 'created', starting, closing;
  const inFlight = new Set();
  const finish = (response, status) => {
    response.writeHead(status, { 'Content-Length': '0', 'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', Connection: 'close' });
    response.end();
  };
  async function dispatch(request, response) {
    const hosts = request.rawHeaders.filter((_, i) => i % 2 === 1 && request.rawHeaders[i - 1].toLowerCase() === 'host');
    if (hosts.length !== 1 || hosts[0] !== origin.host) return finish(response, 421);
    if (typeof request.url !== 'string' || Buffer.byteLength(request.url) > 8192) return finish(response, 414);
    if(request.url==='/admin/session') {
      if(request.method!=='POST') return finish(response,405);
      const count=name=>request.rawHeaders.filter((_,i)=>i%2===0 && request.rawHeaders[i].toLowerCase()===name).length;
      if(count('origin')!==1 || request.headers.origin!==publicOrigin) return finish(response,403);
      if(count('content-type')!==1 || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type']??'')) return finish(response,415);
      let identity;
      try {
        if(await rateLimiter.consume(request.socket.remoteAddress)!==true) return finish(response,429);
        for await(const chunk of request) if(chunk.length) return finish(response,400);
        identity=await authenticateAndAuthorize(request,{platformId:'operator-console',action:'integration-connector:edit'});
      }catch{return finish(response,503);}
      if(!identity) return finish(response,401);
      if(identity.authorized!==true || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(identity.organizationId??'')) return finish(response,403);
      const body=JSON.stringify({organizationId:identity.organizationId});
      response.writeHead(200,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store',
        'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',Connection:'close'});response.end(body);return;
    }
    const assets = {
      '/admin': ['text/html; charset=utf-8', () => operatorPage([
        ...(platforms ? ['platforms'] : []), ...(clients ? ['clients'] : []), ...(connections ? ['connections'] : []),
        ...(captures ? ['captures'] : []), ...(ltiAdmin ? ['lti'] : []), ...(ltiServices?['lti-services']:[]), ...(ltiCaptures?['lti-captures']:[]), ...(recovery ? ['recovery'] : [])])],
      '/admin/app.js': ['text/javascript; charset=utf-8', () => operatorScript],
      '/admin/styles.css': ['text/css; charset=utf-8', () => operatorStyles],
      '/complete': ['text/html; charset=utf-8', () => operatorCompletionPage],
    };
    let assetPath=request.url;
    if(assetPath.startsWith('/complete?')) {
      let valid=true;const seen=new Set();
      try {
        const query=assetPath.slice('/complete?'.length);decodeURIComponent(query.replaceAll('+',' '));
        for(const [name,value] of new URLSearchParams(query)) {
          if(seen.has(name) || !['outcome','platform_id','error_code'].includes(name)) valid=false;
          seen.add(name);
          if(name==='outcome' && !['connected','error'].includes(value)) valid=false;
          if(name==='platform_id' && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value)) valid=false;
          if(name==='error_code' && !/^oauth_[a-z_]{1,80}$/.test(value)) valid=false;
        }
      } catch {valid=false;}
      if(valid && seen.has('outcome')) assetPath='/complete';
    }
    if(Object.hasOwn(assets, assetPath)) {
      if(request.method!=='GET') return finish(response,405);
      const [type,render]=assets[assetPath], body=render();
      response.writeHead(200, {'Content-Type':type,'Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store',
        'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
        'Cross-Origin-Resource-Policy':'same-origin','Cross-Origin-Opener-Policy':'same-origin',
        'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        Connection:'close'});
      response.end(body);return;
    }
    if(ltiServices && (/^\/lti\/registrations\/[a-f0-9-]+\/jwks$/.test(request.url)||/^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/lti\/registrations\/[a-f0-9-]+\/(tool-key|service-credentials)\//.test(request.url)))return ltiServices(request,response);
    if(ltiIdentity && /^\/lti\/registrations\/[a-f0-9-]+\/provider-identity$/.test(request.url)) return ltiIdentity(request,response);
    if(lti && request.url.startsWith('/lti/registrations/')) return lti(request,response);
    if(ltiCaptures&&/^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/lti\/registrations\/[a-f0-9-]+\/capture-routes\//.test(request.url))return ltiCaptures(request,response);
    if(ltiAdmin && /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/lti\/registrations\//.test(request.url)) return ltiAdmin(request,response);
    if (request.url === '/oauth/callback' || request.url.startsWith('/oauth/callback?')) return callback(request, response);
    if (/^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/oauth\/start$/.test(request.url)) return admin(request, response);
    if(recovery && /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/oauth\/attempts\/(inspect|receipt|recover)$/.test(request.url)) return recovery(request,response);
    if(connections && /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/connection\/(inspect|receipt|disconnect)$/.test(request.url)) return connections(request,response);
    if(platforms && (request.url==='/platforms/catalog' || /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/configuration\/(inspect|receipt|create|change)$/.test(request.url))) return platforms(request,response);
    if(clients && /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/oauth\/client\/(inspect|receipt|provision)$/.test(request.url)) return clients(request,response);
    if(captures && /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/capture-routes\/(?:catalog|[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:inspect|receipt|capture|create|replace|activate|deactivate|schedule))$/.test(request.url)) return captures(request,response);
    return finish(response, 404);
  }
  function incoming(request, response) {
    if (request.rawHeaders.length > 128) return finish(response, 431);
    if (state !== 'listening' || inFlight.size >= maxConcurrentRequests) return finish(response, 503);
    // Reserve until the actual handler settles, even when the peer disconnects.
    // Releasing on response/socket close would admit unbounded background work.
    const work = Promise.resolve().then(() => dispatch(request, response)).catch(() => {
      if (!response.headersSent && !response.destroyed) finish(response, 500);
      else response.destroy();
    });
    inFlight.add(work);
    void work.then(() => inFlight.delete(work), () => inFlight.delete(work));
  }
  server.maxConnections = 64;
  // Preserve all bounded raw headers so duplicate security headers cannot be
  // hidden by Node's parsed-header truncation. Reject the count above instead.
  server.maxHeadersCount = 0;
  server.maxRequestsPerSocket = 1;
  server.setTimeout(30000, socket => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  // Never forward runtime/parser errors, URLs, headers or TLS material to logs.
  server.on('error', () => {});
  return Object.freeze({
    async listen() {
      if (state !== 'created') throw unavailable();
      state = 'starting';
      starting = new Promise((resolve, reject) => {
        const failed = () => { state = 'failed'; reject(unavailable()); };
        server.once('error', failed);
        server.listen(port, host, () => {
          server.removeListener('error', failed);
          if (state === 'starting') state = 'listening';
          const address = server.address();
          resolve(Object.freeze({ host, port: address.port }));
        });
      });
      return starting;
    },
    close() {
      if (closing) return closing;
      const wasStarting = state === 'starting';
      state = 'closing';
      closing = (async () => {
        if (wasStarting) await starting.catch(() => {});
        if (server.listening) await new Promise(resolve => server.close(resolve));
        // A disconnected HTTP peer does not mean a token exchange or durable
        // write stopped. Wait before the embedding process closes its pool/vault.
        await Promise.allSettled([...inFlight]);
        state = 'closed';
      })();
      return closing;
    },
  });
}
