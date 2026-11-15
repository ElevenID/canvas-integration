// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanvasOAuthProvider } from '../src/canvas-oauth-provider.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const PRIVATE = ['127.0.0.1', '::1'];
const input = origin => ({
  canvasOrigin: origin,
  clientId: 'synthetic-client-id',
  clientSecret: 'synthetic-client-secret',
  code: 'synthetic-authorization-code',
  redirectUri: 'https://connector.example.test/oauth/callback',
});

test('authorization-code exchange uses the fixed Canvas token endpoint and form body', async () => {
  const fixture = await httpsFixture();
  try {
    let body = '';
    fixture.setHandler((req, res) => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        body = Buffer.concat(chunks).toString('utf8');
        json(res, { access_token: 'synthetic-access-token', refresh_token: 'synthetic-refresh-token', expires_in: 3600, token_type: 'Bearer' });
      });
    });
    const provider = createCanvasOAuthProvider({
      allowedPrivateAddresses: PRIVATE, ca: fixture.ca, timeoutMs: 3000,
    });
    const result = await provider.exchange(input(fixture.origin));
    assert.deepEqual(result, {
      accessToken: 'synthetic-access-token',
      refreshToken: 'synthetic-refresh-token',
      expiresInSeconds: 3600,
    });
    assert.equal(fixture.seen.length, 1);
    assert.equal(fixture.seen[0].method, 'POST');
    assert.equal(fixture.seen[0].url, '/login/oauth2/token');
    assert.equal(fixture.seen[0].headers.authorization, undefined);
    assert.equal(fixture.seen[0].headers['x-api-key'], undefined);
    const form = new URLSearchParams(body);
    assert.equal(form.get('grant_type'), 'authorization_code');
    assert.equal(form.get('client_id'), 'synthetic-client-id');
    assert.equal(form.get('client_secret'), 'synthetic-client-secret');
    assert.equal(form.get('code'), 'synthetic-authorization-code');
    assert.equal(form.get('redirect_uri'), 'https://connector.example.test/oauth/callback');
  } finally { await fixture.close(); }
});

test('refresh uses refresh_token grant and never returns response extras', async () => {
  const fixture = await httpsFixture();
  try {
    let body = '';
    fixture.setHandler((req, res) => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        body = Buffer.concat(chunks).toString('utf8');
        json(res, { access_token: 'rotated-access-token', expires_in: 120, token_type: 'Bearer', private: 'discarded' });
      });
    });
    const provider = createCanvasOAuthProvider({ allowedPrivateAddresses: PRIVATE, ca: fixture.ca });
    const result = await provider.refresh({
      canvasOrigin: fixture.origin,
      clientId: 'synthetic-client-id',
      clientSecret: 'synthetic-client-secret',
      refreshToken: 'synthetic-refresh-token',
    });
    assert.deepEqual(result, { accessToken: 'rotated-access-token', expiresInSeconds: 120 });
    const form = new URLSearchParams(body);
    assert.equal(form.get('grant_type'), 'refresh_token');
    assert.equal(form.get('refresh_token'), 'synthetic-refresh-token');
  } finally { await fixture.close(); }
});

test('Canvas redirects are rejected and credentials are not forwarded', async () => {
  const fixture = await httpsFixture();
  try {
    fixture.setHandler((_req, res) => {
      res.writeHead(302, { Location: 'https://gateway.example.test/v1/integrations/canvas/oauth/callback' });
      res.end();
    });
    const provider = createCanvasOAuthProvider({ allowedPrivateAddresses: PRIVATE, ca: fixture.ca });
    await assert.rejects(provider.exchange(input(fixture.origin)), { code: 'redirect_denied' });
    assert.equal(fixture.seen.length, 1);
  } finally { await fixture.close(); }
});

test('invalid origins and token response shapes fail closed', async () => {
  const provider = createCanvasOAuthProvider({ allowedPrivateAddresses: [] });
  for (const origin of [
    'http://canvas.example.test', 'https://canvas.example.test/path',
    'https://gateway.example.test', 'https://postgres', 'https://canvas.example.test.',
  ]) {
    await assert.rejects(provider.exchange(input(origin)));
  }
  const fixture = await httpsFixture();
  try {
    fixture.setHandler((_req, res) => json(res, { access_token: 'bad\nvalue' }));
    const local = createCanvasOAuthProvider({ allowedPrivateAddresses: PRIVATE, ca: fixture.ca });
    await assert.rejects(local.exchange(input(fixture.origin)), { code: 'invalid_token_response' });
  } finally { await fixture.close(); }
});

test('provider response size, TLS and absolute timeout are enforced', async () => {
  const fixture = await httpsFixture();
  try {
    const provider = createCanvasOAuthProvider({
      allowedPrivateAddresses: PRIVATE, ca: fixture.ca, maxResponseBytes: 128, timeoutMs: 100,
    });
    fixture.setHandler((_req, res) => json(res, { access_token: 'x'.repeat(512) }));
    await assert.rejects(provider.exchange(input(fixture.origin)), { code: 'response_too_large' });
    fixture.setHandler((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{');
      const timer = setInterval(() => res.write(' '), 10);
      res.on('close', () => clearInterval(timer));
    });
    await assert.rejects(provider.exchange(input(fixture.origin)), { code: 'timeout' });
    const untrusted = createCanvasOAuthProvider({ allowedPrivateAddresses: PRIVATE });
    await assert.rejects(untrusted.exchange(input(fixture.origin)), { code: 'transport_error' });
  } finally { await fixture.close(); }
});
