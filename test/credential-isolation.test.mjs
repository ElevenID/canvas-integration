// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createCanvasRestReader } from '../src/canvas-rest-reader.mjs';
import { createGatewayClient } from '../src/gateway-client.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

test('actual Canvas and Gateway HTTPS peers receive only their own credential types', async () => {
  const gateway = await httpsFixture();
  const canvas = await httpsFixture();
  const apiKey = 'synthetic_isolation_gateway_key_000000000001';
  const accessToken = 'synthetic_isolation_canvas_token_0000000001';
  try {
    gateway.setHandler((_req, res) => json(res, []));
    canvas.setHandler((_req, res) => json(res, { requirement_count: 2, requirement_completed_count: 2 }));
    const reader = createCanvasRestReader({ canvasOrigin: canvas.origin, accessToken, ca: canvas.ca,
      allowedPrivateAddresses: ['127.0.0.1', '::1'] });
    const consumer = createGatewayClient({ gatewayOrigin: gateway.origin, organizationId: 'synthetic-org', apiKey, ca: gateway.ca });
    const requirement = { factType: 'canvas.course_completion', courseId: '1', userId: '2' };
    await Promise.all([reader.readRequirement(requirement), consumer.execute('listCanvasPlatforms')]);
    assert.equal(canvas.seen.length, 1); assert.equal(gateway.seen.length, 1);
    assert.equal(canvas.seen[0].headers.authorization, `Bearer ${accessToken}`);
    assert.equal(canvas.seen[0].headers['x-api-key'], undefined);
    assert.ok(!JSON.stringify(canvas.seen).includes(apiKey));
    assert.equal(gateway.seen[0].headers['x-api-key'], apiKey);
    assert.equal(gateway.seen[0].headers.authorization, undefined);
    assert.ok(!JSON.stringify(gateway.seen).includes(accessToken));
    canvas.setHandler((_req, res) => { res.writeHead(302, { Location: `${gateway.origin}/v1/integrations/canvas/platforms` }); res.end(); });
    await assert.rejects(reader.readRequirement(requirement), { code: 'redirect_denied' });
    assert.equal(gateway.seen.length, 1, 'Canvas redirect never contacts Gateway');
    gateway.setHandler((_req, res) => { res.writeHead(307, { Location: `${canvas.origin}/api/v1/courses/1/users/2/progress` }); res.end(); });
    const canvasCount = canvas.seen.length;
    await assert.rejects(consumer.execute('listCanvasPlatforms'), { code: 'redirect_denied' });
    assert.equal(canvas.seen.length, canvasCount, 'Gateway redirect never contacts Canvas');
  } finally { await gateway.close(); await canvas.close(); }
});
test('Canvas provider package import fails in browser conditions', async () => {
  await assert.rejects(promisify(execFile)(process.execPath, ['--conditions=browser', '--input-type=module', '-e',
    "await import('@elevenid/canvas-integration/canvas-rest')"]), actual => {
    assert.match(actual.stderr, /server-only/); return true;
  });
});
