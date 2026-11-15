#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
import { createGatewayClient, GatewayError } from '../src/gateway-client.mjs';
import { loadConfiguration } from '../src/configuration.mjs';

try {
  if (process.argv.length !== 2) throw new GatewayError('arguments_forbidden');
  const client = createGatewayClient(await loadConfiguration());
  const platforms = await client.execute('listCanvasPlatforms');
  // Do not print platform records, names, tokens, URLs or tenant identifiers.
  console.log(JSON.stringify({ gatewayAccess: 'verified', operation: 'listCanvasPlatforms', count: platforms.length }));
} catch (error) {
  console.error(JSON.stringify({ gatewayAccess: 'failed', code: error instanceof GatewayError ? error.code : 'unexpected_error',
    ...(error instanceof GatewayError && error.status !== undefined ? { status: error.status } : {}) }));
  process.exitCode = 1;
}
