#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
import { loadConnectorOAuthConfiguration } from '../src/oauth-service-config.mjs';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';

const forbidden = /^(?:DATABASE_URL|REDIS_URL|PG[A-Z_]*|BAO_TOKEN(?:_FILE)?|VAULT_TOKEN(?:_FILE)?|MARTY_GATEWAY_API_KEY(?:_FILE)?|ISSUANCE_.*|SIGNING_KEYS_.*|INTEGRATION_SECRET_MASTER_KEY.*|NODE_TLS_REJECT_UNAUTHORIZED)$/;
const controller = new AbortController();
let runtime, stopping = false, shutdown;
const starting = Promise.resolve().then(async () => {
  if (process.argv.length !== 2 || Object.keys(process.env).some(name => forbidden.test(name))) throw Error();
  const configuration = await loadConnectorOAuthConfiguration({ path: process.env.CANVAS_CONNECTOR_CONFIG_FILE, signal: controller.signal });
  if (stopping) return;
  runtime = await createConnectorOAuthRuntime(configuration);
  if (stopping) { await runtime.close(); return; }
  const address = await runtime.listen();
  if (!stopping) console.log(JSON.stringify({ state: 'listening', port: address.port }));
}).catch(async () => {
  if (!stopping) { process.exitCode = 1; console.error(JSON.stringify({ state: 'failed', code: 'connector_service_startup_failed' })); }
  try { await runtime?.close(); } catch { process.exitCode = 1; }
});

function stop() {
  if (shutdown) return;
  stopping = true; controller.abort();
  // Handle rejection immediately, even while startup is still pending.
  const closed = runtime ? runtime.close().then(() => true, () => false) : Promise.resolve(true);
  shutdown = (async () => {
    await starting;
    if (!await closed) throw Error();
    await runtime?.close();
    console.log(JSON.stringify({ state: 'stopped' }));
  })().catch(() => {
    process.exitCode = 1; console.error(JSON.stringify({ state: 'failed', code: 'connector_service_shutdown_failed' }));
  }).finally(() => {
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  });
}
process.on('SIGINT', stop); process.on('SIGTERM', stop);
await starting;
