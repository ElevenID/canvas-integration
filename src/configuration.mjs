// SPDX-License-Identifier: AGPL-3.0-only
import { open, constants } from 'node:fs/promises';
import { GatewayError } from './gateway-client.mjs';

const FORBIDDEN_ENV = /^(?:DATABASE_URL|REDIS_URL|ISSUANCE_API_KEY(?:_FILE)?|ISSUANCE_INTERNAL_API_BASE_URL|SIGNING_KEYS_.*|BAO_TOKEN(?:_FILE)?|VAULT_TOKEN(?:_FILE)?|INTEGRATION_SECRET_MASTER_KEY.*)$/;

async function readFile(path, secret) {
  let handle;
  try {
    if (typeof path !== 'string' || !path) throw new Error();
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > (secret ? 1024 : 65536)) throw new Error();
    if (secret && process.platform !== 'win32' && (stat.mode & 0o077)) throw new Error();
    return (await handle.readFile('utf8')).trim();
  } catch { throw new GatewayError(secret ? 'invalid_key_file' : 'invalid_ca_file'); }
  finally { await handle?.close(); }
}

/** The CLI never reads a raw key from argv, browser storage or internal-service variables. */
export async function loadConfiguration(environment = process.env) {
  if (Object.keys(environment).some(key => FORBIDDEN_ENV.test(key))) throw new GatewayError('internal_configuration_forbidden');
  if (Object.hasOwn(environment, 'MARTY_GATEWAY_API_KEY')) throw new GatewayError('key_file_required');
  return {
    gatewayOrigin: environment.MARTY_GATEWAY_ORIGIN,
    organizationId: environment.MARTY_ORGANIZATION_ID,
    apiKey: await readFile(environment.MARTY_GATEWAY_API_KEY_FILE, true),
    ...(environment.MARTY_GATEWAY_CA_FILE ? { ca: await readFile(environment.MARTY_GATEWAY_CA_FILE, false) } : {}),
  };
}
