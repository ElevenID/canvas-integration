// SPDX-License-Identifier: AGPL-3.0-only
import { createPrivateTextFile } from './private-file.mjs';
const unavailable = () => new Error('connector_file_credential_unavailable');
function provider(configuration, purpose) {
  let reader;
  try {
    if (configuration === null || typeof configuration !== 'object' || Array.isArray(configuration)
        || Object.keys(configuration).some(key => !['path', 'timeoutMs'].includes(key))) throw unavailable();
    reader = createPrivateTextFile({ ...configuration, maxBytes: 4098 });
  } catch { throw unavailable(); }
  async function acquire(options = {}) {
    try {
      const signal = options?.signal;
      let value = await reader.readText(options);
      if (signal?.aborted) throw unavailable();
      if (value.endsWith('\r\n')) value = value.slice(0, -2);
      else if (value.endsWith('\n')) value = value.slice(0, -1);
      if (!value || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f-\u009f]/.test(value)
          || (purpose === 'openbao' && !/^[A-Za-z0-9._~-]{16,4096}$/.test(value))
          || (purpose === 'gateway' && !/^[A-Za-z0-9._~-]{32,512}$/.test(value))) throw unavailable();
      return value;
    } catch { throw unavailable(); }
  }
  return Object.freeze(purpose === 'database' ? { getPassword: acquire } : purpose==='gateway'?{getApiKey:acquire}:{ getToken: acquire });
}
export function createConnectorDatabasePasswordFile(configuration) { return provider(configuration, 'database'); }
export function createConnectorOpenBaoTokenFile(configuration) { return provider(configuration, 'openbao'); }
export function createConnectorGatewayApiKeyFile(configuration) { return provider(configuration, 'gateway'); }
