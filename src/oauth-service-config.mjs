// SPDX-License-Identifier: AGPL-3.0-only
import { resolve, isAbsolute } from 'node:path';
import { parsePrivateJson } from './private-json.mjs';
import { createPrivateTextFile } from './private-file.mjs';
import { createConnectorDatabasePasswordFile, createConnectorOpenBaoTokenFile } from './file-credentials.mjs';

const unavailable = () => new Error('connector_service_configuration_unavailable');
function fields(value, allowed) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !allowed.includes(key))) throw unavailable();
}
/** Read private static routing/TLS configuration once. Password/token values
 * remain in separate renewing files, read only by their purpose-specific APIs.
 * This function does no network I/O, provisioning or environment lookup.
 */
export async function loadConnectorOAuthConfiguration(options = {}) {
  try {
    fields(options, ['path', 'signal', 'timeoutMs']);
    const { path, signal, timeoutMs = 1000 } = options;
    const read = filename => createPrivateTextFile({ path: filename, timeoutMs, maxBytes: 65536 }).readText({ signal });
    const configuration = parsePrivateJson(await read(path));
    fields(configuration, ['schemaVersion', 'database', 'keyCustody', 'canvas', 'gatewayAuthentication', 'http', 'lti']);
    if (configuration.schemaVersion !== 1) throw unavailable();
    const { database, keyCustody, http, gatewayAuthentication } = configuration;
    const canvas = configuration.canvas === undefined ? {} : configuration.canvas;
    const lti = configuration.lti;
    if (lti !== undefined) fields(lti, ['selfManagedOriginAllowlist','allowedPrivateAddresses','caFile','timeoutMs']);
    fields(database, ['host', 'port', 'database', 'user', 'caFile', 'passwordFile', 'maxConnections', 'connectTimeoutMs', 'queryTimeoutMs']);
    fields(keyCustody, ['openbaoOrigin', 'mount', 'keyPath', 'keyNamespace', 'caFile', 'tokenFile', 'timeoutMs']);
    fields(gatewayAuthentication, ['gatewayOrigin', 'sessionCookieName', 'caFile', 'timeoutMs']);
    fields(canvas, ['caFile', 'allowedPrivateAddresses', 'timeoutMs', 'maxResponseBytes']);
    fields(http, ['publicOrigin', 'completionUrl', 'host', 'port', 'maxConcurrentRequests', 'tlsKeyFile', 'tlsCertificateFile']);
    const exclusive = [path, database.passwordFile, keyCustody.tokenFile, http.tlsKeyFile].map(filename => {
      if (typeof filename !== 'string' || !isAbsolute(filename)) throw unavailable();
      return resolve(filename);
    });
    if (new Set(exclusive).size !== exclusive.length) throw unavailable();
    const identities = await Promise.all(exclusive.map((filename, index) => createPrivateTextFile({
      path: filename, timeoutMs, maxBytes: index === 1 || index === 2 ? 4098 : 65536,
    }).inspect({ signal })));
    if (new Set(identities.map(value => value.path)).size !== identities.length
        || new Set(identities.map(value => `${value.dev}:${value.ino}`)).size !== identities.length) throw unavailable();
    const { passwordFile, caFile: databaseCaFile, ...databaseOptions } = database;
    const { tokenFile, caFile: keyCaFile, ...keyOptions } = keyCustody;
    const { caFile: gatewayCaFile, ...gatewayOptions } = gatewayAuthentication;
    const { caFile: canvasCaFile, ...canvasOptions } = canvas;
    const { tlsKeyFile, tlsCertificateFile, ...httpOptions } = http;
    return {
      database: { ...databaseOptions, ca: await read(databaseCaFile),
        credentialProvider: createConnectorDatabasePasswordFile({ path: identities[1].path, timeoutMs }) },
      keyCustody: { ...keyOptions, ...(keyCaFile === undefined ? {} : { ca: await read(keyCaFile) }),
        tokenProvider: createConnectorOpenBaoTokenFile({ path: identities[2].path, timeoutMs }) },
      canvas: { ...canvasOptions, ...(canvasCaFile === undefined ? {} : { ca: await read(canvasCaFile) }) },
      ...(lti === undefined ? {} : { lti: {
        ...Object.fromEntries(Object.entries(lti).filter(([key])=>key!=='caFile')),
        ...(lti.caFile === undefined ? {} : { ca: await read(lti.caFile) }),
      } }),
      gatewayAuthentication: { ...gatewayOptions, ...(gatewayCaFile === undefined ? {} : { ca: await read(gatewayCaFile) }) },
      http: { ...httpOptions, tls: { key: await read(identities[3].path), cert: await read(tlsCertificateFile) } },
    };
  } catch { throw unavailable(); }
}
