// SPDX-License-Identifier: AGPL-3.0-only
/** Removed Canvas-specific Marty administration API. Use the documented generic
 * Gateway adapters; this compatibility entry point cannot perform any request.
 */
export class GatewayError extends Error {
  constructor() {
    super('Canvas-specific Marty Gateway API has been retired');
    this.name = 'GatewayError';
    this.code = 'retired_gateway_api';
  }
}
export function createGatewayClient() {
  throw new GatewayError();
}
