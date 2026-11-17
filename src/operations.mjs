// SPDX-License-Identifier: AGPL-3.0-only
// Adapted from Marty-ui's canvasIntegrationsApi.js. See NOTICE.md.
// This registry is an explicit compatibility surface, not a wildcard proxy.
const base = '/v1/integrations/canvas';
const platformFields = ['display_name', 'canvas_base_url', 'lti_client_id', 'lti_deployment_id', 'enabled'];
const bindingFields = ['application_template_id', 'credential_template_id', 'display_name',
  'auto_approve_on_evidence', 'evidence_requirements', 'canvas_scope', 'delivery_mode',
  'approval_policy_set_id', 'deployment_profile_id', 'feature_flags'];
const filters = ['status', 'platform_id', 'binding_id'];
const definitions = [
  ['listCanvasPlatforms', 'GET', `${base}/platforms`, 'list', [], true],
  ['getCanvasPlatform', 'GET', `${base}/platforms/{id}`, 'object'],
  ['getCanvasLtiRegistrationConfig', 'GET', `${base}/platforms/{id}/registration-config`, 'object'],
  ['getCanvasPlatformReadiness', 'GET', `${base}/platforms/{id}/readiness`, 'object'],
  ['listCanvasProgramBindings', 'GET', `${base}/program-bindings`, 'list', ['platform_id', 'application_template_id'], true],
  ['getCanvasProgramBinding', 'GET', `${base}/program-bindings/{id}`, 'object'],
  ['getCanvasSyncJob', 'GET', `${base}/canvas-sync-jobs/{id}`, 'object'],
  ['listCanvasSyncJobs', 'GET', `${base}/canvas-sync-jobs`, 'list', filters, true],
  ['listCanvasAwardCandidates', 'GET', `${base}/canvas-award-candidates`, 'list', filters, true],
  ['listCanvasEvidencePolicyReviews', 'GET', `${base}/evidence-policy-reviews`, 'list', ['status', 'binding_id'], true],
  ['getCanvasMirrorProvenance', 'GET', '/v1/issuance/delivery-records/canvas-credentials/provenance', 'object',
    ['delivery_record_id', 'external_credential_id', 'credential_id', 'canvas_account_id'], true],
  ['getCanvasMirrorHealth', 'GET', '/v1/issuance/organizations/{organization_id}/canvas-mirror-health', 'object'],
  ['createCanvasPlatform', 'POST', `${base}/platforms`, 'object', [], true, platformFields, true],
  ['updateCanvasPlatform', 'PUT', `${base}/platforms/{id}`, 'object', [], false, platformFields],
  ['finalizeCanvasLtiInstallation', 'PUT', `${base}/platforms/{id}/lti-installation`, 'object', [], false,
    ['lti_client_id', 'lti_deployment_id']],
  ['deleteCanvasPlatform', 'DELETE', `${base}/platforms/{id}`, 'optional'],
  ['createCanvasProgramBinding', 'POST', `${base}/platforms/{id}/program-bindings`, 'object', [], true, bindingFields, true],
  ['updateCanvasProgramBinding', 'PUT', `${base}/program-bindings/{id}`, 'object', [], false, bindingFields],
  ['deleteCanvasProgramBinding', 'DELETE', `${base}/program-bindings/{id}`, 'optional'],
  ['validateCanvasProgramBinding', 'POST', `${base}/program-bindings/{id}/validate`, 'object', [], false, []],
  ['activateCanvasProgramBinding', 'POST', `${base}/program-bindings/{id}/activate`, 'object', [], false, []],
  ['deactivateCanvasProgramBinding', 'POST', `${base}/program-bindings/{id}/deactivate`, 'object', [], false, []],
];
export const OPERATIONS = Object.freeze(Object.fromEntries(definitions.map(
  ([name, method, path, response, query = [], organizationQuery = false, fields, idempotent = false]) => [name,
    Object.freeze({ method, path, response, query: Object.freeze([...query]), organizationQuery,
      fields: fields === undefined ? undefined : Object.freeze([...fields]), idempotent,
      scope: method === 'GET' ? 'integrations:read' : 'integrations:write' })]
)));
export const READ_OPERATIONS = Object.freeze(Object.keys(OPERATIONS).filter(name => OPERATIONS[name].method === 'GET'));
