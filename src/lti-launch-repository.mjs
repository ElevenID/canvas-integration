// SPDX-License-Identifier: AGPL-3.0-only
import { exactRecord } from './canvas-rest-contract.mjs';

const unavailable = () => { throw new Error('lti_launch_repository_unavailable'); };
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const version = value => Number.isSafeInteger(value) && value >= 1;
const time = value => Number.isSafeInteger(value) && value >= 0;
function receipt(value) {
  exactRecord(value, ['launchId','registrationId','organizationId','platformId','platformVersion','registrationVersion','acceptedAtMs'], 'invalid_lti_receipt');
  if (Object.keys(value).length !== 7 || !uuid(value.launchId) || !uuid(value.registrationId) ||
      !id(value.organizationId) || !id(value.platformId) || !version(value.platformVersion) ||
      !version(value.registrationVersion) || !time(value.acceptedAtMs)) unavailable();
  return Object.freeze({ ...value });
}
function state(value) {
  exactRecord(value, ['state_hash','launch_id','browser_hash','organization_id','platform_id','registration_id',
    'platform_version','registration_version','registration_snapshot','nonce','phase','token_hash','protocol_claims',
    'created_at','expires_at','accepted_at'], 'invalid_lti_state');
  const createdAtMs = Date.parse(value.created_at), expiresAtMs = Date.parse(value.expires_at);
  const acceptedAtMs = value.accepted_at === null ? null : Date.parse(value.accepted_at);
  if (Object.keys(value).length !== 16 || !hash(value.state_hash) || !hash(value.browser_hash) ||
      !uuid(value.launch_id) || !uuid(value.registration_id) || !id(value.organization_id) || !id(value.platform_id) ||
      !version(value.platform_version) || !version(value.registration_version) || !time(createdAtMs) ||
      !time(expiresAtMs) || expiresAtMs <= createdAtMs || expiresAtMs - createdAtMs > 300000 ||
      typeof value.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.nonce) ||
      !['pending','staged','accepted'].includes(value.phase)) unavailable();
  const snapshot = value.registration_snapshot;
  exactRecord(snapshot, ['canvasOrigin','trustProfile','environment','clientId','deploymentId','targetLinkUri'], 'invalid_lti_snapshot');
  if (Object.keys(snapshot).length !== 6) unavailable();
  if (value.phase === 'pending') {
    if (value.token_hash !== null || value.protocol_claims !== null || acceptedAtMs !== null) unavailable();
  } else if (!hash(value.token_hash) || value.protocol_claims === null || typeof value.protocol_claims !== 'object' ||
    Array.isArray(value.protocol_claims) || (value.phase === 'staged' ? acceptedAtMs !== null :
      (!time(acceptedAtMs) || acceptedAtMs < createdAtMs || acceptedAtMs >= expiresAtMs))) unavailable();
  return Object.freeze({ stateHash: value.state_hash, launchId: value.launch_id, browserHash: value.browser_hash,
    organizationId: value.organization_id, platformId: value.platform_id, registrationId: value.registration_id,
    platformVersion: value.platform_version, registrationVersion: value.registration_version,
    registrationSnapshot: Object.freeze({ ...snapshot }), nonce: value.nonce, phase: value.phase,
    tokenHash: value.token_hash, protocolClaims: value.protocol_claims === null ? null : Object.freeze({ ...value.protocol_claims }),
    createdAtMs, expiresAtMs, acceptedAtMs });
}
const registrationSelect = `jsonb_build_object('registrationId',r.id,'organizationId',r.organization_id,'platformId',r.platform_id,
 'version',r.version,'clientId',r.client_id,'deploymentId',r.deployment_id,'trustProfile',r.trust_profile,
 'environment',r.environment,'targetLinkUri',r.target_link_uri,'enabled',r.enabled,'platformVersion',p.config_version,
 'canvasOrigin',p.canvas_origin,'platformEnabled',p.enabled,'platformArchived',p.archived)`;
function registration(value) {
  const names = ['registrationId','organizationId','platformId','version','clientId','deploymentId','trustProfile',
    'environment','targetLinkUri','enabled','platformVersion','canvasOrigin','platformEnabled','platformArchived'];
  exactRecord(value, names, 'invalid_lti_registration');
  if (Object.keys(value).length !== names.length || !uuid(value.registrationId) || !id(value.organizationId) ||
      !id(value.platformId) || !version(value.version) || !version(value.platformVersion) ||
      ![value.enabled,value.platformEnabled,value.platformArchived].every(item => typeof item === 'boolean')) unavailable();
  return Object.freeze({ ...value });
}

export function createLtiLaunchRepository(pool) {
  if (typeof globalThis.window !== 'undefined' || typeof pool?.query !== 'function') unavailable();
  async function query(sql, parameters, decode) {
    try {
      const response = await pool.query(sql, parameters);
      if (!Array.isArray(response.rows) || response.rows.length !== 1 || !Object.hasOwn(response.rows[0], 'result')) unavailable();
      return response.rows[0].result === null ? null : decode(response.rows[0].result);
    } catch { unavailable(); }
  }
  return Object.freeze({
    async registration(registrationId) {
      if (!uuid(registrationId)) unavailable();
      return query(`SELECT (SELECT jsonb_build_object('registration',${registrationSelect},
        'nowMs',floor(extract(epoch FROM clock_timestamp())*1000)::bigint) FROM canvas_connector.lti_registrations r
        JOIN canvas_connector.platforms p ON p.organization_id=r.organization_id AND p.id=r.platform_id WHERE r.id=$1::uuid) AS result`,
      [registrationId], value => { if (!time(value.nowMs)) unavailable();return Object.freeze({ registration: registration(value.registration), nowMs: value.nowMs }); });
    },
    async context(stateHash) {
      if (!hash(stateHash)) unavailable();
      return query(`SELECT (SELECT jsonb_build_object('state',to_jsonb(s),'registration',${registrationSelect},
        'receipt',(SELECT a.receipt FROM canvas_connector.lti_launch_receipts a WHERE a.state_hash=s.state_hash),
        'nowMs',floor(extract(epoch FROM clock_timestamp())*1000)::bigint)
        FROM canvas_connector.lti_launch_states s JOIN canvas_connector.lti_registrations r ON r.id=s.registration_id
        JOIN canvas_connector.platforms p ON p.organization_id=r.organization_id AND p.id=r.platform_id WHERE s.state_hash=$1) AS result`,
      [stateHash], value => {
        if (!time(value.nowMs)) unavailable();
        const saved = state(value.state), defined = registration(value.registration);
        if (saved.registrationId !== defined.registrationId || saved.organizationId !== defined.organizationId || saved.platformId !== defined.platformId) unavailable();
        const accepted = value.receipt === null ? null : receipt(value.receipt);
        if ((saved.phase === 'accepted') !== (accepted !== null) || (accepted &&
          (accepted.launchId !== saved.launchId || accepted.registrationId !== saved.registrationId || accepted.organizationId !== saved.organizationId ||
           accepted.platformId !== saved.platformId || accepted.platformVersion !== saved.platformVersion ||
           accepted.registrationVersion !== saved.registrationVersion || accepted.acceptedAtMs !== saved.acceptedAtMs))) unavailable();
        return Object.freeze({ state: saved, registration: defined, receipt: accepted, nowMs: value.nowMs });
      });
    },
    async begin(input) {
      exactRecord(input, ['registrationId','platformVersion','registrationVersion','stateHash','browserHash','nonce','launchId'], 'invalid_lti_begin');
      if (!uuid(input.registrationId) || !uuid(input.launchId) || !version(input.platformVersion) || !version(input.registrationVersion) ||
          !hash(input.stateHash) || !hash(input.browserHash) || typeof input.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.nonce)) unavailable();
      return query('SELECT canvas_connector.begin_lti_launch($1::uuid,$2::bigint,$3::bigint,$4,$5,$6,$7::uuid) AS result',
        [input.registrationId,input.platformVersion,input.registrationVersion,input.stateHash,input.browserHash,input.nonce,input.launchId],state);
    },
    async stage(input) {
      exactRecord(input, ['stateHash','tokenHash','protocolClaims'], 'invalid_lti_stage');
      if (!hash(input.stateHash) || !hash(input.tokenHash)) unavailable();
      return query('SELECT canvas_connector.stage_lti_launch($1,$2,$3::jsonb) AS result',
        [input.stateHash,input.tokenHash,JSON.stringify(input.protocolClaims)],state);
    },
    async confirm(input) {
      exactRecord(input, ['stateHash','browserHash','tokenHash'], 'invalid_lti_confirm');
      if (!hash(input.stateHash) || !hash(input.browserHash) || !hash(input.tokenHash)) unavailable();
      return query('SELECT canvas_connector.confirm_lti_launch($1,$2,$3) AS result',
        [input.stateHash,input.browserHash,input.tokenHash],receipt);
    },
  });
}
