// SPDX-License-Identifier: AGPL-3.0-only
import { createConnectorPostgresPool } from './postgres-pool.mjs';
import { createPostgresRepository } from './postgres-repository.mjs';
import { createOpenBaoKeyProvider } from './openbao-key-provider.mjs';
import { createEncryptedVault } from './encrypted-vault.mjs';
import { createCanvasOAuthProvider } from './canvas-oauth-provider.mjs';
import { createCanvasOAuthLifecycle } from './canvas-oauth.mjs';
import { createGatewayAdminAuthenticator } from './gateway-admin-auth.mjs';
import { createConnectorHttpsService } from './connector-https-service.mjs';
import { createOAuthHttpRateLimiter } from './oauth-http-rate-limiter.mjs';
import { createOAuthAttemptRecoveryStore } from './oauth-attempt-recovery.mjs';
import { createConnectionAdminStore } from './connection-admin.mjs';
import { createPlatformAdminStore } from './platform-admin.mjs';
import { createOAuthClientStore } from './oauth-client-admin.mjs';
import { createCaptureRouteAdminStore } from './capture-route-admin-store.mjs';
import { createGatewayBindingReader } from './gateway-binding-reader.mjs';
import { createLtiLaunchRepository } from './lti-launch-repository.mjs';
import { createLtiLaunchLifecycle } from './lti-launch-lifecycle.mjs';
import { createLtiRegistrationAdminStore } from './lti-registration-admin-store.mjs';
import { preflightLtiRuntime } from './lti-runtime-preflight.mjs';
import { createLtiProviderIdentityStore } from './lti-provider-identity-store.mjs';
import { createLtiToolKeyStore } from './lti-tool-key-store.mjs';
import { createLtiServiceStore } from './lti-service-store.mjs';
import { createLtiServiceLifecycle } from './lti-service-lifecycle.mjs';
import { createLtiServiceRecoveryStore } from './lti-service-recovery-store.mjs';
import { preflightLtiServices } from './lti-service-preflight.mjs';
import { createLtiCaptureAdminStore } from './lti-capture-admin-store.mjs';
import { preflightLtiCaptureAdministration } from './lti-capture-admin-preflight.mjs';

const unavailable = () => new Error('connector_oauth_runtime_unavailable');
function fields(value, allowed) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !allowed.includes(key))) throw unavailable();
}
// No transport or authority replacement hooks: production adapters are composed
// here. Credential providers are explicitly scoped to their separate owners.
export async function createConnectorOAuthRuntime(configuration) {
  let pool, service;
  try {
    fields(configuration, ['database', 'keyCustody', 'canvas', 'gatewayAuthentication', 'http', 'lti']);
    const { database, keyCustody, canvas, gatewayAuthentication, http, lti } = configuration;
    if (lti !== undefined) {
      fields(lti, ['selfManagedOriginAllowlist','allowedPrivateAddresses','ca','timeoutMs','services','captures']);
      if(lti.services!==undefined&&typeof lti.services!=='boolean')throw unavailable();
      if(lti.captures!==undefined&&typeof lti.captures!=='boolean'||lti.captures===true&&lti.services!==true)throw unavailable();
    }
    fields(keyCustody, ['openbaoOrigin', 'mount', 'keyPath', 'keyNamespace', 'tokenProvider', 'ca', 'timeoutMs']);
    fields(gatewayAuthentication, ['gatewayOrigin', 'sessionCookieName', 'ca', 'timeoutMs']);
    fields(http, ['publicOrigin', 'completionUrl', 'tls', 'host', 'port', 'maxConcurrentRequests']);
    const keyProvider = createOpenBaoKeyProvider(keyCustody);
    const provider = createCanvasOAuthProvider(canvas);
    const authenticateAndAuthorize = createGatewayAdminAuthenticator({ ...gatewayAuthentication, adminOrigin: http.publicOrigin });
    pool = createConnectorPostgresPool(database);
    const repository = createPostgresRepository(pool);
    const secretVault = createEncryptedVault({ pool, keyProvider });
    let ltiServices;
    if(lti?.services===true) {
      const keyStore=createLtiToolKeyStore({pool,keyProvider}),store=createLtiServiceStore({pool,keyProvider});
      ltiServices={keyStore,store,recoveryStore:createLtiServiceRecoveryStore(pool),
        lifecycle:createLtiServiceLifecycle({store,toolKeyStore:keyStore,canvasPolicy:{ca:lti.ca,
          allowedPrivateAddresses:lti.allowedPrivateAddresses??[],timeoutMs:lti.timeoutMs??15000,maxResponseBytes:1048576}})};
    }
    const lifecycle = createCanvasOAuthLifecycle({ publicOrigin: http.publicOrigin,
      completionUrl: http.completionUrl, repository, secretVault, provider,requireConfiguredClient:true });
    service = createConnectorHttpsService({ ...http, lifecycle, authenticateAndAuthorize,...(ltiServices===undefined?{}:{ltiServices}),
      ...(lti?.captures===true?{ltiCaptureStore:createLtiCaptureAdminStore(pool)}:{}),
      ...(lti === undefined ? {} : {
        ltiLifecycle:createLtiLaunchLifecycle({repository:createLtiLaunchRepository(pool),publicOrigin:http.publicOrigin,
          platformPolicy:Object.fromEntries(Object.entries(lti).filter(([key])=>!['services','captures'].includes(key)))}),
        ltiRegistrationStore:createLtiRegistrationAdminStore(pool),
        ltiIdentityStore:createLtiProviderIdentityStore(pool),
        ltiSelfManagedOriginAllowlist:lti.selfManagedOriginAllowlist??[],
      }),
      recoveryStore:createOAuthAttemptRecoveryStore(pool),
      connectionStore:createConnectionAdminStore(pool),
      platformStore:createPlatformAdminStore(pool),
      clientStore:createOAuthClientStore(pool,secretVault),
      captureStore:createCaptureRouteAdminStore(pool),
      readBinding:createGatewayBindingReader({...gatewayAuthentication,adminOrigin:http.publicOrigin}),
      rateLimiter: createOAuthHttpRateLimiter(pool) });
    let state = 'created', starting, closing;
    async function preflight() {
      // This checks available adapter privileges, not schema provenance or a
      // production role approval. Actual DDL/role provisioning is owner-only.
      const result = await pool.query(`SELECT NOT EXISTS (
        SELECT 1 FROM (VALUES
          ('platforms','SELECT'),('secrets','SELECT'),('secrets','INSERT'),
          ('platforms','INSERT'),('platform_operation_audit','SELECT'),('platform_operation_audit','INSERT'),
          ('rest_capture_routes','SELECT'),('rest_route_operation_audit','SELECT'),
          ('oauth_client_configurations','SELECT'),('oauth_client_configurations','INSERT'),
          ('oauth_client_provisioning_audit','SELECT'),('oauth_client_provisioning_audit','INSERT'),
          ('authorizations','SELECT'),('authorizations','INSERT'),('authorizations','DELETE'),
          ('oauth_status','SELECT'),('oauth_status','INSERT'),('oauth_status','UPDATE'),
          ('connections','SELECT'),('connections','INSERT'),('connections','UPDATE'),
          ('connections','DELETE'),
          ('connection_operation_audit','SELECT'),('connection_operation_audit','INSERT'),
          ('authorization_attempts','SELECT'),('authorization_attempts','INSERT'),('authorization_attempts','UPDATE'),
          ('authorization_recovery_audit','SELECT'),('authorization_recovery_audit','INSERT'),
          ('revocation_jobs','SELECT'),('revocation_jobs','INSERT'),
          ('oauth_http_limit','SELECT')) AS required(name,privilege)
        WHERE NOT has_table_privilege(current_user,'canvas_connector.'||required.name,required.privilege)
      ) AND has_any_column_privilege(current_user,'canvas_connector.platforms','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.platforms','enabled','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.platforms','archived','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.oauth_client_configurations','client_id','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.oauth_client_configurations','client_secret_ref','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.oauth_client_configurations','platform_config_version','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.refresh_attempts','organization_id','SELECT')
        AND has_column_privilege(current_user,'canvas_connector.refresh_attempts','platform_id','SELECT')
        AND has_column_privilege(current_user,'canvas_connector.refresh_attempts','phase','SELECT')
        AND has_column_privilege(current_user,'canvas_connector.refresh_attempts','lease_until','SELECT')
        AND has_column_privilege(current_user,'canvas_connector.secrets','created_at','UPDATE')
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE
          tgrelid='canvas_connector.secrets'::regclass AND tgname='secret_creation_time'
          AND tgfoid='canvas_connector.keep_secret_created_at()'::regprocedure
          AND NOT tgisinternal AND tgenabled IN ('O','A') AND tgtype=19
          AND tgqual IS NULL AND tgnargs=0 AND tgattr=''::int2vector)
        AND (SELECT count(*)=9 FROM pg_catalog.pg_trigger t JOIN (VALUES
          ('connections','connection_identity','keep_connection_identity()',19),
          ('authorization_attempts','authorization_cleanup','fence_authorization_cleanup()',19),
          ('connection_operation_audit','connection_operation_audit_immutable','keep_connection_operation_audit()',27),
          ('platforms','platform_configuration_revision','bump_platform_configuration()',19),
          ('platform_operation_audit','platform_operation_audit_immutable','keep_platform_operation_audit()',27),
          ('oauth_client_provisioning_audit','oauth_client_provisioning_audit_immutable','keep_oauth_client_provisioning_audit()',27),
          ('rest_capture_routes','rest_route_revision','revise_rest_route()',19),
          ('rest_capture_jobs','rest_capture_immutable','protect_rest_capture()',27),
          ('rest_route_operation_audit','rest_route_operation_audit_immutable','keep_rest_route_operation_audit()',27)
          ) expected(relation,name,signature,kind)
          ON t.tgrelid=('canvas_connector.'||expected.relation)::regclass AND t.tgname=expected.name
          AND t.tgfoid=('canvas_connector.'||expected.signature)::regprocedure
          WHERE NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND t.tgtype=expected.kind
            AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
        AND NOT EXISTS(SELECT 1 FROM (VALUES
          ('rest_capture_routes','INSERT',ARRAY['organization_id','id','producer_ref','platform_id','binding_id','binding_revision','requirement','claim_names','effective_time_policy','enabled']),
          ('rest_capture_routes','UPDATE',ARRAY['binding_revision','requirement','claim_names','effective_time_policy','enabled']),
          ('rest_route_operation_audit','INSERT',ARRAY['organization_id','operation_id','platform_id','route_id','actor_id','action','request','receipt']),
          ('rest_capture_jobs','INSERT',ARRAY['organization_id','capture_id','producer_ref','route_id','route_version','platform_id','binding_id','binding_revision','requirement','claim_names','effective_time_policy']),
          ('rest_capture_jobs','SELECT',ARRAY['organization_id','capture_id','producer_ref','route_id','route_version','platform_id','binding_id','binding_revision','requirement','claim_names','effective_time_policy','phase','attempts','available_at','lease_id','lease_expires_at','last_error'])
          ) capability(relation,privilege,names) CROSS JOIN LATERAL unnest(capability.names) field(name)
          WHERE NOT has_column_privilege(current_user,'canvas_connector.'||capability.relation,field.name,capability.privilege))
        AND has_function_privilege(current_user,'canvas_connector.valid_rest_route(jsonb,text[])','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.administer_rest_route(text,text,text,uuid,text,text,bigint,bigint,jsonb)','EXECUTE')
        AND has_column_privilege(current_user,'canvas_connector.oauth_http_limit','hits','UPDATE')
        AND has_column_privilege(current_user,'canvas_connector.oauth_http_limit','window_started_at','UPDATE')
        AND has_function_privilege(current_user,'canvas_connector.consume_oauth_http_limit()','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.consume_authorization_attempt(text,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.begin_authorization_exchange(text,text,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.require_authorization_reconciliation(text,text,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.publish_authorization_connection(text,text,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.recover_authorization_attempt(text,text,text,bigint,uuid,text,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.disconnect_connection(text,text,uuid,bigint,uuid,text)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.administer_platform(text,text,uuid,text,text,text,bigint,boolean,boolean)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.provision_oauth_client(text,text,uuid,text,bigint,text,text,text,bytea,bytea,bytea,bytea)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.stage_authorization_result(text,text,text,text,text,bytea,bytea,bytea,text,text,bytea,bytea,bytea,timestamp with time zone)','EXECUTE')
        AND has_function_privilege(current_user,'canvas_connector.mark_authorization_pending(text,text,bigint,text)','EXECUTE') AS ready`);
      if (result?.rows?.length !== 1 || result.rows[0].ready !== true) throw unavailable();
      if (lti !== undefined) await preflightLtiRuntime(pool);
      if(ltiServices!==undefined)await preflightLtiServices(pool);
      if(lti?.captures===true)await preflightLtiCaptureAdministration(pool);
      const policy = await pool.query('SELECT request_limit,window_ms,hits FROM canvas_connector.oauth_http_limit WHERE singleton=true');
      if (policy?.rows?.length !== 1 || !Number.isInteger(policy.rows[0].request_limit)
          || policy.rows[0].request_limit < 1 || policy.rows[0].request_limit > 1000
          || !Number.isInteger(policy.rows[0].window_ms) || policy.rows[0].window_ms < 1000 || policy.rows[0].window_ms > 60000
          || !Number.isInteger(policy.rows[0].hits) || policy.rows[0].hits < 0 || policy.rows[0].hits > 1000) throw unavailable();
      const current = await keyProvider.current();
      try { if (!Buffer.isBuffer(current?.key) || current.key.length !== 32) throw unavailable(); }
      finally { if (Buffer.isBuffer(current?.key)) current.key.fill(0); }
    }
    function close() {
      if (closing) return closing;
      state = 'closing';
      closing = (async () => {
        const httpClosed = service.close();
        // Starting must finish its custody/schema probe before the pool closes.
        if (starting) await starting.catch(() => {});
        await httpClosed;
        await pool.close();
        state = 'closed';
      })();
      return closing;
    }
    return Object.freeze({
      async listen() {
        if (state !== 'created') throw unavailable();
        state = 'starting';
        starting = (async () => {
          await preflight();
          if (state !== 'starting') throw unavailable();
          const address = await service.listen();
          if (state === 'starting') state = 'listening';
          return address;
        })();
        try { return await starting; }
        catch { await close(); throw unavailable(); }
      },
      close,
    });
  } catch {
    try { await service?.close(); await pool?.close(); } catch { /* already bounded/redacted adapter failure */ }
    throw unavailable();
  }
}
