// SPDX-License-Identifier: AGPL-3.0-only
// Supply a connector-owned autocommit PostgreSQL pool. No default connection,
// environment lookup, credential storage, network transport or core database.
export function createPostgresRepository(pool) {
  if (typeof globalThis.window !== 'undefined' || typeof pool?.query !== 'function') {
    throw new Error('invalid_connector_database');
  }
  const query = async (sql, parameters = []) => {
    try { return await pool.query(sql, parameters); }
    catch { throw new Error('connector_database_unavailable'); }
  };
  const first = async (sql, values) => (await query(sql, values)).rows[0] ?? null;
  const platform = `SELECT id, organization_id AS "organizationId", canvas_origin AS "canvasOrigin",
    config_version::float8 AS "configVersion", enabled, archived FROM canvas_connector.platforms
    WHERE organization_id=$1 AND id=$2`;
  const connection = `SELECT organization_id AS "organizationId", platform_id AS "platformId",
    platform_config_version::float8 AS "platformConfigVersion", canvas_origin AS "canvasOrigin",
    client_id AS "clientId", client_secret_ref AS "clientSecretRef", access_token_ref AS "accessTokenRef",
    refresh_token_ref AS "refreshTokenRef", (extract(epoch FROM token_expires_at)*1000)::float8 AS "tokenExpiresAt",
    capabilities, scopes, status FROM canvas_connector.connections WHERE organization_id=$1 AND platform_id=$2`;
  return Object.freeze({
    async consumeAuthorizationAttempt(hash, browserBindingHash) {
      if (!/^[a-f0-9]{64}$/.test(hash ?? '') || !/^[a-f0-9]{64}$/.test(browserBindingHash ?? '')) return null;
      return first(`SELECT state_hash AS "stateHash",browser_binding_hash AS "browserBindingHash",state_hash AS "authorizationId",
        organization_id AS "organizationId",platform_id AS "platformId",
        platform_config_version::float8 AS "platformConfigVersion",canvas_origin AS "canvasOrigin",
        client_id AS "clientId",client_secret_ref AS "clientSecretRef",capabilities,scopes,redirect_uri AS "redirectUri",
        (extract(epoch FROM created_at)*1000)::float8 AS "createdAt",
        (extract(epoch FROM expires_at)*1000)::float8 AS "expiresAt"
        FROM canvas_connector.consume_authorization_attempt($1,$2)`,[hash,browserBindingHash]);
    },
    async beginAuthorizationExchange(hash, org, platform) {
      return (await first('SELECT canvas_connector.begin_authorization_exchange($1,$2,$3) AS ok',[hash,org,platform])).ok===true;
    },
    async requireAuthorizationReconciliation(hash, org, platform) {
      return (await first('SELECT canvas_connector.require_authorization_reconciliation($1,$2,$3) AS ok',[hash,org,platform])).ok===true;
    },
    async publishAuthorizationConnection(hash, org, platform) {
      return (await first('SELECT canvas_connector.publish_authorization_connection($1,$2,$3) AS ok',[hash,org,platform])).ok===true;
    },
    async authorizationAttempt(hash, org, platform) {
      // Internal recovery snapshot only; never returns code, browser proof,
      // plaintext, ciphertext or any provider response. No HTTP route is added.
      return first(`SELECT authorization_hash AS "authorizationId",organization_id AS "organizationId",
        platform_id AS "platformId",phase,access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef",
        (extract(epoch FROM token_expires_at)*1000)::float8 AS "tokenExpiresAt"
        FROM canvas_connector.authorization_attempts
        WHERE authorization_hash=$1 AND organization_id=$2 AND platform_id=$3`,[hash,org,platform]);
    },
    async claimRefresh(org, id) {
      return first(`SELECT id,lease_id AS "leaseId",organization_id AS "organizationId",platform_id AS "platformId",
        canvas_origin AS "canvasOrigin",client_id AS "clientId",client_secret_ref AS "clientSecretRef",
        access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef"
        FROM canvas_connector.claim_refresh($1,$2)`, [org, id]);
    },
    async beginRefreshExchange(id, lease) {
      return (await first('SELECT canvas_connector.begin_refresh_exchange($1,$2) AS ok', [id, lease])).ok === true;
    },
    async requireRefreshReconciliation(id, lease) {
      return (await first('SELECT canvas_connector.require_refresh_reconciliation($1,$2) AS ok', [id, lease])).ok === true;
    },
    async abandonUnstartedRefresh(id, lease) {
      return (await first('SELECT canvas_connector.abandon_unstarted_refresh($1,$2) AS ok', [id, lease])).ok === true;
    },
    async publishRefresh(id, lease) {
      return (await first('SELECT canvas_connector.publish_refresh($1,$2) AS ok',[id,lease])).ok===true;
    },
    async disconnect(org, id) {
      return (await first('SELECT canvas_connector.disconnect($1,$2) AS ok', [org, id])).ok === true;
    },
    async claimRevocation() {
      return first(`SELECT id,organization_id AS "organizationId",platform_id AS "platformId",
        canvas_origin AS "canvasOrigin",access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef",
        lease_id AS "leaseId",(provider_revoked_at IS NOT NULL) AS revoked FROM canvas_connector.claim_revocation()`, []);
    },
    async recordProviderRevocation(id, lease) {
      return (await first('SELECT canvas_connector.record_provider_revocation($1,$2) AS ok', [id, lease])).ok === true;
    },
    async finishRevocation(id, lease) {
      return (await first('SELECT canvas_connector.finish_revocation($1,$2) AS ok', [id, lease])).ok === true;
    },
    async retryRevocation(id, lease) {
      return (await first('SELECT canvas_connector.retry_revocation($1,$2) AS ok', [id, lease])).ok === true;
    },
    getPlatform: (org, id) => first(platform, [org, id]),
    connection: (org, id) => first(connection, [org, id]),
    async saveAuthorization(value) {
      const result = await query(`INSERT INTO canvas_connector.authorizations
        (state_hash,organization_id,platform_id,platform_config_version,canvas_origin,client_id,
         client_secret_ref,capabilities,scopes,redirect_uri,created_at,expires_at,browser_binding_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,to_timestamp($11::float8/1000),to_timestamp($12::float8/1000),$13)
        ON CONFLICT (state_hash) DO NOTHING RETURNING state_hash`,
      [value.stateHash, value.organizationId, value.platformId, value.platformConfigVersion,
        value.canvasOrigin, value.clientId, value.clientSecretRef, value.capabilities, value.scopes,
        value.redirectUri, value.createdAt, value.expiresAt, value.browserBindingHash]);
      return result.rows.length === 1;
    },
    async markAuthorizationPending(org, id, version, hash) {
      return (await first('SELECT canvas_connector.mark_authorization_pending($1,$2,$3,$4) AS ok',
        [org, id, version, hash])).ok === true;
    },
    async consumeAuthorization(hash, _now, browserBindingHash) {
      if (!/^[a-f0-9]{64}$/.test(browserBindingHash ?? '')) return null;
      // pool.query must commit this single statement before resolving. Never
      // pass a transaction-bound client: provider exchange follows this return.
      return first(`SELECT state_hash AS "stateHash", browser_binding_hash AS "browserBindingHash", state_hash AS "authorizationId",
        organization_id AS "organizationId", platform_id AS "platformId",
        platform_config_version::float8 AS "platformConfigVersion", canvas_origin AS "canvasOrigin",
        client_id AS "clientId", client_secret_ref AS "clientSecretRef", capabilities, scopes,
        redirect_uri AS "redirectUri", (extract(epoch FROM created_at)*1000)::float8 AS "createdAt",
        (extract(epoch FROM expires_at)*1000)::float8 AS "expiresAt"
        FROM canvas_connector.consume_authorization($1,$2)`, [hash,browserBindingHash]);
    },
    async cancelAuthorization(hash) {
      await query('DELETE FROM canvas_connector.authorizations WHERE state_hash=$1 RETURNING state_hash', [hash]);
    },
    async publishConnection(value, expectedVersion) {
      if (value.platformConfigVersion !== expectedVersion) return false;
      // A single autocommitted statement fences configuration via the schema
      // trigger. Only an explicit zero-row conflict is a definite rejection.
      // Exceptions propagate as unknown outcomes: lifecycle preserves vault refs.
      const result = await query(`INSERT INTO canvas_connector.connections
        (organization_id,platform_id,platform_config_version,canvas_origin,client_id,client_secret_ref,
         access_token_ref,refresh_token_ref,token_expires_at,capabilities,scopes,status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::float8/1000),$10,$11,'connected')
        ON CONFLICT (organization_id,platform_id) DO NOTHING RETURNING platform_id`,
      [value.organizationId, value.platformId, expectedVersion, value.canvasOrigin, value.clientId,
        value.clientSecretRef, value.accessTokenRef, value.refreshTokenRef, value.tokenExpiresAt,
        value.capabilities, value.scopes]);
      return result.rows.length === 1;
    },
    async markConnected(org, id, version, clientId, capabilities, scopes) {
      const result = await query(`WITH locked_platform AS MATERIALIZED (
        SELECT organization_id,id FROM canvas_connector.platforms
        WHERE organization_id=$1 AND id=$2 AND config_version=$3 AND enabled AND NOT archived FOR UPDATE
        ), current AS (
        SELECT p.organization_id, p.id FROM locked_platform p
        JOIN canvas_connector.connections c ON c.organization_id=p.organization_id AND c.platform_id=p.id
        WHERE c.platform_config_version=$3 AND c.client_id=$4 AND c.capabilities=$5 AND c.scopes=$6
          AND c.status='connected' FOR UPDATE OF c
        ) INSERT INTO canvas_connector.oauth_status(organization_id,platform_id,status)
          SELECT organization_id,id,'connected' FROM current
          ON CONFLICT (organization_id,platform_id) DO UPDATE SET status='connected',authorization_hash=NULL
          RETURNING platform_id`, [org, id, version, clientId, capabilities, scopes]);
      return result.rows.length === 1;
    },
    async markReauthorizationRequired(org, id) {
      // Acquire the platform before the connection, including after disablement.
      await query(`WITH locked AS (SELECT organization_id,id FROM canvas_connector.platforms
        WHERE organization_id=$1 AND id=$2 FOR UPDATE), changed AS (
        UPDATE canvas_connector.connections c SET status='reauthorization_required'
        FROM locked p WHERE c.organization_id=p.organization_id AND c.platform_id=p.id RETURNING c.platform_id
        ) INSERT INTO canvas_connector.oauth_status(organization_id,platform_id,status)
        SELECT $1,platform_id,'reauthorization_required' FROM changed
        ON CONFLICT (organization_id,platform_id) DO UPDATE SET status='reauthorization_required',authorization_hash=NULL
        RETURNING platform_id`, [org, id]);
    },
  });
}
