// SPDX-License-Identifier: AGPL-3.0-only
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';

const fail = () => { throw new Error('connector_vault_unavailable'); };
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const purposes = ['oauth_client_secret', 'oauth_access_token', 'oauth_refresh_token'];
function context(org, row) {
  return Buffer.from(JSON.stringify([1, org, row.reference, row.platform_id, row.provider, row.purpose, row.key_id]));
}
function keyCopy(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail();
  return Buffer.from(value);
}

/** Connector-only encrypted custody. Keys come from an explicit external key
 * provider, never the database, environment, Gateway or a plaintext fallback.
 */
export function createEncryptedVault({ pool, keyProvider } = {}) {
  if (typeof globalThis.window !== 'undefined' || typeof pool?.query !== 'function'
      || typeof keyProvider?.current !== 'function' || typeof keyProvider?.byId !== 'function') fail();
  const execute = async (sql, values) => {
    try { return await pool.query(sql, values); } catch { fail(); }
  };
  const load = async (org, reference) => {
    if (!id(org) || !id(reference)) fail();
    return (await execute(`SELECT reference,platform_id,provider,purpose,key_id,enabled,ciphertext,nonce,tag
      FROM canvas_connector.secrets WHERE organization_id=$1 AND reference=$2`, [org, reference])).rows[0] ?? null;
  };
  const encrypt = async (org, row, value) => {
    let key;
    try {
      const selected = await keyProvider.current();
      if (!id(selected?.id)) fail();
      key = keyCopy(selected.key);
      row.key_id = selected.id;
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      cipher.setAAD(context(org, row));
      return { ciphertext: Buffer.concat([cipher.update(value), cipher.final()]), nonce, tag: cipher.getAuthTag() };
    } catch { fail(); } finally { key?.fill(0); }
  };
  const decrypt = async (org, row) => {
    if (!row || row.enabled !== true) fail();
    let key; let partial;
    try {
      key = keyCopy(await keyProvider.byId(row.key_id));
      if (!Buffer.isBuffer(row.nonce) || row.nonce.length !== 12
          || !Buffer.isBuffer(row.tag) || row.tag.length !== 16 || !Buffer.isBuffer(row.ciphertext)) fail();
      const decipher = createDecipheriv('aes-256-gcm', key, row.nonce, { authTagLength: 16 });
      decipher.setAAD(context(org, row));
      decipher.setAuthTag(row.tag);
      partial = decipher.update(row.ciphertext);
      return Buffer.concat([partial, decipher.final()]);
    } catch { fail(); } finally { key?.fill(0); partial?.fill(0); }
  };
  const scope = (row, expected) => {
    if (expected===undefined) return;
    if (!id(expected?.platformId) || expected.provider!=='canvas' || !purposes.includes(expected.purpose)) fail();
    if (row && (row.platform_id!==expected.platformId || row.provider!==expected.provider || row.purpose!==expected.purpose)) fail();
  };
  return Object.freeze({
    async metadata(org, reference) {
      const row = await load(org, reference);
      return row ? Object.freeze({ organizationId: org, platformId: row.platform_id,
        provider: row.provider, purpose: row.purpose, enabled: row.enabled }) : null;
    },
    async put(org, metadata, value) {
      if (!id(org) || !id(metadata?.platformId) || metadata.provider !== 'canvas'
          || !purposes.includes(metadata.purpose) || typeof value !== 'string'
          || !value.length || value.length > 4096 || Buffer.byteLength(value) > 16384) fail();
      const row = { reference: randomUUID(), platform_id: metadata.platformId,
        provider: 'canvas', purpose: metadata.purpose };
      const plaintext = Buffer.from(value);
      let encrypted;
      try { encrypted = await encrypt(org, row, plaintext); } finally { plaintext.fill(0); }
      await execute(`INSERT INTO canvas_connector.secrets
        (organization_id,reference,platform_id,provider,purpose,key_id,ciphertext,nonce,tag)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING reference`,
      [org, row.reference, row.platform_id, row.provider, row.purpose, row.key_id,
        encrypted.ciphertext, encrypted.nonce, encrypted.tag]);
      return row.reference;
    },
    async get(org, reference, expected) {
      const row = await load(org, reference);
      scope(row,expected);
      let plaintext;
      try {
        plaintext = await decrypt(org, row);
        return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
      } catch { fail(); } finally { plaintext?.fill(0); }
    },
    // Encrypt first, then stage both ciphertexts AND their exact attempt refs
    // atomically. No plaintext or independent unassociated put is persisted.
    async stageRefreshResult(job,bundle,expiresAt) {
      if (!id(job?.id) || !id(job.leaseId) || !id(job.organizationId) || !id(job.platformId)
          || !Number.isSafeInteger(expiresAt) || expiresAt<=0) fail();
      const prepare=async(purpose,value)=>{
        if (typeof value!=='string' || !value.length || value.length>4096 || Buffer.byteLength(value)>16384) fail();
        const row={reference:randomUUID(),platform_id:job.platformId,provider:'canvas',purpose};
        const plaintext=Buffer.from(value);
        try {return {...row,...await encrypt(job.organizationId,row,plaintext),key_id:row.key_id};}
        finally {plaintext.fill(0);}
      };
      const access=await prepare('oauth_access_token',bundle?.accessToken);
      const refresh=bundle.refreshToken==null?null:await prepare('oauth_refresh_token',bundle.refreshToken);
      const result=await execute(`SELECT new_access_token_ref AS "accessTokenRef",new_refresh_token_ref AS "refreshTokenRef"
        FROM canvas_connector.stage_refresh_result($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,to_timestamp($15::float8/1000))`,
        [job.id,job.leaseId,job.organizationId,job.platformId,access.reference,access.key_id,access.ciphertext,access.nonce,access.tag,
          refresh?.reference??null,refresh?.key_id??null,refresh?.ciphertext??null,refresh?.nonce??null,refresh?.tag??null,expiresAt]);
      if (result.rows.length!==1) fail();
      return Object.freeze(result.rows[0]);
    },
    // Initial exchange counterpart of stageRefreshResult. All ciphertexts and
    // the durable attempt's refs commit together, including after config drift.
    async stageAuthorizationResult(attempt,bundle,expiresAt) {
      if (!/^[a-f0-9]{64}$/.test(attempt?.authorizationId ?? '')
          || !id(attempt.organizationId) || !id(attempt.platformId)
          || (expiresAt!==null && (!Number.isSafeInteger(expiresAt) || expiresAt<=0))) fail();
      const prepare=async(purpose,value)=>{
        if (typeof value!=='string' || !value.length || value.length>4096 || Buffer.byteLength(value)>16384) fail();
        const row={reference:randomUUID(),platform_id:attempt.platformId,provider:'canvas',purpose};
        const plaintext=Buffer.from(value);
        try {return {...row,...await encrypt(attempt.organizationId,row,plaintext),key_id:row.key_id};}
        finally {plaintext.fill(0);}
      };
      const access=await prepare('oauth_access_token',bundle?.accessToken);
      const refresh=bundle?.refreshToken==null?null:await prepare('oauth_refresh_token',bundle.refreshToken);
      const result=await execute(`SELECT access_token_ref AS "accessTokenRef",refresh_token_ref AS "refreshTokenRef"
        FROM canvas_connector.stage_authorization_result($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,to_timestamp($14::float8/1000))`,
        [attempt.authorizationId,attempt.organizationId,attempt.platformId,access.reference,access.key_id,
          access.ciphertext,access.nonce,access.tag,refresh?.reference??null,refresh?.key_id??null,
          refresh?.ciphertext??null,refresh?.nonce??null,refresh?.tag??null,expiresAt]);
      if (result.rows.length!==1) fail();
      return Object.freeze(result.rows[0]);
    },
    async rotate(org, reference) {
      const previous = await load(org, reference);
      let plaintext;
      try {
        plaintext = await decrypt(org, previous);
        const next = { ...previous };
        const encrypted = await encrypt(org, next, plaintext);
        const result = await execute(`UPDATE canvas_connector.secrets SET key_id=$3,ciphertext=$4,nonce=$5,tag=$6
          WHERE organization_id=$1 AND reference=$2 AND enabled
            AND key_id=$7 AND ciphertext=$8 AND nonce=$9 AND tag=$10
            AND platform_id=$11 AND provider=$12 AND purpose=$13 RETURNING reference`,
        [org, reference, next.key_id, encrypted.ciphertext, encrypted.nonce, encrypted.tag,
          previous.key_id, previous.ciphertext, previous.nonce, previous.tag,
          previous.platform_id, previous.provider, previous.purpose]);
        return result.rows.length === 1;
      } finally { plaintext?.fill(0); }
    },
    async delete(org, reference, expected) {
      if (!id(org) || !id(reference)) fail();
      if (expected!==undefined) {
        const row=await load(org,reference);scope(row,expected);
        if (!row) return;
        const deleted=await execute('DELETE FROM canvas_connector.secrets WHERE organization_id=$1 AND reference=$2 AND platform_id=$3 AND provider=$4 AND purpose=$5 RETURNING reference',
          [org,reference,expected.platformId,expected.provider,expected.purpose]);
        if (deleted.rows.length!==1) fail();
        return;
      }
      await execute('DELETE FROM canvas_connector.secrets WHERE organization_id=$1 AND reference=$2 RETURNING reference', [org, reference]);
    },
  });
}
