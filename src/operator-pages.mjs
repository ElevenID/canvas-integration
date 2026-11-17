// SPDX-License-Identifier: AGPL-3.0-only
// Public static shell. Every data read and mutation uses the existing authorized
// adapter; this page supplies no identity, tenant, credential or permission.
const input = (name, title, options = '') => `<label>${title}<input name="${name}" ${options} required></label>`;
const choice = (name, title, entries) => `<label>${title}<select name="${name}">${entries.map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}</select></label>`;
const revision = (name, title) => input(name, title, 'type="number" min="1" max="9007199254740991" step="1"');
const resource = () => input('resource_id', 'Route or registration ID', 'maxlength="128"');
const actions = (name, entries) => choice(name, 'Action', entries.map(value => [value, value.replaceAll('_', ' ')]));
const form = (id, title, contents, button = 'Submit change') => `<details><summary>${title}</summary><form id="${id}" method="post" action="/admin">${contents}<button>${button}</button></form></details>`;

export function operatorPage(features) {
  if (!Array.isArray(features) || features.some(value => !['platforms', 'clients', 'connections', 'captures', 'lti', 'lti-services', 'lti-captures', 'recovery'].includes(value))) throw Error('invalid_operator_features');
  const numeric = 'inputmode="numeric" pattern="[1-9][0-9]{0,19}" maxlength="20"';
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Canvas connections · ElevenID</title><link rel="stylesheet" href="/admin/styles.css"><script src="/admin/app.js" defer></script>
<header><a href="/">ElevenID</a><p>Integrations</p><h1>Canvas connections</h1><p>Manage Canvas access and capture settings. Your current ElevenID organization and permissions govern every action.</p></header>
<main data-features="${features.join(',')}"><p id="notice" role="status" aria-live="polite">Loading your current organization. Sign in to ElevenID on this origin first.</p><p id="organization">Organization context not loaded.</p>
<fieldset id="workspace" disabled><legend class="sr-only">Connection controls</legend><button id="reload-context" type="button">Reload organization context</button>
<section data-requires="platforms"><h2>Platforms</h2><div class="toolbar"><button id="catalog" type="button">Load platforms</button><button id="catalog-next" type="button" hidden>Next page</button></div><ul id="platform-list"></ul>
<label>Selected platform<input id="platform-id" maxlength="128" autocomplete="off"></label><label>Platform version<input id="platform-version" type="number" min="1" max="9007199254740991" step="1"></label>
<button id="inspect-platform" type="button">Inspect platform</button><p id="platform-status">No platform selected.</p>
${form('platform-create', 'Add a platform', input('platform_id', 'Platform ID', 'maxlength="128" autocomplete="off"') + input('canvas_origin', 'Canvas HTTPS origin', 'type="url" maxlength="2048"'), 'Create disabled platform')}
${form('platform-change', 'Enable, disable or archive', choice('mode', 'Platform state', [['enable', 'Enabled'], ['disable', 'Disabled'], ['archive', 'Archived']]))}</section>
<section data-requires="clients"><h2>Canvas OAuth</h2><p>Use the Canvas developer key approved for this platform. Secrets are submitted only to this connector and are never retained in this page’s request journal.</p>
<button id="inspect-client" type="button">Inspect developer key</button>
${form('client-provision', 'Provision or rotate developer key', input('client_id', 'Canvas client ID', 'maxlength="512" autocomplete="off"') + input('client_secret', 'Canvas client secret', 'type="password" maxlength="4096" autocomplete="new-password"'), 'Encrypt and provision')}
${form('oauth-start', 'Connect your Canvas account', `<fieldset><legend>Approved capabilities</legend>${[['catalog','Course catalog'],['native_activity_scores','Assignment and quiz scores'],['course_completion','Course completion'],['module_completion','Module completion'],['background_roster','Background roster']].map(([value,label])=>`<label class="check"><input type="checkbox" name="capabilities" value="${value}">${label}</label>`).join('')}</fieldset>`, 'Continue to Canvas')}
</section>
<section data-requires="connections"><h2>Connection status</h2><button id="inspect-connection" type="button">Inspect connection and pending work</button>
${form('connection-disconnect', 'Disconnect Canvas access', input('connection_id', 'Connection ID', 'maxlength="36"') + revision('expected_revision', 'Connection revision'), 'Disconnect and queue cleanup')}
</section>
<section data-requires="captures"><h2>Capture routes</h2><p>Create and approve the application’s evidence binding in ElevenID first. Enter its binding ID and current revision below. The server checks current Gateway authority; Canvas user IDs do not establish ElevenID identity.</p>
<button id="catalog-routes" type="button">List capture routes</button><button id="routes-next" type="button" hidden>Next route page</button>
${form('route-edit', 'Create or replace a route', actions('action',['create','replace']) + resource() + revision('expected_route_version','Route version for replacement') + input('producer_ref','Approved producer reference','maxlength="128"') + input('binding_id','ElevenID binding ID','maxlength="128"') + revision('binding_revision','Binding revision') + choice('fact_type','Observation',[['canvas.course_completion','Course completion'],['canvas.assignment_score','Assignment score'],['canvas.quiz_score','Quiz score'],['canvas.module_completion','Module completion']]) + input('course_id','Canvas course ID',numeric) + input('user_id','Canvas user ID',numeric) + `<label>Assignment or quiz ID<input name="activity_id" ${numeric}></label><label>Module ID<input name="module_id" ${numeric}></label><fieldset><legend>Claims allowed by the binding</legend>${['completed','score','score_maximum','score_percent','provider_state','requirement_count','requirement_completed_count'].map(value=>`<label class="check"><input type="checkbox" name="claims" value="${value}"${value==='completed'?' checked':''}>${value.replaceAll('_',' ')}</label>`).join('')}</fieldset>` + choice('effective_time_policy','Observation time',[['require_provider_time','Require Canvas timestamp'],['as_of_read','Time of read, when the binding permits it']]))}
${form('route-action', 'Inspect, activate or capture', resource() + actions('action',['inspect','activate','deactivate','schedule','capture']) + revision('expected_route_version','Route version') + `<label>Capture ID, for status inspection<input name="capture_id" maxlength="128"></label>`, 'Apply selected action')}
<p>Automatic cadence is configured in the private worker service. A route or capture does not verify evidence or authorize credential issuance.</p></section>
<section data-requires="lti"><h2>LTI registrations</h2><button id="catalog-lti" type="button">List registrations</button><button id="lti-next" type="button" hidden>Next registration page</button>
${form('lti-edit', 'Create or replace a registration', actions('action',['create','replace']) + resource() + revision('expected_registration_version','Registration version for replacement') + input('client_id','Canvas LTI client ID','maxlength="255"') + input('deployment_id','Canvas deployment ID','maxlength="255"') + choice('trust_profile','Platform trust',[['hosted_global','Canvas hosted'],['self_managed_same_origin','Explicitly allowed self-managed Canvas']]) + choice('environment','Hosted environment',[['production','Production'],['beta','Beta'],['test','Test']]))}
${form('lti-action', 'Inspect or change registration state', resource() + actions('action',['inspect','activate','deactivate']) + revision('expected_registration_version','Registration version'), 'Apply selected action')}
<p>Copy the returned target link URI into the approved Canvas tool configuration. Provider launch assertions remain separate from ElevenID account ownership.</p></section>
<section data-requires="lti-services"><h2>LTI service access</h2><p>Generate a tool key, copy the inspected public JWK URL into Canvas, and activate the registration before requesting approved read scopes. Key material and service tokens remain in connector custody.</p>
${form('lti-key','Inspect, provision or rotate a tool key',resource()+actions('action',['inspect','provision','rotate','deactivate'])+revision('expected_registration_version','Registration version')+revision('expected_key_version','Tool-key version'),'Apply key action')}
${form('lti-credential','Request or inspect service credentials',resource()+actions('action',['exchange','inspect','recover','catalog'])+revision('expected_registration_version','Registration version')+revision('expected_key_version','Tool-key version')+input('attempt_id','Original credential attempt ID','maxlength="36"')+`<label>After attempt ID (optional)<input name="after_id" maxlength="36"></label><fieldset><legend>Approved read scopes</legend>${[['results','Assignment results'],['lineitems','Line-item metadata'],['memberships','Resource membership']].map(([value,title])=>`<label class="check"><input type="checkbox" name="service_scopes" value="${value}"${value==='results'?' checked':''}>${title}</label>`).join('')}</fieldset>`,'Apply credential action')}
<p>An uncertain exchange is never repeated automatically. Inspect its original ID. Recovery of staged credentials only reconciles the stored result.</p>
${form('lti-service-recovery','Resolve a service attempt',resource()+input('attempt_id','Original credential attempt ID','maxlength="36"')+actions('action',['abandon_prepared','retire_known','resolve_unknown'])+choice('expected_phase','Current attempt phase',[['prepared','Prepared'],['exchanging','Exchanging'],['uncertain','Uncertain'],['staged','Staged'],['published','Published']])+revision('expected_registration_version','Current disabled registration version')+revision('expected_key_version','Current deactivated tool-key version')+input('confirmation_reference','External disposition record ID (operator attestation)','maxlength="36"'),'Record resolution')}
<p>Unknown-outcome resolution requires a disabled platform and registration, a deactivated tool key, and an external disposition record. It records your attestation; it does not verify remote revocation. Known tokens can retire only after their conservative expiry window.</p></section>
<section data-requires="lti-captures"><h2>LTI capture routes</h2><p>Use an approved ElevenID evidence binding and a published service credential attempt. The server checks their current scope and revisions. Scores and membership are provider observations; they do not establish ElevenID identity or completion.</p>
${form('lti-capture-edit','Create or replace an LTI capture route',input('registration_id','LTI registration ID','maxlength="36"')+input('resource_id','LTI capture route ID','maxlength="128"')+actions('action',['create','replace'])+revision('expected_route_version','Route version for replacement')+revision('expected_registration_version','Registration version')+revision('expected_key_version','Tool-key version')+input('service_operation_id','Published credential attempt ID','maxlength="36"')+input('producer_ref','Approved producer reference','maxlength="128"')+input('binding_id','ElevenID binding ID','maxlength="128"')+revision('binding_revision','Binding revision')+choice('fact_type','Observation',[['canvas.ags_result','AGS result'],['canvas.nrps_membership','NRPS membership']])+input('course_id','Canvas course ID',numeric)+input('provider_user_id','Opaque provider user ID','maxlength="255"')+input('resource_link_id','LTI resource link ID','maxlength="255"')+input('line_item_id','AGS line-item ID',numeric)+input('context_id','NRPS context ID','maxlength="255"')+`<fieldset><legend>Claims allowed by the binding</legend>${['score','score_maximum','score_percent','provider_state'].map(value=>`<label class="check"><input type="checkbox" name="lti_claims" value="${value}"${value==='score'?' checked':''}>${value.replaceAll('_',' ')}</label>`).join('')}</fieldset>`,'Save disabled LTI route')}
${form('lti-capture-action','Inspect, activate or schedule an LTI capture',input('registration_id','LTI registration ID','maxlength="36"')+input('resource_id','LTI capture route ID','maxlength="128"')+actions('action',['catalog','inspect','activate','deactivate','schedule','capture'])+revision('expected_route_version','Route version')+revision('expected_registration_version','Registration version')+revision('expected_key_version','Tool-key version')+input('service_operation_id','Published credential attempt ID','maxlength="36"')+input('capture_id','Original capture ID','maxlength="36"')+`<label>After route ID (optional)<input name="after_id" maxlength="128"></label>`,'Apply capture action')}
<p>These reads use their time of observation. Automatic cadence is configured in the private LTI worker. An unconfirmed response or permission loss can follow a committed change; keep the original operation ID until its receipt is reconciled.</p></section>
<section data-requires="recovery"><h2>Authorization recovery</h2><p>Inspect the original authorization before choosing an action. These actions do not repeat a token exchange.</p>
${form('recovery', 'Inspect or resolve an authorization attempt', input('authorization_id','Original authorization ID','pattern="[a-f0-9]{64}" maxlength="64"') + actions('mode',['inspect','recover']) + revision('expected_revision','Attempt revision') + actions('action',['abandon_unstarted','queue_staged_revocation','finish_staged_revocation']), 'Apply selected action')}
</section>
<section><h2>Original operation receipts</h2><p>Changes are never retried automatically. Pending IDs survive reload in this tab’s session storage; copy IDs before closing the tab. An absent receipt is a snapshot and does not prove rollback.</p><ul id="operations"></ul>
${form('receipt', 'Inspect a saved operation ID', choice('kind','Operation',[['platform','Platform'],['client','Developer key'],['connection','Disconnect'],['route','Capture route'],['lti','LTI registration'],['lti-key','LTI tool key'],['lti-credential','LTI credentials'],['lti-resolution','LTI service resolution'],['lti-capture','LTI capture route'],['recovery','Authorization recovery']]) + resource() + input('operation_id','Original operation ID','maxlength="36"') + `<label>LTI registration ID, for capture receipts<input name="registration_id" maxlength="36"></label><label>Authorization ID, for recovery receipts<input name="authorization_id" maxlength="64"></label><label>Credential attempt ID, for LTI resolution receipts<input name="attempt_id" maxlength="36"></label>`, 'Inspect original receipt')}
</section></fieldset><section><h2>Result</h2><pre id="result" tabindex="0">No inspection yet.</pre></section></main>
<footer>External observations remain unsigned producer attestations. Verification and issuance are governed by ElevenID.</footer></html>`;
}

export const operatorCompletionPage = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Canvas authorization</title><link rel="stylesheet" href="/admin/styles.css"><main><h1>Canvas authorization</h1><p>Return to your connections and inspect the current status to confirm the result.</p><a href="/admin">Return to Canvas connections</a></main></html>';
export const operatorStyles = `:root{font:16px/1.6 system-ui,sans-serif;color:#172b35;background:#f5f7f8}*{box-sizing:border-box}body{margin:0}header,main,footer{max-width:1040px;margin:auto;padding:24px}header{padding-top:40px}h1{font-size:2.5rem;line-height:1.15;margin:.3em 0}h2{line-height:1.3}header>p:first-of-type{font-weight:600;color:#46606c}a{color:#155c69}section{background:white;border:1px solid #d9e2e6;border-radius:12px;padding:24px;margin:20px 0}label{display:block;margin:12px 0;font-weight:600}input,select{display:block;width:100%;font:inherit;padding:9px;border:1px solid #8ba1ab;border-radius:5px;background:white}button{font:inherit;font-weight:600;color:white;background:#155c69;border:1px solid #155c69;border-radius:5px;padding:9px 15px;margin:6px 8px 6px 0;cursor:pointer}button:disabled{opacity:.55;cursor:wait}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #c77c0a;outline-offset:3px}fieldset{border:0;padding:0;margin:0;min-width:0}form>fieldset{border:1px solid #d9e2e6;padding:10px}legend{font-weight:600}.check{font-weight:400;display:flex;align-items:center;gap:9px}.check input{width:auto}details{border-top:1px solid #d9e2e6;margin-top:18px;padding-top:14px}summary{font-weight:600;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem;max-height:35rem;overflow:auto}#notice{border-left:4px solid #155c69;padding:12px 16px;background:#e9f2f4}#platform-status,footer{color:#46606c}ul{padding-left:22px}.sr-only{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}[hidden]{display:none!important}@media(min-width:700px){form{max-width:680px}.toolbar{display:flex;gap:8px}header,main,footer{padding-left:40px;padding-right:40px}}`;

// Serialized for the browser only, as with the LTI browser bridge. One reviewed
// fetch site admits only fixed same-origin administration paths. No production
// Node outbound transport or configurable credential destination is introduced.
function operatorBrowser() {
  'use strict';
  const get = id => document.getElementById(id), workspace = get('workspace');
  const notice = value => { get('notice').textContent = value; };
  const show = value => { get('result').textContent = JSON.stringify(value, (key, item) => key === 'clientSecretRef' ? '[encrypted reference]' : item, 2).slice(0, 131072); };
  const label = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
  const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const legacyPathAllowed = path => ['/admin/session','/platforms/catalog'].includes(path) || /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:configuration\/(?:inspect|receipt|create|change)|connection\/(?:inspect|receipt|disconnect)|oauth\/client\/(?:inspect|receipt|provision)|oauth\/start|oauth\/attempts\/(?:inspect|receipt|recover)|capture-routes\/(?:catalog|[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:inspect|receipt|capture|create|replace|activate|deactivate|schedule))|lti\/registrations\/(?:catalog|[a-f0-9-]{36}\/(?:inspect|receipt|create|replace|activate|deactivate)))$/.test(path);
  const capturePath = path => /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/lti\/registrations\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\/capture-routes\/(?:catalog|[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:inspect|receipt|capture|create|replace|activate|deactivate|schedule))$/.test(path);
  const pathAllowed = path => legacyPathAllowed(path) || capturePath(path) || /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/lti\/registrations\/[a-f0-9-]{36}\/(?:tool-key\/(?:inspect|receipt|provision|rotate|deactivate)|service-credentials\/(?:catalog|inspect|receipt|exchange|recover|resolve|resolution-receipt))$/.test(path);
  const features = new Set(document.querySelector('main').dataset.features.split(','));
  for (const section of document.querySelectorAll('[data-requires]')) section.hidden = !features.has(section.dataset.requires);
  let busy = false, platformCursor = null, routeCursor = null, ltiCursor = null, cursorPlatform = null;
  let organizationId = null;
  let journal = [], storageReady = true;
  const storageKey = 'elevenid_canvas_operator_pending_v1';
  const formIds = ['platform-create','platform-change','client-provision','connection-disconnect','route-edit','route-action','lti-edit','lti-action','lti-key','lti-credential','lti-service-recovery','lti-capture-edit','lti-capture-action','recovery'];
  function validEntry(entry) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join(',') !== 'extras,formId,operationId,organizationId,path,platformId,receiptPath') return false;
    if(entry.formId==='lti-key'&&!/\/tool-key\/(provision|rotate|deactivate)$/.test(entry.path))return false;
    if(entry.formId==='lti-credential'&&!/\/service-credentials\/(exchange|recover)$/.test(entry.path))return false;
    if(entry.formId==='lti-service-recovery'&&!/\/service-credentials\/resolve$/.test(entry.path))return false;
    if(capturePath(entry.path)&&!['lti-capture-edit','lti-capture-action'].includes(entry.formId))return false;
    if(entry.formId==='lti-capture-edit'&&(!capturePath(entry.path)||!/\/capture-routes\/[^/]+\/(create|replace)$/.test(entry.path)))return false;
    if(entry.formId==='lti-capture-action'&&(!capturePath(entry.path)||!/\/capture-routes\/[^/]+\/(activate|deactivate|schedule)$/.test(entry.path)))return false;
    return formIds.includes(entry.formId) && uuid(entry.organizationId) && label(entry.platformId) && uuid(entry.operationId) && pathAllowed(entry.path)
      && entry.path.startsWith('/platforms/' + entry.platformId + '/') && /\/(?:create|change|provision|rotate|disconnect|replace|activate|deactivate|schedule|recover|exchange|resolve)$/.test(entry.path)
      && entry.receiptPath === entry.path.replace(/[^/]+$/, entry.formId==='lti-service-recovery'?'resolution-receipt':'receipt') && pathAllowed(entry.receiptPath)
      && entry.extras && typeof entry.extras === 'object' && !Array.isArray(entry.extras)
      && (['lti-capture-edit','lti-capture-action'].includes(entry.formId)?Object.keys(entry.extras).sort().join(',')==='expectedVersion,serviceOperationId'
          &&Number.isSafeInteger(entry.extras.expectedVersion)&&entry.extras.expectedVersion>0
          &&(entry.path.endsWith('/deactivate')?entry.extras.serviceOperationId===null:uuid(entry.extras.serviceOperationId))
        : entry.formId==='lti-service-recovery' ? Object.keys(entry.extras).join(',')==='attempt_id'&&uuid(entry.extras.attempt_id)
        : ['lti-key','lti-credential'].includes(entry.formId)?Object.keys(entry.extras).length===0
        : Object.keys(entry.extras).length === 0 || (Object.keys(entry.extras).join(',') === 'authorization_id' && hash(entry.extras.authorization_id)));
  }
  try {
    const saved = window.sessionStorage.getItem(storageKey);
    if (saved !== null) {
      if (saved.length > 16384) throw Error();
      journal = JSON.parse(saved);
      if (!Array.isArray(journal) || journal.length > 16 || journal.some(entry => !validEntry(entry)) || new Set(journal.map(entry => entry.formId)).size !== journal.length) throw Error();
    }
  } catch { storageReady = false; journal = []; notice('Pending-operation storage is unavailable or invalid. Inspections remain available; changes are disabled.'); }
  function save(next) {
    if (!storageReady || next.length > 16) throw Error('journal_unavailable');
    const encoded = JSON.stringify(next);
    if (encoded.length > 16384 || next.some(entry => !validEntry(entry))) throw Error('journal_unavailable');
    window.sessionStorage.setItem(storageKey, encoded);
    if (window.sessionStorage.getItem(storageKey) !== encoded) throw Error('journal_unavailable');
    journal = next; renderJournal();
  }
  function matchesReceipt(entry, receipt) {
    if (receipt?.operationId !== entry.operationId) return false;
    if (entry.formId === 'connection-disconnect') return uuid(receipt.connectionId) && receipt.status === 'disconnected';
    if (entry.formId === 'recovery') return receipt.authorizationId === entry.extras.authorization_id;
    if(entry.formId==='lti-service-recovery')return receipt.platformId===entry.platformId&&receipt.attemptId===entry.extras.attempt_id&&receipt.phase==='resolved';
    if(['lti-capture-edit','lti-capture-action'].includes(entry.formId)) {
      const parts=entry.path.split('/'),action=parts[8];
      return receipt.platformId===entry.platformId&&receipt.registrationId===parts[5]&&receipt.routeId===parts[7]&&receipt.action===action
        &&receipt.version===entry.extras.expectedVersion&&uuid(receipt.serviceOperationId)
        &&(entry.extras.serviceOperationId===null||receipt.serviceOperationId===entry.extras.serviceOperationId)&&receipt.enabled===['activate','schedule'].includes(action)
        &&receipt.captureId===(action==='schedule'?entry.operationId:null);
    }
    return receipt.platformId === entry.platformId;
  }
  function platform() {
    const value = get('platform-id').value;
    if (!label(value)) throw Error('invalid_input');
    return value;
  }
  const base = () => '/platforms/' + platform();
  function number(value) {
    if (!/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) throw Error('invalid_input');
    return value;
  }
  const version = () => number(get('platform-version').value);
  function route(value) { if (!label(value)) throw Error('invalid_input'); return '/capture-routes/' + value; }
  function registration(value) { if (!uuid(value)) throw Error('invalid_input'); return '/lti/registrations/' + value; }
  function ltiCapture(registrationId,routeId) {if(!label(routeId))throw Error('invalid_input');return registration(registrationId)+'/capture-routes/'+routeId;}
  async function post(path, values = {}) {
    if (!pathAllowed(path)) throw Error('invalid_input');
    if(path!=='/admin/session' && organizationId===null) throw Error('context_required');
    const body = new URLSearchParams(values), controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await window.fetch(path, { method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Accept: 'application/json',
          ...(path==='/admin/session'?{}:{'X-Connector-Organization-Intent':organizationId}) }, body });
      if (response.status !== 200) { const error = Error('request_unconfirmed'); error.status = response.status; throw error; }
      if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw Error('request_unconfirmed');
      const reader = response.body.getReader(), chunks = []; let size = 0;
      try { for (;;) { const item = await reader.read(); if (item.done) break; size += item.value.byteLength; if (size > 131072) throw Error('request_unconfirmed'); chunks.push(item.value); } }
      finally { await reader.cancel().catch(() => {}); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } finally { clearTimeout(timer); }
  }
  async function run(action) {
    if (busy) return;
    busy = true; workspace.disabled = true;
    try { await action(); }
    catch (error) {
      if (error.message === 'invalid_input') notice('Check the selected platform, IDs and versions.');
      else if (error.message === 'journal_unavailable') notice('Operation IDs could not be safely retained. Inspect any displayed receipt before further changes.');
      else if (error.message === 'context_required') notice('Sign in and reload the current organization context before continuing.');
      else if (error.status === 401) notice('Sign in or explicitly reload organization context before continuing. The active organization may have changed.');
      else if (error.status === 403) notice('Your current organization or permission does not allow this action.');
      else if (error.status === 409) notice('The change conflicts with current configuration, scope or version. Inspect current state before submitting a new operation.');
      else if (error.status === 400) notice('The server rejected the supplied fields. Check the IDs, versions and required values.');
      else if (error.status === 429) notice('The request budget is exhausted. Wait before inspecting or submitting another operation.');
      else notice('The result was not confirmed. Inspect the original operation receipt before taking further action.');
    } finally { busy = false; workspace.disabled = false; }
  }
  function renderJournal() {
    const list = get('operations'); list.replaceChildren();
    for (const entry of journal) {
      const item = document.createElement('li'), text = document.createElement('p'), button = document.createElement('button');
      text.textContent = entry.organizationId + ' · ' + entry.platformId + ' · ' + entry.formId + ' · ' + entry.operationId;
      button.type = 'button'; button.textContent = 'Inspect original receipt';
      button.addEventListener('click', () => run(async () => {
        if(organizationId!==entry.organizationId) {notice('Switch to the original ElevenID organization '+entry.organizationId+' and reload context to inspect this receipt.');return;}
        const data={operation_id:entry.operationId};
        if(entry.formId==='recovery')data.authorization_id=entry.extras.authorization_id;
        if(entry.formId==='lti-service-recovery')data.attempt_id=entry.extras.attempt_id;
        const result = await post(entry.receiptPath,data); show(result);
        if (matchesReceipt(entry, result.receipt)) {
          save(journal.filter(current => current !== entry)); notice('Original receipt found. Inspect current state before another change.');
        } else if(entry.formId==='lti-credential'&&result.attemptId===entry.operationId&&result.phase==='resolved'&&result.receipt===null) {
          save(journal.filter(current=>current!==entry));notice('The original credential attempt is resolved. Inspect current state before another operation.');
        } else if (result.receipt === null) notice('No receipt in this snapshot. The original request may still be finishing; keep this ID and inspect again.');
        else notice('Receipt response did not match the original operation. Keep this ID for reconciliation.');
      }));
      item.append(text, button); list.append(item);
    }
  }
  renderJournal();
  async function mutate(form, path, values) {
    if(organizationId===null) throw Error('context_required');
    const recovering=form.id==='lti-credential'&&path.endsWith('/recover');
    const previous=journal.find(entry=>entry.formId===form.id),receiptPath=path.replace(/[^/]+$/,form.id==='lti-service-recovery'?'resolution-receipt':'receipt');
    if(previous&&(!recovering||previous.organizationId!==organizationId||previous.operationId!==values.attempt_id||previous.receiptPath!==receiptPath)) {notice('This form has an unconfirmed operation. Inspect its original receipt first.');return;}
    const operationId = recovering?values.attempt_id:window.crypto.randomUUID(), platformId = path.split('/')[2];
    if(!uuid(operationId))throw Error('invalid_input');
    let extras=form.id==='lti-service-recovery'?{attempt_id:values.attempt_id}:values.authorization_id?{authorization_id:values.authorization_id}:{};
    if(['lti-capture-edit','lti-capture-action'].includes(form.id)) {
      const action=path.split('/').at(-1),expectedVersion=action==='create'?1:Number(number(values.expected_route_version))+(action==='schedule'?0:1);
      if(!Number.isSafeInteger(expectedVersion)||expectedVersion<1||action!=='deactivate'&&!uuid(values.service_operation_id))throw Error('invalid_input');
      extras={expectedVersion,serviceOperationId:action==='deactivate'?null:values.service_operation_id};
    }
    const entry = previous??{ formId: form.id, organizationId, platformId, path, receiptPath, operationId,extras };
    if(!previous)save([...journal, entry]);
    show({operationId,platformId,status:'pending'});
    notice('Submitting operation ' + operationId + '. Keep this ID until the result is confirmed.');
    // The journal contains only receipt pointers, never intent bodies or secrets.
    let result;
    try { result = await post(path, recovering?values:{ ...values, operation_id: operationId }); }
    catch (error) {
      // These existing adapters reject these statuses before a write. Transport
      // failures, malformed successes and server errors retain the original ID.
      if (!recovering&&[400,401,403,404,405,409,413,415,429].includes(error.status)&&!(error.status===403&&['lti-key','lti-credential','lti-service-recovery','lti-capture-edit','lti-capture-action'].includes(form.id))) save(journal.filter(current => current !== entry));
      throw error;
    }
    show(result);
    if(form.id==='lti-credential'&&result.attempt?.attemptId===operationId) {
      if(result.attempt.phase==='resolved'&&result.attempt.receipt===null) {save(journal.filter(current=>current!==entry));notice('Original credential attempt is resolved. Inspect current state before another operation.');return;}
      if(!matchesReceipt(entry,result.attempt.receipt)) {notice('Credential attempt '+operationId+' is '+result.attempt.phase+'. Inspect this original ID; it will not be exchanged again automatically.');return;}
      result={...result,receipt:result.attempt.receipt};
    }
    if (!matchesReceipt(entry, result.receipt)) throw Error('request_unconfirmed');
    save(journal.filter(current => current !== entry));
    notice('Change recorded as ' + operationId + '. Inspect current state before continuing.');
  }
  function readButton(id, makePath) {
    get(id).addEventListener('click', () => run(async () => { show(await post(makePath())); notice('Inspection complete for the selected platform.'); }));
  }
  async function catalog(after) {
    const result = await post('/platforms/catalog', after ? { after_id: after } : {});
    if (!Array.isArray(result.platforms) || result.platforms.length > 20 || result.platforms.some(item => !label(item.platformId))
      || !(result.nextCursor === null || label(result.nextCursor))) throw Error('request_unconfirmed');
    const list = get('platform-list'); list.replaceChildren();
    for (const item of result.platforms) {
      const li = document.createElement('li'), button = document.createElement('button');button.type = 'button';
      button.textContent = item.platformId + (item.archived ? ' · archived' : item.enabled ? ' · enabled' : ' · disabled');
      button.addEventListener('click', () => { get('platform-id').value = item.platformId; get('platform-version').value = ''; get('platform-status').textContent = 'Platform selected. Inspect its current version before making a change.'; });
      li.append(button); list.append(li);
    }
    platformCursor = result.nextCursor; get('catalog-next').hidden = platformCursor === null;
    notice('Platform page loaded. Select a platform, then inspect it.');
  }
  get('catalog').addEventListener('click', () => run(() => catalog(null)));
  get('catalog-next').addEventListener('click', () => run(() => catalog(platformCursor)));
  get('inspect-platform').addEventListener('click', () => run(async () => {
    const result = await post(base() + '/configuration/inspect'); show(result);
    if (result.platform === null) { get('platform-version').value = ''; notice('No platform found in the current organization.'); return; }
    if (result.platform?.platformId !== platform() || !Number.isSafeInteger(result.platform.configVersion)) throw Error('request_unconfirmed');
    get('platform-version').value = String(result.platform.configVersion);
    get('platform-status').textContent = result.platform.canvasOrigin + ' · version ' + result.platform.configVersion + (result.platform.archived ? ' · archived' : result.platform.enabled ? ' · enabled' : ' · disabled');
    notice('Current platform loaded. Changes remain subject to server revision and permission checks.');
  }));
  get('platform-id').addEventListener('input', () => { get('platform-version').value = ''; get('platform-status').textContent = 'Inspect this platform before making a change.'; });
  readButton('inspect-client', () => base() + '/oauth/client/inspect');
  readButton('inspect-connection', () => base() + '/connection/inspect');
  async function resourceCatalog(kind, after) {
    const selected = platform();
    if (after && cursorPlatform !== selected) throw Error('invalid_input');
    const result = await post(base() + (kind === 'route' ? '/capture-routes/catalog' : '/lti/registrations/catalog'), after ? { after_id: after } : {}); show(result);
    const cursor = result.nextCursor;
    if (!(cursor === null || (kind === 'route' ? label(cursor) : uuid(cursor)))) throw Error('request_unconfirmed');
    cursorPlatform = selected;
    if (kind === 'route') { routeCursor = cursor; get('routes-next').hidden = cursor === null; }
    else { ltiCursor = cursor; get('lti-next').hidden = cursor === null; }
    notice('Resource page loaded for ' + selected + '.');
  }
  get('catalog-routes').addEventListener('click', () => run(() => resourceCatalog('route', null)));
  get('routes-next').addEventListener('click', () => run(() => resourceCatalog('route', routeCursor)));
  get('catalog-lti').addEventListener('click', () => run(() => resourceCatalog('lti', null)));
  get('lti-next').addEventListener('click', () => run(() => resourceCatalog('lti', ltiCursor)));
  function updateForm(form) {
    const value = name => form.elements.namedItem(name)?.value;
    const use = (name, active) => {
      const field = form.elements.namedItem(name);
      if (!field) return;
      field.disabled = !active; field.required = active;
      field.closest('label').hidden = !active;
    };
    if (form.id === 'route-edit') {
      use('expected_route_version', value('action') === 'replace');
      use('activity_id', ['canvas.assignment_score','canvas.quiz_score'].includes(value('fact_type')));
      use('module_id', value('fact_type') === 'canvas.module_completion');
    }
    if (form.id === 'route-action') {
      use('expected_route_version', !['inspect','capture'].includes(value('action')));
      use('capture_id', value('action') === 'capture');
    }
    if (form.id === 'lti-edit') { use('expected_registration_version', value('action') === 'replace'); use('environment', value('trust_profile') === 'hosted_global'); }
    if (form.id === 'lti-action') use('expected_registration_version', value('action') !== 'inspect');
    if(form.id==='lti-capture-edit') {
      const ags=value('fact_type')==='canvas.ags_result';use('expected_route_version',value('action')==='replace');use('line_item_id',ags);use('context_id',!ags);
      const fields=[...form.querySelectorAll('[name="lti_claims"]')];
      for(const field of fields){const active=ags?field.value!=='provider_state':field.value==='provider_state';field.disabled=!active;field.closest('label').hidden=!active;}
      if(!fields.some(field=>!field.disabled&&field.checked))fields.find(field=>!field.disabled).checked=true;
    }
    if(form.id==='lti-capture-action') {
      const active=['activate','schedule'].includes(value('action'));
      use('resource_id',value('action')!=='catalog');use('expected_route_version',active||value('action')==='deactivate');
      for(const name of ['expected_registration_version','expected_key_version','service_operation_id'])use(name,active);
      use('capture_id',value('action')==='capture');use('after_id',value('action')==='catalog');form.elements.namedItem('after_id').required=false;
    }
    if(form.id==='lti-key') {
      use('expected_registration_version',['provision','rotate'].includes(value('action')));
      use('expected_key_version',['rotate','deactivate'].includes(value('action')));
    }
    if(form.id==='lti-credential') {
      use('expected_registration_version',value('action')==='exchange');use('expected_key_version',value('action')==='exchange');
      use('attempt_id',!['exchange','catalog'].includes(value('action')));
      use('after_id',value('action')==='catalog');form.elements.namedItem('after_id').required=false;
      for(const field of form.querySelectorAll('input[name="service_scopes"]'))field.disabled=value('action')!=='exchange';
    }
    if(form.id==='lti-service-recovery') {
      const external=value('action')==='resolve_unknown';
      use('expected_registration_version',external);use('expected_key_version',external);use('confirmation_reference',external);
      const phases=value('action')==='abandon_prepared'?['prepared']:external?['exchanging','uncertain']:['staged','published'];
      const field=form.elements.namedItem('expected_phase');for(const option of field.options)option.disabled=!phases.includes(option.value);
      if(!phases.includes(field.value))field.value=phases[0];
    }
    if (form.id === 'recovery') { use('expected_revision', value('mode') === 'recover'); use('action', value('mode') === 'recover'); }
    if (form.id === 'receipt') { use('resource_id', ['route','lti','lti-key','lti-credential','lti-resolution','lti-capture'].includes(value('kind'))); use('authorization_id', value('kind') === 'recovery');use('attempt_id',value('kind')==='lti-resolution');use('registration_id',value('kind')==='lti-capture'); }
  }
  for (const form of document.forms) { updateForm(form); form.addEventListener('change', event => {
    if(form.id==='lti-credential'&&event.target.name==='resource_id')form.elements.namedItem('after_id').value='';updateForm(form);
    if(form.id==='lti-capture-action'&&event.target.name==='registration_id')form.elements.namedItem('after_id').value='';
  }); }
  async function loadContext() {
    organizationId=null;get('organization').textContent='Organization context not loaded.';
    for(const form of document.forms) {form.reset();updateForm(form);}
    get('platform-id').value='';get('platform-version').value='';get('platform-status').textContent='Select and inspect a platform in this organization.';
    get('platform-list').replaceChildren();get('result').textContent='No inspection yet.';
    platformCursor=routeCursor=ltiCursor=cursorPlatform=null;
    for(const id of ['catalog-next','routes-next','lti-next']) get(id).hidden=true;
    const current=await post('/admin/session');
    if(!current || Object.keys(current).join(',')!=='organizationId' || !uuid(current.organizationId)) throw Error('request_unconfirmed');
    organizationId=current.organizationId;
    get('organization').textContent='ElevenID organization: '+organizationId;
    notice(storageReady?'Organization context loaded. Load platforms to continue. Pending receipts remain in their original organization.':'Pending-operation storage is unavailable or invalid. Inspections remain available; changes are disabled.');
  }
  get('reload-context').addEventListener('click',()=>run(loadContext));
  for (const form of document.forms) form.addEventListener('submit', event => {
    event.preventDefault();
    // Snapshot before the workspace fieldset is disabled for the request.
    const submitted = new FormData(form), values = Object.fromEntries(submitted);
    void run(async () => {
      const selectedBase = form.id === 'platform-create' ? null : base();
      if (form.id === 'platform-create') {
        if (!label(values.platform_id)) throw Error('invalid_input');
        return mutate(form, '/platforms/' + values.platform_id + '/configuration/create', { canvas_origin: values.canvas_origin });
      }
      if (form.id === 'platform-change') return mutate(form, selectedBase + '/configuration/change', { expected_version: version(), enabled: String(values.mode === 'enable'), archived: String(values.mode === 'archive') });
      if (form.id === 'client-provision') {
        // Clear the visible secret before yielding; no storage or result contains it.
        form.elements.client_secret.value = '';
        submitted.delete('client_secret');
        try { return await mutate(form, selectedBase + '/oauth/client/provision', { expected_version: version(), client_id: values.client_id, client_secret: values.client_secret }); }
        finally { values.client_secret = ''; }
      }
      if (form.id === 'oauth-start') {
        const capabilities = submitted.getAll('capabilities');
        if (!capabilities.length) throw Error('invalid_input');
        const current = await post(selectedBase + '/configuration/inspect');
        const result = await post(selectedBase + '/oauth/start', { capabilities: capabilities.join(',') });
        const target = new URL(result.authorizationUrl);
        if (target.protocol !== 'https:' || target.origin !== current.platform?.canvasOrigin || target.username || target.password || target.hash
          || target.pathname !== '/login/oauth2/auth' || target.searchParams.getAll('redirect_uri').length !== 1
          || target.searchParams.get('redirect_uri') !== window.location.origin + '/oauth/callback') throw Error('request_unconfirmed');
        window.location.assign(target.href); return;
      }
      if (form.id === 'connection-disconnect') return mutate(form, selectedBase + '/connection/disconnect', { connection_id: values.connection_id, expected_revision: number(values.expected_revision) });
      if (form.id === 'route-edit') {
        const requirement = { factType: values.fact_type, courseId: values.course_id, userId: values.user_id };
        if (['canvas.assignment_score','canvas.quiz_score'].includes(values.fact_type)) requirement.activityId = values.activity_id;
        if (values.fact_type === 'canvas.module_completion') requirement.moduleId = values.module_id;
        const claims = submitted.getAll('claims');
        if (!claims.length) throw Error('invalid_input');
        const data = { expected_platform_version: version(), producer_ref: values.producer_ref, binding_id: values.binding_id,
          binding_revision: number(values.binding_revision), requirement: JSON.stringify(requirement), claim_names: JSON.stringify(claims), effective_time_policy: values.effective_time_policy };
        if (values.action === 'replace') data.expected_route_version = number(values.expected_route_version);
        return mutate(form, selectedBase + route(values.resource_id) + '/' + values.action, data);
      }
      if (form.id === 'route-action') {
        const path = selectedBase + route(values.resource_id) + '/' + values.action;
        if (values.action === 'inspect' || values.action === 'capture') { show(await post(path, values.action === 'capture' ? { capture_id: values.capture_id } : {})); notice('Inspection complete.'); return; }
        const data = { expected_route_version: number(values.expected_route_version) };
        if (values.action !== 'deactivate') data.expected_platform_version = version();
        return mutate(form, path, data);
      }
      if (form.id === 'lti-edit') {
        const data = { expected_platform_version: version(), client_id: values.client_id, deployment_id: values.deployment_id, trust_profile: values.trust_profile };
        if (values.trust_profile === 'hosted_global') data.environment = values.environment;
        if (values.action === 'replace') data.expected_registration_version = number(values.expected_registration_version);
        return mutate(form, selectedBase + registration(values.resource_id) + '/' + values.action, data);
      }
      if(form.id==='lti-capture-edit') {
        if(!uuid(values.service_operation_id))throw Error('invalid_input');
        const requirement={factType:values.fact_type,courseId:values.course_id,userId:values.provider_user_id,resourceLinkId:values.resource_link_id};
        if(values.fact_type==='canvas.ags_result')requirement.lineItemId=values.line_item_id;else requirement.contextId=values.context_id;
        const claims=submitted.getAll('lti_claims');if(!claims.length)throw Error('invalid_input');
        const data={expected_platform_version:version(),expected_registration_version:number(values.expected_registration_version),expected_key_version:number(values.expected_key_version),
          service_operation_id:values.service_operation_id,producer_ref:values.producer_ref,binding_id:values.binding_id,binding_revision:number(values.binding_revision),
          requirement:JSON.stringify(requirement),claim_names:JSON.stringify(claims),effective_time_policy:'as_of_read'};
        if(values.action==='replace')data.expected_route_version=number(values.expected_route_version);
        return mutate(form,selectedBase+ltiCapture(values.registration_id,values.resource_id)+'/'+values.action,data);
      }
      if(form.id==='lti-capture-action') {
        if(values.action==='catalog') {
          if(values.after_id&&!label(values.after_id))throw Error('invalid_input');
          const result=await post(selectedBase+registration(values.registration_id)+'/capture-routes/catalog',values.after_id?{after_id:values.after_id}:{});show(result);
          if(!Array.isArray(result.routes)||result.routes.length>20||!(result.nextCursor===null||label(result.nextCursor)))throw Error('request_unconfirmed');
          form.elements.namedItem('after_id').value=result.nextCursor??'';notice(result.nextCursor?'LTI route page loaded. Submit catalog for the next page.':'LTI route page loaded; no further page in this snapshot.');return;
        }
        const path=selectedBase+ltiCapture(values.registration_id,values.resource_id)+'/'+values.action;
        if(['inspect','capture'].includes(values.action)) {
          if(values.action==='capture'&&!uuid(values.capture_id))throw Error('invalid_input');
          show(await post(path,values.action==='capture'?{capture_id:values.capture_id}:{}));notice('LTI capture state inspected.');return;
        }
        const data={expected_route_version:number(values.expected_route_version)};
        if(values.action!=='deactivate') {
          if(!uuid(values.service_operation_id))throw Error('invalid_input');
          Object.assign(data,{expected_platform_version:version(),expected_registration_version:number(values.expected_registration_version),expected_key_version:number(values.expected_key_version),service_operation_id:values.service_operation_id});
        }
        return mutate(form,path,data);
      }
      if (form.id === 'lti-action') {
        const path = selectedBase + registration(values.resource_id) + '/' + values.action;
        if (values.action === 'inspect') { show(await post(path)); notice('Inspection complete.'); return; }
        const data = { expected_registration_version: number(values.expected_registration_version) };
        if (values.action !== 'deactivate') data.expected_platform_version = version();
        return mutate(form, path, data);
      }
      if(form.id==='lti-key') {
        const path=selectedBase+registration(values.resource_id)+'/tool-key/'+values.action;
        if(values.action==='inspect'){show(await post(path));notice('Tool-key state and public JWK URL inspected.');return;}
        const data={};
        if(values.action!=='deactivate'){data.expected_platform_version=version();data.expected_registration_version=number(values.expected_registration_version);}
        if(values.action!=='provision')data.expected_key_version=number(values.expected_key_version);
        return mutate(form,path,data);
      }
      if(form.id==='lti-credential') {
        const path=selectedBase+registration(values.resource_id)+'/service-credentials/'+values.action;
        if(values.action==='catalog') {
          if(values.after_id&&!uuid(values.after_id))throw Error('invalid_input');
          const result=await post(path,values.after_id?{after_id:values.after_id}:{});show(result);
          if(!(result.nextCursor===null||uuid(result.nextCursor)))throw Error('request_unconfirmed');
          form.elements.namedItem('after_id').value=result.nextCursor??'';
          notice(result.nextCursor?'Attempt page loaded. Submit catalog again for the next page.':'Attempt page loaded; no further page in this snapshot.');return;
        }
        if(values.action!=='exchange') {
          if(!uuid(values.attempt_id))throw Error('invalid_input');
          if(values.action==='recover')return mutate(form,path,{attempt_id:values.attempt_id});
          const result=await post(path,{attempt_id:values.attempt_id});show(result);
          const pending=journal.find(entry=>entry.formId===form.id&&entry.organizationId===organizationId&&entry.operationId===values.attempt_id);
          if(pending&&matchesReceipt(pending,result.attempt?.receipt))save(journal.filter(entry=>entry!==pending));
          notice('Original credential attempt inspected. Recovery performs no provider exchange.');return;
        }
        const scopeNames={results:'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',lineitems:'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',memberships:'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly'};
        const scopes=submitted.getAll('service_scopes').map(value=>scopeNames[value]);if(!scopes.length||scopes.some(value=>!value))throw Error('invalid_input');
        return mutate(form,path,{expected_platform_version:version(),expected_registration_version:number(values.expected_registration_version),
          expected_key_version:number(values.expected_key_version),scopes:JSON.stringify(scopes)});
      }
      if(form.id==='lti-service-recovery') {
        if(!uuid(values.attempt_id))throw Error('invalid_input');
        const data={attempt_id:values.attempt_id,action:values.action,expected_phase:values.expected_phase};
        if(values.action==='resolve_unknown') {
          if(!uuid(values.confirmation_reference))throw Error('invalid_input');
          Object.assign(data,{expected_platform_version:version(),expected_registration_version:number(values.expected_registration_version),
            expected_key_version:number(values.expected_key_version),confirmation_reference:values.confirmation_reference});
        }
        return mutate(form,selectedBase+registration(values.resource_id)+'/service-credentials/resolve',data);
      }
      if (form.id === 'recovery') {
        if (!hash(values.authorization_id)) throw Error('invalid_input');
        const data = { authorization_id: values.authorization_id }, path = selectedBase + '/oauth/attempts/' + values.mode;
        if (values.mode === 'inspect') { show(await post(path, data)); notice('Inspection complete.'); return; }
        return mutate(form, path, { ...data, expected_revision: number(values.expected_revision), action: values.action });
      }
      if (form.id === 'receipt') {
        if (!uuid(values.operation_id)) throw Error('invalid_input');
        const suffix = { platform: '/configuration', client: '/oauth/client', connection: '/connection', route: null, lti: null, recovery: '/oauth/attempts' }[values.kind];
        const ltiKind=['lti','lti-key','lti-credential','lti-resolution'].includes(values.kind);
        const path = selectedBase + (values.kind==='lti-capture'?ltiCapture(values.registration_id,values.resource_id):values.kind === 'route' ? route(values.resource_id) : ltiKind ? registration(values.resource_id)+({lti:'','lti-key':'/tool-key','lti-credential':'/service-credentials','lti-resolution':'/service-credentials'}[values.kind]) : suffix) + (values.kind==='lti-resolution'?'/resolution-receipt':'/receipt');
        const data = { operation_id: values.operation_id };
        if (values.kind === 'recovery') { if (!hash(values.authorization_id)) throw Error('invalid_input'); data.authorization_id = values.authorization_id; }
        if(values.kind==='lti-resolution'){if(!uuid(values.attempt_id))throw Error('invalid_input');data.attempt_id=values.attempt_id;}
        const result = await post(path, data); show(result);
        notice(result.receipt === null ? 'No receipt in this snapshot. Absence does not prove rollback.' : 'Historical receipt inspected. Inspect current state before another change.');
      }
    });
  });
  workspace.dataset.ready = 'true';
  void run(loadContext);
}
export const operatorScript = '(' + operatorBrowser.toString() + ')();';
