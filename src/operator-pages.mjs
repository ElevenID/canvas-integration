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
  if (!Array.isArray(features) || features.some(value => !['platforms', 'clients', 'connections', 'captures', 'lti', 'recovery'].includes(value))) throw Error('invalid_operator_features');
  const numeric = 'inputmode="numeric" pattern="[1-9][0-9]{0,19}" maxlength="20"';
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Canvas connections · ElevenID</title><link rel="stylesheet" href="/admin/styles.css"><script src="/admin/app.js" defer></script>
<header><a href="/">ElevenID</a><p>Integrations</p><h1>Canvas connections</h1><p>Manage Canvas access and capture settings. Your current ElevenID organization and permissions govern every action.</p></header>
<main data-features="${features.join(',')}"><p id="notice" role="status" aria-live="polite">Load your platforms to begin. Sign in to ElevenID on this origin first.</p>
<fieldset id="workspace" disabled><legend class="sr-only">Connection controls</legend>
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
<section data-requires="recovery"><h2>Authorization recovery</h2><p>Inspect the original authorization before choosing an action. These actions do not repeat a token exchange.</p>
${form('recovery', 'Inspect or resolve an authorization attempt', input('authorization_id','Original authorization ID','pattern="[a-f0-9]{64}" maxlength="64"') + actions('mode',['inspect','recover']) + revision('expected_revision','Attempt revision') + actions('action',['abandon_unstarted','queue_staged_revocation','finish_staged_revocation']), 'Apply selected action')}
</section>
<section><h2>Original operation receipts</h2><p>Changes are never retried automatically. Pending IDs survive reload in this tab’s session storage; copy IDs before closing the tab. An absent receipt is a snapshot and does not prove rollback.</p><ul id="operations"></ul>
${form('receipt', 'Inspect a saved operation ID', choice('kind','Operation',[['platform','Platform'],['client','Developer key'],['connection','Disconnect'],['route','Capture route'],['lti','LTI registration'],['recovery','Authorization recovery']]) + resource() + input('operation_id','Original operation ID','maxlength="36"') + `<label>Authorization ID, for recovery receipts<input name="authorization_id" maxlength="64"></label>`, 'Inspect original receipt')}
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
  const pathAllowed = path => path === '/platforms/catalog' || /^\/platforms\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:configuration\/(?:inspect|receipt|create|change)|connection\/(?:inspect|receipt|disconnect)|oauth\/client\/(?:inspect|receipt|provision)|oauth\/start|oauth\/attempts\/(?:inspect|receipt|recover)|capture-routes\/(?:catalog|[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:inspect|receipt|capture|create|replace|activate|deactivate|schedule))|lti\/registrations\/(?:catalog|[a-f0-9-]{36}\/(?:inspect|receipt|create|replace|activate|deactivate)))$/.test(path);
  const features = new Set(document.querySelector('main').dataset.features.split(','));
  for (const section of document.querySelectorAll('[data-requires]')) section.hidden = !features.has(section.dataset.requires);
  let busy = false, platformCursor = null, routeCursor = null, ltiCursor = null, cursorPlatform = null;
  let journal = [], storageReady = true;
  const storageKey = 'elevenid_canvas_operator_pending_v1';
  const formIds = ['platform-create','platform-change','client-provision','connection-disconnect','route-edit','route-action','lti-edit','lti-action','recovery'];
  function validEntry(entry) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join(',') !== 'extras,formId,operationId,path,platformId,receiptPath') return false;
    return formIds.includes(entry.formId) && label(entry.platformId) && uuid(entry.operationId) && pathAllowed(entry.path)
      && entry.path.startsWith('/platforms/' + entry.platformId + '/') && /\/(?:create|change|provision|disconnect|replace|activate|deactivate|schedule|recover)$/.test(entry.path)
      && entry.receiptPath === entry.path.replace(/[^/]+$/, 'receipt') && pathAllowed(entry.receiptPath)
      && entry.extras && typeof entry.extras === 'object' && !Array.isArray(entry.extras)
      && (Object.keys(entry.extras).length === 0 || (Object.keys(entry.extras).join(',') === 'authorization_id' && hash(entry.extras.authorization_id)));
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
  async function post(path, values = {}) {
    if (!pathAllowed(path)) throw Error('invalid_input');
    const body = new URLSearchParams(values), controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await window.fetch(path, { method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Accept: 'application/json' }, body });
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
      else if (error.status === 401) notice('Sign in to ElevenID on this origin, then inspect again.');
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
      text.textContent = entry.platformId + ' · ' + entry.formId + ' · ' + entry.operationId;
      button.type = 'button'; button.textContent = 'Inspect original receipt';
      button.addEventListener('click', () => run(async () => {
        const result = await post(entry.receiptPath, { ...entry.extras, operation_id: entry.operationId }); show(result);
        if (matchesReceipt(entry, result.receipt)) {
          save(journal.filter(current => current !== entry)); notice('Original receipt found. Inspect current state before another change.');
        } else if (result.receipt === null) notice('No receipt in this snapshot. The original request may still be finishing; keep this ID and inspect again.');
        else notice('Receipt response did not match the original operation. Keep this ID for reconciliation.');
      }));
      item.append(text, button); list.append(item);
    }
  }
  renderJournal();
  async function mutate(form, path, values) {
    if (journal.some(entry => entry.formId === form.id)) { notice('This form has an unconfirmed operation. Inspect its original receipt first.'); return; }
    const operationId = window.crypto.randomUUID(), platformId = path.split('/')[2];
    const entry = { formId: form.id, platformId, path, receiptPath: path.replace(/[^/]+$/, 'receipt'), operationId,
      extras: values.authorization_id ? { authorization_id: values.authorization_id } : {} };
    save([...journal, entry]);
    show({operationId,platformId,status:'pending'});
    notice('Submitting operation ' + operationId + '. Keep this ID until the result is confirmed.');
    // The journal contains only receipt pointers, never intent bodies or secrets.
    let result;
    try { result = await post(path, { ...values, operation_id: operationId }); }
    catch (error) {
      // These existing adapters reject these statuses before a write. Transport
      // failures, malformed successes and server errors retain the original ID.
      if ([400,401,403,404,405,409,413,415,429].includes(error.status)) save(journal.filter(current => current !== entry));
      throw error;
    }
    show(result);
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
    if (form.id === 'recovery') { use('expected_revision', value('mode') === 'recover'); use('action', value('mode') === 'recover'); }
    if (form.id === 'receipt') { use('resource_id', ['route','lti'].includes(value('kind'))); use('authorization_id', value('kind') === 'recovery'); }
  }
  for (const form of document.forms) { updateForm(form); form.addEventListener('change', () => updateForm(form)); }
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
      if (form.id === 'lti-action') {
        const path = selectedBase + registration(values.resource_id) + '/' + values.action;
        if (values.action === 'inspect') { show(await post(path)); notice('Inspection complete.'); return; }
        const data = { expected_registration_version: number(values.expected_registration_version) };
        if (values.action !== 'deactivate') data.expected_platform_version = version();
        return mutate(form, path, data);
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
        const path = selectedBase + (values.kind === 'route' ? route(values.resource_id) : values.kind === 'lti' ? registration(values.resource_id) : suffix) + '/receipt';
        const data = { operation_id: values.operation_id };
        if (values.kind === 'recovery') { if (!hash(values.authorization_id)) throw Error('invalid_input'); data.authorization_id = values.authorization_id; }
        const result = await post(path, data); show(result);
        notice(result.receipt === null ? 'No receipt in this snapshot. Absence does not prove rollback.' : 'Historical receipt inspected. Inspect current state before another change.');
      }
    });
  });
  workspace.dataset.ready = 'true';
  workspace.disabled = false;
}
export const operatorScript = '(' + operatorBrowser.toString() + ')();';
