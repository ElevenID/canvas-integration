// SPDX-License-Identifier: AGPL-3.0-only
// This function is serialized into a nonce-authorized inline browser script.
// It never runs on the connector host and has no credentials or Core authority.
function browserBridge(plan) {
  const message = document.getElementById('message');
  let target, settled = false, timer;
  const fail = () => {
    if (settled) return;
    settled = true; clearTimeout(timer); window.removeEventListener('message', receive);
    if (plan.mode === 'login') window.location.replace(plan.authorizationUrl); // Cookie fallback; server proof remains mandatory.
    else message.textContent = 'Unable to confirm this browser. Launch again from Canvas.';
  };
  const finish = value => {
    if (settled) return;
    settled = true; clearTimeout(timer); window.removeEventListener('message', receive);
    if (plan.mode === 'login') { window.location.replace(plan.authorizationUrl); return; }
    const form = document.createElement('form');form.method = 'POST';form.action = plan.action;
    for (const [name, content] of Object.entries({ state: plan.state, browser_proof: value,
      storage_target: plan.storageTarget, ...(plan.mode === 'confirm' ? { token_hash: plan.tokenHash } : {}) })) {
      const input = document.createElement('input');input.type = 'hidden';input.name = name;input.value = content;form.appendChild(input);
    }
    document.body.appendChild(form);form.submit();
  };
  const subject = plan.mode === 'login' ? 'lti.put_data' : 'lti.get_data';
  const key = 'canvas-lti-browser:' + plan.state;
  function receive(event) {
    if (settled || event.origin !== plan.storageOrigin || event.source !== target) return;
    const data = event.data;
    if (!data || typeof data !== 'object' || Array.isArray(data) || data.message_id !== plan.messageId || data.subject !== subject + '.response') return;
    if (Object.prototype.hasOwnProperty.call(data, 'error')) { fail(); return; }
    if (data.key !== key || typeof data.value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.value)) return;
    if (plan.mode === 'login' && data.value !== plan.browserProof) return;
    finish(data.value);
  }
  if (plan.mode === 'login' && plan.storageTarget === null) { window.location.replace(plan.authorizationUrl); return; }
  try {
    target = plan.storageTarget === '_parent' ? window.parent : window.parent.frames[plan.storageTarget];
    if (!target || typeof target.postMessage !== 'function') { fail(); return; }
    window.addEventListener('message', receive);
    timer = setTimeout(fail, 3000);
    target.postMessage({ subject, message_id: plan.messageId, key,
      ...(plan.mode === 'login' ? { value: plan.browserProof } : {}) }, plan.storageOrigin);
  } catch { fail(); }
}
function scriptJson(value) {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
}
export function ltiBridgePage(plan, nonce) {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">' +
    '<title>Connecting Canvas</title><h1>Connecting Canvas</h1><p id="message">Confirming your browser…</p>' +
    '<noscript>JavaScript is required. Launch again from Canvas with JavaScript enabled.</noscript>' +
    `<script nonce="${nonce}">(${browserBridge.toString()})(${scriptJson(plan)});</script></html>`;
}
export function ltiResourcePage() {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">' +
    '<title>Canvas connected</title><h1>Canvas connected</h1><p>Your Canvas launch has been confirmed.</p></html>';
}
