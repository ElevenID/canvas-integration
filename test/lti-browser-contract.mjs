// SPDX-License-Identifier: AGPL-3.0-only
// Receives a Playwright Page in an isolated test browser, never a user session.
export async function exerciseLtiBrowser(page, info, selected = null) {
  const ensure = (condition, label) => { if (!condition) throw Error('lti_browser_contract_' + label); };
  const browser = page.context().browser(), results = [];
  async function scenario(name, options = {}, exercise) {
    if (selected && !selected.includes(name)) return;
    const context = await browser.newContext({ ignoreHTTPSErrors: true }); // Owned synthetic certificates only.
    try {
      const control = async (action, extra = '') => {
        const response = await context.request.get(info.canvasOrigin + '/control?cap=' + info.cap + '&action=' + action + extra);
        ensure(response.status() === 200, 'fixture_control');return response.json();
      };
      await control('configure', '&mode=' + (options.mode ?? 'valid') + '&cookies=' + (options.blockCookies ? 'blocked' : 'allowed') + '&lose=' + (options.lose ? 'true' : 'false'));
      const before = await control('inspect'), p = await context.newPage();
      let originalState, resourcePosts = 0;
      p.on('request', request => {
        if (request.method() === 'POST' && request.url().split('?')[0] === info.connectorOrigin + info.base + '/launch') {
          const match = /(?:^|&)state=([A-Za-z0-9_-]{43})(?:&|$)/.exec(request.postData() ?? '');
          if (match) originalState = match[1];
        }
        if (request.method() === 'POST' && request.url().split('?')[0] === info.connectorOrigin + info.base + '/resource') resourcePosts++;
      });
      const tool = p.frameLocator('iframe[name=tool]');
      const connected = () => tool.getByRole('heading', { name: 'Canvas connected', exact: true }).waitFor({ timeout: 12000 });
      const replay = async () => {
        ensure(!!originalState, 'original_state');
        await p.locator('iframe[name=tool]').evaluate((element, url) => { element.src = url; }, info.canvasOrigin + '/replay?state=' + originalState);
      };
      await exercise({ p,context,control,before,tool,connected,replay,state:()=>originalState,resourcePosts:()=>resourcePosts });
      results.push({ name, passed: true });
    } catch (error) { error.message = 'lti_browser_' + name + ': ' + error.message;throw error; }
    finally { await context.close(); }
  }
  await scenario('cross-site partitioned HttpOnly cookie', { storage: false }, async ({p,context,before,control,connected}) => {
    await p.goto(info.canvasOrigin + '/parent?storage=false');await connected();
    const cookies = (await context.cookies(info.connectorOrigin)).filter(value => value.name.startsWith('__Host-canvas_lti_'));
    ensure(cookies.length === 1 && cookies[0].secure && cookies[0].httpOnly && cookies[0].sameSite === 'None' && !!cookies[0].partitionKey, 'cookie_attributes');
    ensure((await control('inspect')).receipts === before.receipts + 1, 'cookie_receipt');
  });
  await scenario('cookie-free SSO storage, replay and configuration closure', { blockCookies: true }, async ({p,context,before,control,connected,replay,state,resourcePosts,tool}) => {
    await p.goto(info.canvasOrigin + '/parent');await connected();
    ensure((await context.cookies(info.connectorOrigin)).length === 0 && resourcePosts() > 0, 'cookie_free_resource_proof');
    ensure(!(await tool.locator('body').innerText()).includes('synthetic-browser-subject'), 'private_claim_output');
    const original = state();
    const replayResponse = p.waitForResponse(response => response.url().split('?')[0] === info.connectorOrigin + info.base + '/launch');
    await replay();await replayResponse;await connected();
    ensure(state() === original && (await control('inspect')).receipts === before.receipts + 1, 'stable_replay');
    await control('disable');
    const rejected = p.waitForResponse(response => response.status() === 403 && response.url().startsWith(info.connectorOrigin + info.base + '/resource'));
    await replay();await rejected;await tool.getByRole('heading', {name:'Canvas connected',exact:true}).waitFor({state:'hidden',timeout:5000});
    ensure((await control('inspect')).receipts === before.receipts + 1, 'historical_receipt_not_active');
  });
  for (const mode of ['wrong-origin','wrong-source','wrong-id','wrong-key','error']) {
    await scenario('reject storage ' + mode, { blockCookies: true, mode }, async ({p,before,control,tool}) => {
      await p.goto(info.canvasOrigin + '/parent');
      await tool.getByText('Unable to confirm this browser. Launch again from Canvas.', {exact:true}).waitFor({timeout:12000});
      ensure((await control('inspect')).receipts === before.receipts, 'unbound_storage_receipt');
      ensure(await tool.getByRole('heading', {name:'Canvas connected',exact:true}).count() === 0, 'unbound_storage_resource');
    });
  }
  await scenario('neither cookie nor advertised storage fails closed', {blockCookies:true}, async ({p,before,control}) => {
    const rejected = p.waitForResponse(response => response.status() === 403 && response.url().split('?')[0] === info.connectorOrigin + info.base + '/launch');
    await p.goto(info.canvasOrigin + '/parent?storage=false');await rejected;
    ensure((await control('inspect')).receipts === before.receipts, 'no_browser_proof');
  });
  await scenario('lost acceptance reply reconciles original browser launch', {blockCookies:true,lose:true}, async ({p,before,control,connected,replay,state}) => {
    const lost = p.waitForResponse(response => response.status() === 503 && response.url().split('?')[0] === info.connectorOrigin + info.base + '/confirm');
    await p.goto(info.canvasOrigin + '/parent');await lost;
    ensure((await control('inspect')).receipts === before.receipts + 1, 'lost_reply_committed');
    const original = state();
    const retried = p.waitForResponse(response => response.url().split('?')[0] === info.connectorOrigin + info.base + '/launch');
    await replay();await retried;await connected();
    ensure(state() === original && (await control('inspect')).receipts === before.receipts + 1, 'lost_reply_original_identity');
  });
  return { browser: browser.version(), passed: results.length, failed: 0, scenarios: results,
    scope: 'Real browser + production HTTP/lifecycle/repository + actual PG16 via test-only docker/psql adapter + synthetic verified-TLS Canvas peer. Synthetic browser certificates ignored; cookie-free cases suppress Set-Cookie only at the test edge. No production TLS PG pool or real Canvas/Gateway/OB3-wallet qualification.' };
}
