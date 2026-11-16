// SPDX-License-Identifier: AGPL-3.0-only
// Actual production runtime/PG/OpenBao + Chromium; canonical Gateway/Canvas are
// synthetic public HTTPS peers. This is not deployed Core authority qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';

const [file, container, browserModule] = process.argv.slice(2);
assert.match(file ?? '', /canvas-driver-contract-[^/\\]+[/\\]synthetic-fixture\.json$/);
assert.match(container ?? '', /^canvas-pg-driver-[a-f0-9]{32}$/);
assert.ok(isAbsolute(browserModule));
assert.equal(JSON.parse(await readFile(join(dirname(browserModule), 'package.json'), 'utf8')).version, '1.59.1');
const { chromium } = await import(pathToFileURL(browserModule).href);
const f = JSON.parse(await readFile(file, 'utf8'));
const owner = sql => execFileSync('docker', ['exec','-i',container,'psql','-X','-q','-A','-t','-U','postgres','-d','canvas_driver_test','-v','ON_ERROR_STOP=1'], {input:sql,encoding:'utf8'}).trim();
const front = await httpsFixture(), canvas = await httpsFixture({ipAddressSan:true});
const canvasOrigin = canvas.origin.replace('localhost','127.0.0.1');
const org = '750e8400-e29b-41d4-a716-446655440091', otherOrg = '750e8400-e29b-41d4-a716-446655440092';
const session = '__Host-marty_session=synthetic_operator_session_000001';
const secret = 'synthetic_operator_client_secret_000001';
let permitted = true, sessionOrg = org, address, runtime, browser, loseReply = false, exchanges = 0;
let mutationRequests = 0, gatewayReads = 0;
const binding = { id:'operator-binding',source_id:'operator-source',active:true,revision:3,
  provider:'canvas',fact_type:'canvas.course_completion',resource_scope:{canvas_origin:canvasOrigin,course_id:'11',user_id:'22'},
  application_id:'private-operator-application',subject_id:'private-operator-subject',application_status:'pending',
  application_revision:1794844800000000,application_expires_at_ms:Date.now()+600000,
  claim_rules:{completed:{kind:'boolean',required:true,nullable:false},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}} };
front.setHandler((req,res) => { void (async () => {
  if (req.url === '/fixture/login') {
    res.writeHead(302,{'Set-Cookie':session+'; Path=/; Secure; HttpOnly; SameSite=Lax',Location:'/admin'});res.end();return;
  }
  if (req.url.startsWith('/v1/')) {
    gatewayReads++;
    assert.equal(req.headers.cookie, session); assert.equal(req.headers['x-api-key'],undefined); assert.equal(req.headers['x-organization-id'],undefined);
    if (req.url === '/v1/auth/me') return json(res,{authenticated:true,user:{user_id:'operator-actor',organization_id:sessionOrg}});
    if (req.url === `/v1/organizations/${sessionOrg}/members/me/permissions`) return json(res,{permissions:permitted?['integration-connector:edit']:[]});
    if (req.url === `/v1/organizations/${org}/external-observation-bindings/operator-binding/inspect`) {
      assert.equal(req.headers.origin,front.origin);
      let body='';for await(const part of req)body+=part;assert.equal(body,'{}');
      return json(res,{found:true,record:binding,snapshot_at_ms:Date.now()},200,{'Cache-Control':'no-store'});
    }
    res.writeHead(404);res.end();return;
  }
  if (!address) {res.writeHead(503);res.end();return;}
  if(req.method==='POST' && /\/(create|change|provision|disconnect|replace|activate|deactivate|schedule|recover)$/.test(req.url)) mutationRequests++;
  const proxy=request({hostname:'localhost',port:address.port,method:req.method,path:req.url,ca:front.ca,agent:false,
    headers:{...req.headers,host:new URL(front.origin).host}},reply=>{
    if(loseReply && req.method==='POST' && req.url.endsWith('/configuration/change') && reply.statusCode===200) {
      loseReply=false;reply.resume();reply.on('end',()=>res.destroy());return;
    }
    res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);
  });
  proxy.on('error',()=>res.destroy());req.pipe(proxy);
})().catch(()=>{res.destroy();}); });
canvas.setHandler((req,res)=>{void(async()=>{
  assert.equal(req.headers.cookie,undefined,'Gateway session must never reach the Canvas hostname');
  assert.equal(req.headers['x-api-key'],undefined);
  const url=new URL(req.url,canvasOrigin);
  if(url.pathname==='/login/oauth2/auth') {
    const redirect=new URL(url.searchParams.get('redirect_uri'));assert.equal(redirect.href,front.origin+'/oauth/callback');
    redirect.searchParams.set('state',url.searchParams.get('state'));redirect.searchParams.set('code','synthetic_operator_code');
    res.writeHead(302,{Location:redirect.href});res.end();return;
  }
  assert.equal(url.pathname,'/login/oauth2/token');
  let body='';for await(const part of req)body+=part;const values=new URLSearchParams(body);
  assert.equal(values.get('client_secret'),secret);exchanges++;
  json(res,{access_token:'synthetic_operator_access_token_000001',refresh_token:'synthetic_operator_refresh_token_00001',expires_in:3600,token_type:'Bearer'});
})().catch(()=>res.destroy());});
try {
  owner("UPDATE canvas_connector.oauth_http_limit SET request_limit=1000,hits=0,window_started_at=clock_timestamp()-interval '1 second';");
  runtime=await createConnectorOAuthRuntime({
    database:{host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_oauth_http',ca:f.ca,
      credentialProvider:{getPassword:async()=> 'synthetic-oauth-http-password'},maxConnections:8,queryTimeoutMs:5000,connectTimeoutMs:1000},
    keyCustody:{openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}},
    canvas:{ca:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:10000},
    gatewayAuthentication:{gatewayOrigin:front.origin,sessionCookieName:'__Host-marty_session',ca:front.ca},
    http:{publicOrigin:front.origin,completionUrl:front.origin+'/complete',tls:{key:front.key,cert:front.ca},port:0,maxConcurrentRequests:8},
    lti:{selfManagedOriginAllowlist:[canvasOrigin],allowedPrivateAddresses:['127.0.0.1','::1'],ca:canvas.ca},
  });
  address=await runtime.listen();
  browser=await chromium.launch({headless:true});
  const context=await browser.newContext({ignoreHTTPSErrors:true}); // Owned fixture certificates only.
  const page=await context.newPage(), pageErrors=[];
  page.on('pageerror',error=>pageErrors.push(error.name));
  const idle=()=>page.locator('#workspace').evaluate(element=>!element.disabled);
  const wait=()=>page.waitForFunction(()=>!document.getElementById('workspace').disabled);
  async function click(selector) {await page.locator('#workspace[data-ready=true]').waitFor();await page.locator(selector).click();await wait();}
  async function submit(id,values={}) {
    await page.locator('#'+id).evaluate(element=>element.closest('details').open=true);
    for(const [name,value] of Object.entries(values)) {
      const field=page.locator('#'+id+` [name="${name}"]`);
      if(await field.evaluate(element=>element.tagName)==='SELECT') await field.selectOption(value);else await field.fill(value);
    }
    await click('#'+id+' button[type=submit], #'+id+' button:not([type])');
  }
  const output=async()=>{
    const value=await page.locator('#result').textContent();
    try{return JSON.parse(value);}catch{throw Error('operator_output_not_json: '+await page.locator('#notice').textContent());}
  };
  // The shell is public; no cookie is invented and API data stays unauthorized.
  await page.goto(front.origin+'/admin');assert.equal((await context.cookies()).length,0);
  await click('#catalog');assert.match(await page.locator('#notice').textContent(),/Sign in/);assert.equal(gatewayReads,0);
  await page.goto(front.origin+'/fixture/login');
  const cookies=await context.cookies();assert.ok(cookies.some(cookie=>cookie.name==='__Host-marty_session'&&cookie.httpOnly&&cookie.secure));
  assert.equal(await page.evaluate(()=>document.cookie.includes('__Host-marty_session')),false);
  await submit('platform-create',{platform_id:'operator-platform',canvas_origin:canvasOrigin});
  assert.equal((await output()).receipt.configVersion,1);
  await click('#catalog');await page.getByRole('button',{name:'operator-platform · disabled',exact:true}).click();await click('#inspect-platform');
  await submit('platform-change',{mode:'enable'});assert.equal((await output()).receipt.configVersion,2);await click('#inspect-platform');
  await submit('client-provision',{client_id:'operator-client',client_secret:secret});assert.equal((await output()).receipt.configVersion,3);
  assert.equal(await page.locator('#client-provision [name=client_secret]').inputValue(),'');
  assert.equal((await page.locator('body').textContent()).includes(secret),false);
  assert.equal(await page.evaluate(value=>JSON.stringify(sessionStorage).includes(value),secret),false);
  await click('#inspect-platform');
  await page.locator('#oauth-start').evaluate(element=>element.closest('details').open=true);
  await page.locator('#oauth-start [value=course_completion]').check();
  await page.locator('#oauth-start button').click();await page.waitForURL(url=>url.origin===front.origin&&url.pathname==='/complete'&&url.searchParams.get('outcome')==='connected');
  assert.equal(exchanges,1);await page.getByRole('link',{name:'Return to Canvas connections'}).click();
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');await click('#inspect-connection');
  const connection=(await output()).connection;assert.equal(connection.status,'connected');
  await submit('route-edit',{resource_id:'operator-route',producer_ref:'operator-source',binding_id:'operator-binding',binding_revision:'3',course_id:'11',user_id:'22'});
  assert.equal((await output()).receipt.enabled,false);
  for(const privateValue of ['private-operator-application','private-operator-subject',secret]) assert.equal((await page.locator('body').textContent()).includes(privateValue),false);
  await submit('route-action',{resource_id:'operator-route',action:'activate',expected_route_version:'1'});assert.equal((await output()).receipt.version,2);
  await submit('route-action',{action:'schedule',expected_route_version:'2'});const capture=(await output()).receipt.captureId;assert.ok(capture);
  await submit('route-action',{action:'capture',capture_id:capture});assert.equal((await output()).capture.phase,'pending');
  const registration='10000000-0000-4000-8000-000000000091';
  await submit('lti-edit',{resource_id:registration,client_id:'lti-operator-client',deployment_id:'operator-deployment',trust_profile:'self_managed_same_origin'});
  assert.equal((await output()).receipt.enabled,false);
  await submit('lti-action',{resource_id:registration,action:'activate',expected_registration_version:'1'});assert.equal((await output()).receipt.enabled,true);
  // Current permission is reloaded; a previously loaded console confers no right.
  permitted=false;const beforeDenied=owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${org}' AND id='operator-platform';`);
  await submit('platform-change',{mode:'disable'});assert.match(await page.locator('#notice').textContent(),/permission/);
  assert.equal(owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${org}' AND id='operator-platform';`),beforeDenied);permitted=true;
  // Real commit, lost HTTP reply. One immutable operation survives reload and
  // tenant switches; reconciliation never calls the write endpoint again.
  loseReply=true;await submit('platform-change',{mode:'disable'});
  const pending=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('elevenid_canvas_operator_pending_v1')));
  assert.equal(pending.length,1);const originalId=pending[0].operationId,beforeReconcile=mutationRequests;
  await page.reload();await page.locator('#platform-id').fill('operator-platform');
  await submit('platform-change',{mode:'disable'});assert.equal(mutationRequests,beforeReconcile);
  sessionOrg=otherOrg;await click('#operations button');assert.match(await page.locator('#notice').textContent(),/No receipt/);
  assert.equal(await page.locator('#operations li').count(),1);sessionOrg=org;
  await click('#operations button');assert.equal((await output()).receipt.operationId,originalId);assert.equal(await page.locator('#operations li').count(),0);
  assert.equal(mutationRequests,beforeReconcile);
  assert.equal(owner(`SELECT count(*) FROM canvas_connector.platform_operation_audit WHERE organization_id='${org}' AND operation_id='${originalId}';`),'1');
  await click('#inspect-platform');assert.equal((await output()).platform.enabled,false);
  // Tampered local pointers never supply an endpoint, session or tenant authority.
  await page.evaluate(()=>sessionStorage.setItem('elevenid_canvas_operator_pending_v1','[{"path":"https://evil.example/steal"}]'));
  await page.reload();assert.match(await page.locator('#notice').textContent(),/storage/);
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  const beforeStorageFailure=mutationRequests;await submit('platform-change',{mode:'enable'});assert.equal(mutationRequests,beforeStorageFailure);
  await page.evaluate(()=>sessionStorage.removeItem('elevenid_canvas_operator_pending_v1'));await page.reload();
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  await submit('connection-disconnect',{connection_id:connection.connectionId,expected_revision:String(connection.revision)});
  assert.equal((await output()).receipt.status,'disconnected');assert.equal(await page.locator('#operations li').count(),0);
  assert.equal(exchanges,1);assert.deepEqual(pageErrors,[]);assert.ok(await idle());
  const screenshot=process.env.CANVAS_OPERATOR_TEST_SCREENSHOT;
  if(screenshot) {assert.ok(isAbsolute(screenshot));await page.screenshot({path:screenshot,fullPage:true});}
  await context.close();
  console.log('Actual Chromium operator -> same-origin HttpOnly Gateway session -> production restricted-role PG/OpenBao/platform/client/OAuth/capture/LTI/disconnect passed; lost commit reply/tenant switch/permission revocation/reload/pointer tamper preserve original operation, no automatic write retry. Synthetic public Gateway authority only.');
} finally {
  await browser?.close();await runtime?.close();await front.close();await canvas.close();
}
