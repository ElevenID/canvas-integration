// SPDX-License-Identifier: AGPL-3.0-only
// Actual production runtime/PG/OpenBao + Chromium; canonical Gateway/Canvas are
// synthetic public HTTPS peers. This is not deployed Core authority qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createConnectorOAuthRuntime } from '../src/connector-oauth-runtime.mjs';
import { createConnectorPostgresPool } from '../src/postgres-pool.mjs';
import { createOpenBaoKeyProvider } from '../src/openbao-key-provider.mjs';
import { createLtiServiceStore } from '../src/lti-service-store.mjs';
import { ltiServiceReadScopes } from '../src/lti-service-contract.mjs';
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
let loseCaptureReply=false,revokeCaptureAfterCommit=false,forgeCaptureReceipt=false;
let switchAfterPermission=false;
let loseRecoveryReply=false,ltiExchanges=0;
const binding = { id:'operator-binding',source_id:'operator-source',active:true,revision:3,
  provider:'canvas',fact_type:'canvas.course_completion',resource_scope:{canvas_origin:canvasOrigin,course_id:'11',user_id:'22'},
  application_id:'private-operator-application',subject_id:'private-operator-subject',application_status:'pending',
  application_revision:1794844800000000,application_expires_at_ms:Date.now()+600000,
  claim_rules:{completed:{kind:'boolean',required:true,nullable:false},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}} };
const captureRegistration='10000000-0000-4000-8000-000000000091';
const ltiBindings=new Map([
 ['operator-lti-binding',{...binding,id:'operator-lti-binding',revision:1,fact_type:'canvas.ags_result',
  resource_scope:{canvas_origin:canvasOrigin,registration_id:captureRegistration,course_id:'11',user_id:'opaque:operator',line_item_id:'33',resource_link_id:'operator-link'},
  claim_rules:{score:{kind:'number',required:true,nullable:true,minimum:-10000,maximum:10000},
   effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}}}],
 ['operator-lti-member-binding',{...binding,id:'operator-lti-member-binding',revision:1,fact_type:'canvas.nrps_membership',
  resource_scope:{canvas_origin:canvasOrigin,registration_id:captureRegistration,course_id:'11',user_id:'opaque:operator',context_id:'operator-context',resource_link_id:'operator-link'},
  claim_rules:{provider_state:{kind:'text',required:true,nullable:false,max_bytes:32},effective_time_source:{kind:'text',required:true,nullable:false,max_bytes:32}}}],
]);
front.setHandler((req,res) => { void (async () => {
  if (req.url === '/fixture/login') {
    res.writeHead(302,{'Set-Cookie':session+'; Path=/; Secure; HttpOnly; SameSite=Lax',Location:'/admin'});res.end();return;
  }
  if (req.url.startsWith('/v1/')) {
    gatewayReads++;
    assert.equal(req.headers.cookie, session); assert.equal(req.headers['x-api-key'],undefined); assert.equal(req.headers['x-organization-id'],undefined);
    assert.equal(req.headers['x-connector-organization-intent'],undefined);
    if (req.url === '/v1/auth/me') return json(res,{authenticated:true,user:{user_id:'operator-actor',organization_id:sessionOrg}});
    if (req.url === `/v1/organizations/${sessionOrg}/members/me/permissions`) {
      if(revokeCaptureAfterCommit&&owner(`SELECT count(*) FROM canvas_connector.lti_capture_operation_audit WHERE organization_id='${org}' AND route_id='operator-lti-member' AND action='create';`)==='1') {
        revokeCaptureAfterCommit=false;permitted=false;
      }
      if(switchAfterPermission){switchAfterPermission=false;sessionOrg=otherOrg;}
      return json(res,{permissions:permitted?['integration-connector:edit']:[]});
    }
    if (req.url === `/v1/organizations/${org}/external-observation-bindings/operator-binding/inspect`) {
      assert.equal(req.headers.origin,front.origin);
      let body='';for await(const part of req)body+=part;assert.equal(body,'{}');
      return json(res,{found:true,record:binding,snapshot_at_ms:Date.now()},200,{'Cache-Control':'no-store'});
    }
    const ltiBinding=/^\/v1\/organizations\/[^/]+\/external-observation-bindings\/(operator-lti-(?:binding|member-binding))\/inspect$/.exec(req.url);
    if(ltiBinding&&sessionOrg===org) {
      assert.equal(req.headers.origin,front.origin);let body='';for await(const part of req)body+=part;assert.equal(body,'{}');
      return json(res,{found:true,record:ltiBindings.get(ltiBinding[1]),snapshot_at_ms:Date.now()},200,{'Cache-Control':'no-store'});
    }
    res.writeHead(404);res.end();return;
  }
  if (!address) {res.writeHead(503);res.end();return;}
  if(req.method==='POST' && /\/(create|change|provision|rotate|disconnect|replace|activate|deactivate|schedule|recover|exchange|resolve)$/.test(req.url)) mutationRequests++;
  const proxy=request({hostname:'localhost',port:address.port,method:req.method,path:req.url,ca:front.ca,agent:false,
    headers:{...req.headers,host:new URL(front.origin).host}},reply=>{
    if(loseReply && req.method==='POST' && req.url.endsWith('/configuration/change') && reply.statusCode===200) {
      loseReply=false;reply.resume();reply.on('end',()=>res.destroy());return;
    }
    if(loseRecoveryReply&&req.method==='POST'&&req.url.endsWith('/service-credentials/recover')&&reply.statusCode===200){
      loseRecoveryReply=false;reply.resume();reply.on('end',()=>res.destroy());return;
    }
    if(loseCaptureReply&&req.method==='POST'&&/\/capture-routes\/operator-lti-route\/schedule$/.test(req.url)&&reply.statusCode===200) {
      loseCaptureReply=false;reply.resume();reply.on('end',()=>res.destroy());return;
    }
    if(forgeCaptureReceipt&&/\/capture-routes\/[^/]+\/receipt$/.test(req.url)&&reply.statusCode===200) {
      const corruption=forgeCaptureReceipt;forgeCaptureReceipt=false;const chunks=[];reply.on('data',c=>chunks.push(c));reply.on('end',()=>{
        const value=JSON.parse(Buffer.concat(chunks).toString());
        if(corruption==='version')value.receipt.version+=1;else if(corruption==='service')value.receipt.serviceOperationId=randomUUID();else value.receipt.routeId='another-route';
        const body=JSON.stringify(value);
        res.writeHead(200,{...reply.headers,'content-length':Buffer.byteLength(body)});res.end(body);
      });return;
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
  if(values.get('grant_type')==='client_credentials') {
    assert.equal(values.has('client_secret'),false);assert.ok(values.get('client_assertion'));ltiExchanges++;
    return json(res,{access_token:'synthetic_operator_lti_access_token_00001',expires_in:3600,token_type:'Bearer',scope:values.get('scope')});
  }
  assert.equal(values.get('client_secret'),secret);exchanges++;
  json(res,{access_token:'synthetic_operator_access_token_000001',refresh_token:'synthetic_operator_refresh_token_00001',expires_in:3600,token_type:'Bearer'});
})().catch(()=>res.destroy());});
try {
  // The preceding POSIX custody contract rotates its own HTTP login. This
  // fixture owns a separate login inheriting only that reviewed restricted role,
  // so its credential never depends on another fixture's rotation phase.
  owner("CREATE ROLE canvas_operator_http LOGIN PASSWORD 'synthetic-operator-http-password'; GRANT canvas_oauth_http,canvas_lti_capture_admin TO canvas_operator_http;");
  owner("UPDATE canvas_connector.oauth_http_limit SET request_limit=1000,hits=0,window_started_at=clock_timestamp()-interval '1 second';");
  runtime=await createConnectorOAuthRuntime({
    database:{host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_operator_http',ca:f.ca,
      credentialProvider:{getPassword:async()=> 'synthetic-operator-http-password'},maxConnections:8,queryTimeoutMs:5000,connectTimeoutMs:1000},
    keyCustody:{openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}},
    canvas:{ca:canvas.ca,allowedPrivateAddresses:['127.0.0.1','::1'],timeoutMs:10000},
    gatewayAuthentication:{gatewayOrigin:front.origin,sessionCookieName:'__Host-marty_session',ca:front.ca},
    http:{publicOrigin:front.origin,completionUrl:front.origin+'/complete',tls:{key:front.key,cert:front.ca},port:0,maxConcurrentRequests:8},
    lti:{selfManagedOriginAllowlist:[canvasOrigin],allowedPrivateAddresses:['127.0.0.1','::1'],ca:canvas.ca,services:true,captures:true},
  });
  address=await runtime.listen();
  browser=await chromium.launch({headless:true});
  const noScriptContext=await browser.newContext({ignoreHTTPSErrors:true,javaScriptEnabled:false});
  try {
    const inert=await noScriptContext.newPage();await inert.goto(front.origin+'/admin');
    assert.equal(await inert.locator('#client-provision [name=client_secret]').isDisabled(),true);
    assert.equal(await inert.locator('#platform-create button').isDisabled(),true);
  } finally {await noScriptContext.close();}
  const context=await browser.newContext({ignoreHTTPSErrors:true}); // Owned fixture certificates only.
  let page=await context.newPage();const pageErrors=[];
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
  const registration=captureRegistration;
  await submit('lti-edit',{resource_id:registration,client_id:'lti-operator-client',deployment_id:'operator-deployment',trust_profile:'self_managed_same_origin'});
  assert.equal((await output()).receipt.enabled,false);
  await submit('lti-action',{resource_id:registration,action:'activate',expected_registration_version:'1'});assert.equal((await output()).receipt.enabled,true);
  await submit('lti-key',{resource_id:registration,action:'provision',expected_registration_version:'2'});
  const toolKey=(await output()).receipt;assert.equal(toolKey.version,1);
  await submit('lti-key',{action:'inspect'});assert.equal((await output()).publicJwksUrl,front.origin+`/lti/registrations/${registration}/jwks`);
  const beforePublic=gatewayReads,jwks=await context.request.get(front.origin+`/lti/registrations/${registration}/jwks`);
  assert.equal(jwks.status(),200);assert.equal((await jwks.json()).keys[0].kid,toolKey.kid);assert.equal(gatewayReads,beforePublic);
  await page.locator('#lti-credential').evaluate(element=>element.closest('details').open=true);
  await page.locator('#lti-credential [value=lineitems]').check();await page.locator('#lti-credential [value=memberships]').check();
  await submit('lti-credential',{resource_id:registration,action:'exchange',expected_registration_version:'2',expected_key_version:'1'});
  assert.equal((await output()).attempt.phase,'published');const captureCredential=(await output()).attempt.attemptId;
  assert.equal(ltiExchanges,1);assert.equal(await page.locator('#operations li').count(),0);
  assert.equal((await page.locator('body').textContent()).includes('synthetic_operator_lti_access_token_00001'),false);
  const stagingPool=createConnectorPostgresPool({host:'localhost',port:f.port,database:'canvas_driver_test',user:'canvas_operator_http',ca:f.ca,
    credentialProvider:{getPassword:async()=> 'synthetic-operator-http-password'},maxConnections:4,queryTimeoutMs:5000,connectTimeoutMs:1000});
  let stagedAttempt;
  try {
    const tokens=createLtiServiceStore({pool:stagingPool,keyProvider:createOpenBaoKeyProvider({openbaoOrigin:f.baoOrigin,mount:'connector-kv',keyPath:'canvas-envelope',keyNamespace:'canvas',ca:f.baoCa,tokenProvider:{getToken:async()=>f.baoToken}})});
    const prepared=await tokens.prepare({organizationId:org,platformId:'operator-platform',registrationId:registration,operationId:randomUUID(),actorId:'operator-actor',
      expectedPlatformVersion:3,expectedRegistrationVersion:2,expectedKeyVersion:1,scopes:[ltiServiceReadScopes.results]});
    stagedAttempt=await tokens.begin({organizationId:org,operationId:prepared.operationId,dispatchId:randomUUID()});
    await tokens.stage(stagedAttempt,{accessToken:'synthetic_operator_staged_lti_access_00002',scopes:stagedAttempt.scopes},(stagedAttempt.issuedAt+3600)*1000);
  }finally{await stagingPool.close();}
  const oldPage=page;page=await context.newPage();page.on('pageerror',error=>pageErrors.push(error.name));await oldPage.close();
  await page.goto(front.origin+'/admin');await wait();assert.equal(await page.locator('#operations li').count(),0);
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  loseRecoveryReply=true;await submit('lti-credential',{resource_id:registration,action:'recover',attempt_id:stagedAttempt.operationId});
  const originalRecovery=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('elevenid_canvas_operator_pending_v1')));
  assert.equal(originalRecovery.length,1);assert.equal(originalRecovery[0].operationId,stagedAttempt.operationId);assert.deepEqual(originalRecovery[0].extras,{});
  const beforeRecoveryReads=mutationRequests;await page.reload();await wait();await click('#operations button');
  assert.equal((await output()).receipt.operationId,stagedAttempt.operationId);assert.equal(await page.locator('#operations li').count(),0);
  assert.equal(mutationRequests,beforeRecoveryReads);assert.equal(ltiExchanges,1,'fresh-tab recovery and receipt reconciliation never repeat Canvas exchange');
  // Capture administration uses the same canonical session, with a distinct
  // journal family bound to registration, route, action and original operation.
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  await submit('lti-capture-edit',{action:'create',registration_id:registration,resource_id:'operator-lti-route',expected_registration_version:'2',expected_key_version:'1',
    service_operation_id:captureCredential,producer_ref:'operator-source',binding_id:'operator-lti-binding',binding_revision:'1',fact_type:'canvas.ags_result',
    course_id:'11',provider_user_id:'opaque:operator',resource_link_id:'operator-link',line_item_id:'33'});
  assert.equal((await output()).receipt.version,1);assert.equal((await output()).receipt.enabled,false);
  const captureTarget={registration_id:registration,resource_id:'operator-lti-route',expected_registration_version:'2',expected_key_version:'1',service_operation_id:captureCredential};
  await submit('lti-capture-action',{action:'activate',...captureTarget,expected_route_version:'1'});assert.equal((await output()).receipt.version,2);
  await submit('lti-capture-action',{action:'catalog',registration_id:registration});assert.equal((await output()).routes[0].routeId,'operator-lti-route');
  loseCaptureReply=true;await submit('lti-capture-action',{action:'schedule',...captureTarget,expected_route_version:'2'});
  const pendingCapture=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('elevenid_canvas_operator_pending_v1')));
  assert.equal(pendingCapture.length,1);assert.equal(pendingCapture[0].formId,'lti-capture-action');assert.deepEqual(pendingCapture[0].extras,{expectedVersion:2,serviceOperationId:captureCredential});
  const captureOperation=pendingCapture[0].operationId,beforeCaptureReceipt=mutationRequests;
  await page.reload();await wait();await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  await submit('lti-capture-action',{action:'schedule',...captureTarget,expected_route_version:'2'});assert.equal(mutationRequests,beforeCaptureReceipt);
  const corruptKind=structuredClone(pendingCapture);corruptKind[0].formId='route-action';
  await page.evaluate(value=>sessionStorage.setItem('elevenid_canvas_operator_pending_v1',JSON.stringify(value)),corruptKind);await page.reload();
  assert.match(await page.locator('#notice').textContent(),/storage/);
  await page.evaluate(value=>sessionStorage.setItem('elevenid_canvas_operator_pending_v1',JSON.stringify(value)),pendingCapture);await page.reload();await wait();
  for(const corruption of ['route','version','service']) {
    forgeCaptureReceipt=corruption;await click('#operations button');assert.equal(await page.locator('#operations li').count(),1,'mismatched '+corruption+' receipt cannot clear original pointer');
  }
  await click('#operations button');assert.equal((await output()).receipt.captureId,captureOperation);assert.equal(await page.locator('#operations li').count(),0);
  assert.equal(mutationRequests,beforeCaptureReceipt);
  assert.equal(owner(`SELECT count(*) FROM canvas_connector.lti_capture_operation_audit WHERE organization_id='${org}' AND operation_id='${captureOperation}';`),'1');
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  await submit('lti-capture-action',{action:'capture',registration_id:registration,resource_id:'operator-lti-route',capture_id:captureOperation});assert.equal((await output()).capture.phase,'pending');
  await submit('receipt',{kind:'lti-capture',registration_id:registration,resource_id:'operator-lti-route',operation_id:captureOperation});assert.equal((await output()).receipt.captureId,captureOperation);
  await submit('lti-capture-action',{action:'deactivate',registration_id:registration,resource_id:'operator-lti-route',expected_route_version:'2'});assert.equal((await output()).receipt.version,3);
  await submit('lti-capture-edit',{action:'replace',registration_id:registration,resource_id:'operator-lti-route',expected_route_version:'3',expected_registration_version:'2',expected_key_version:'1',
    service_operation_id:captureCredential,producer_ref:'operator-source',binding_id:'operator-lti-binding',binding_revision:'1',fact_type:'canvas.ags_result',
    course_id:'11',provider_user_id:'opaque:operator',resource_link_id:'operator-link',line_item_id:'33'});
  assert.equal((await output()).receipt.version,4);assert.equal((await output()).receipt.enabled,false);
  revokeCaptureAfterCommit=true;
  await submit('lti-capture-edit',{action:'create',registration_id:registration,resource_id:'operator-lti-member',expected_registration_version:'2',expected_key_version:'1',
    service_operation_id:captureCredential,producer_ref:'operator-source',binding_id:'operator-lti-member-binding',binding_revision:'1',fact_type:'canvas.nrps_membership',
    course_id:'11',provider_user_id:'opaque:operator',resource_link_id:'operator-link',context_id:'operator-context'});
  assert.match(await page.locator('#notice').textContent(),/permission/);
  const committedForbidden=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('elevenid_canvas_operator_pending_v1')));
  assert.equal(committedForbidden.length,1);assert.equal(committedForbidden[0].formId,'lti-capture-edit');
  assert.deepEqual(committedForbidden[0].extras,{expectedVersion:1,serviceOperationId:captureCredential});
  for(const privateValue of ['opaque:operator','provider_state',secret,'synthetic_operator_lti_access_token_00001'])assert.equal(JSON.stringify(committedForbidden).includes(privateValue),false);
  assert.equal(owner(`SELECT count(*) FROM canvas_connector.lti_capture_operation_audit WHERE organization_id='${org}' AND operation_id='${committedForbidden[0].operationId}';`),'1');
  const beforeForbiddenReceipt=mutationRequests;permitted=true;await page.reload();await wait();await click('#operations button');
  assert.equal((await output()).receipt.routeId,'operator-lti-member');assert.equal(await page.locator('#operations li').count(),0);assert.equal(mutationRequests,beforeForbiddenReceipt);
  assert.equal(ltiExchanges,1,'capture controls do not exchange or retry Canvas credentials');
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  // Current permission is reloaded; a previously loaded console confers no right.
  permitted=false;const beforeDenied=owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${org}' AND id='operator-platform';`);
  await submit('platform-change',{mode:'disable'});assert.match(await page.locator('#notice').textContent(),/permission/);
  assert.equal(owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${org}' AND id='operator-platform';`),beforeDenied);permitted=true;
  owner(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,config_version,enabled) VALUES('${otherOrg}','operator-platform','${canvasOrigin}',3,true);`);
  sessionOrg=otherOrg;
  await submit('platform-change',{mode:'disable'});assert.match(await page.locator('#notice').textContent(),/organization/);
  assert.equal(owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${otherOrg}' AND id='operator-platform';`),'3');
  sessionOrg=org;switchAfterPermission=true;
  await submit('platform-change',{mode:'disable'});assert.match(await page.locator('#notice').textContent(),/organization/);
  assert.equal(owner(`SELECT config_version FROM canvas_connector.platforms WHERE organization_id='${org}' AND id='operator-platform';`),'3');
  sessionOrg=org;await click('#reload-context');await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');
  // Real commit, lost HTTP reply. One immutable operation survives reload and
  // tenant switches; reconciliation never calls the write endpoint again.
  loseReply=true;await submit('platform-change',{mode:'disable'});
  const pending=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('elevenid_canvas_operator_pending_v1')));
  assert.equal(pending.length,1);const originalId=pending[0].operationId,beforeReconcile=mutationRequests;
  await page.reload();await page.locator('#platform-id').fill('operator-platform');
  await submit('platform-change',{mode:'disable'});assert.equal(mutationRequests,beforeReconcile);
  sessionOrg=otherOrg;await click('#operations button');assert.match(await page.locator('#notice').textContent(),/organization/);
  await click('#reload-context');await click('#operations button');assert.match(await page.locator('#notice').textContent(),/original ElevenID organization/);
  assert.equal(await page.locator('#operations li').count(),1);sessionOrg=org;
  await click('#reload-context');await click('#operations button');assert.equal((await output()).receipt.operationId,originalId);assert.equal(await page.locator('#operations li').count(),0);
  assert.equal(mutationRequests,beforeReconcile);
  assert.equal(owner(`SELECT count(*) FROM canvas_connector.platform_operation_audit WHERE organization_id='${org}' AND operation_id='${originalId}';`),'1');
  await page.locator('#platform-id').fill('operator-platform');await click('#inspect-platform');assert.equal((await output()).platform.enabled,false);
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
  if(screenshot) {
    assert.ok(isAbsolute(screenshot));
    for(const id of ['lti-capture-edit','lti-capture-action'])await page.locator('#'+id).evaluate(element=>element.closest('details').open=true);
    await page.locator('#lti-capture-action [name=action]').selectOption('activate');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    await page.screenshot({path:screenshot,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    await page.screenshot({path:screenshot.replace(/\.png$/,'-mobile.png'),fullPage:true});
  }
  await context.close();
  console.log('Actual Chromium operator -> same-origin HttpOnly Gateway session -> production restricted-role PG/OpenBao/platform/client/OAuth/capture/LTI/disconnect passed; lost commit reply/tenant switch/permission revocation/reload/pointer tamper preserve original operation, no automatic write retry. Synthetic public Gateway authority only.');
} finally {
  await browser?.close();await runtime?.close();await front.close();await canvas.close();
}
