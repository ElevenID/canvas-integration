// SPDX-License-Identifier: AGPL-3.0-only
// Test-only real PG/HTTPS/JWT peers for an isolated browser context. Never deploy.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, unlink } from 'node:fs/promises';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
import { httpsFixture, json } from './support/canvas-https-fixture.mjs';
import { createLtiLaunchRepository } from '../src/lti-launch-repository.mjs';
import { createLtiLaunchLifecycle } from '../src/lti-launch-lifecycle.mjs';
import { createLtiLaunchHandler } from '../src/lti-launch-http.mjs';

const [container, metadataPath] = process.argv.slice(2);
if (!/^canvas-lti-state-[a-f0-9]{32}$/.test(container) || !metadataPath) throw Error('owned_fixture_required');
const run = promisify(execFile), cap = randomBytes(32).toString('hex');
const quote = value => typeof value === 'number' ? String(value) : "'" + String(value).replaceAll("'", "''") + "'";
async function sql(source, role = false) {
  const result = await run('docker', ['exec',container,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','postgres',
    '-v','ON_ERROR_STOP=1','-c',(role ? 'SET ROLE lti_runtime; ' : '') + source]);
  return result.stdout.trim();
}
let loseConfirm = false, mode = 'valid', blockCookies = false;
const repository = createLtiLaunchRepository({ async query(statement, values) {
  const bound = statement.replace(/\$(\d+)/g, (_, index) => quote(values[Number(index)-1]));
  const output = await sql(`SELECT row_to_json(q) FROM (${bound}) q;`,true);
  const rows = output.split('\n').filter(Boolean).map(line => JSON.parse(line));
  if (loseConfirm && statement.includes('confirm_lti_launch') && rows[0]?.result !== null) {
    loseConfirm = false;throw Error('synthetic_lost_reply');
  }
  return { rows };
} });
const canvas = await httpsFixture(), connector = await httpsFixture(), evil = await httpsFixture();
const connectorOrigin = connector.origin.replace('localhost','127.0.0.1');
const registrationId = '10000000-0000-4000-8000-000000000003', base = `/lti/registrations/${registrationId}`;
const target = connectorOrigin+base+'/resource', pair = generateKeyPairSync('rsa',{modulusLength:2048});
const jwk = {...pair.publicKey.export({format:'jwk'}),kid:'browser-fixture'};
const C='https://purl.imsglobal.org/spec/lti/claim/', tokens=new Map();
const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
const escape=value=>String(value).replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;');
const html=(res,body)=>{res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(body);};
function launchForm(res,state,token,storageTarget) {
  html(res,`<!doctype html><form id="launch" method="POST" action="${connectorOrigin+base}/launch"><input name="state" value="${escape(state)}"><input name="id_token" value="${escape(token)}">${storageTarget?'<input name="lti_storage_target" value="post_message_forwarding">':''}</form><script>document.getElementById('launch').submit()</script>`);
}
let finish;
try {
  await sql(`INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES('org-browser','canvas-browser',${quote(canvas.origin)},true);
    INSERT INTO canvas_connector.lti_registrations(id,organization_id,platform_id,client_id,deployment_id,trust_profile,target_link_uri,enabled)
    VALUES('${registrationId}','org-browser','canvas-browser','client-browser','deployment-browser','self_managed_same_origin',${quote(target)},true);`);
  const lifecycle=createLtiLaunchLifecycle({repository,publicOrigin:connectorOrigin,platformPolicy:{selfManagedOriginAllowlist:[canvas.origin],
    allowedPrivateAddresses:['127.0.0.1','::1'],ca:canvas.ca}});
  const handler=createLtiLaunchHandler({lifecycle,publicOrigin:connectorOrigin,rateLimiter:{consume:async()=>true}});
  connector.setHandler((req,res)=>{
    if(blockCookies) {const original=res.writeHead;res.writeHead=function(status,headers){const copy={...headers};delete copy['Set-Cookie'];return original.call(this,status,copy);};}
    void handler(req,res).catch(()=>res.destroy());
  });
  evil.setHandler((_req,res)=>html(res,`<!doctype html><script>addEventListener('message',e=>{if(e.origin!==${JSON.stringify(canvas.origin)})return;parent.frames['tool'].postMessage(e.data,${JSON.stringify(connectorOrigin)});})</script>`));
  canvas.setHandler((req,res)=>{void(async()=>{
    const url=new URL(req.url,canvas.origin);
    if(url.pathname==='/api/lti/security/jwks')return json(res,{keys:[jwk]});
    if(url.pathname==='/control' && url.searchParams.get('cap')===cap) {
      const action=url.searchParams.get('action');
      if(action==='configure') {mode=url.searchParams.get('mode')??'valid';loseConfirm=url.searchParams.get('lose')==='true';blockCookies=url.searchParams.get('cookies')==='blocked';await sql("UPDATE canvas_connector.platforms SET enabled=true WHERE id='canvas-browser';");return json(res,{ok:true});}
      if(action==='disable') {await sql("UPDATE canvas_connector.platforms SET enabled=false WHERE id='canvas-browser';");return json(res,{ok:true});}
      if(action==='inspect') {
        const values=await sql(`SELECT json_build_object('receipts',(SELECT count(*) FROM canvas_connector.lti_launch_receipts a JOIN canvas_connector.lti_launch_states s USING(state_hash) WHERE s.registration_id='${registrationId}'),'staged',(SELECT count(*) FROM canvas_connector.lti_launch_states WHERE registration_id='${registrationId}' AND phase='staged'))`);
        return json(res,JSON.parse(values));
      }
      if(action==='finish') {json(res,{ok:true});finish();return;}
      res.writeHead(400);res.end();return;
    }
    if(url.pathname==='/storage')return html(res,`<!doctype html><script>
      const mode=${JSON.stringify(mode)},tool=${JSON.stringify(connectorOrigin)};
      addEventListener('message',e=>{const d=e.data;if(e.origin!==tool||!d||!['lti.put_data','lti.get_data'].includes(d.subject))return;
        const key=e.origin+'::'+d.key;let value;
        if(d.subject==='lti.put_data'){localStorage.setItem(key,d.value);value=d.value}else value=localStorage.getItem(key);
        const response={subject:d.subject+'.response',message_id:d.message_id,key:d.key,value};
        if(mode==='wrong-id')response.message_id+='wrong';if(mode==='wrong-key')response.key+='wrong';
        if(mode==='error')response.error={code:'key_not_found'};
        if(mode==='wrong-source'){parent.postMessage({fixture:response},${JSON.stringify(canvas.origin)});return;}
        if(mode==='wrong-origin'){parent.frames['evil'].postMessage(response,${JSON.stringify(evil.origin)});return;}
        e.source.postMessage(response,e.origin);
      });</script>`);
    if(url.pathname==='/api/lti/authorize_redirect') {
      const state=url.searchParams.get('state'),nonce=url.searchParams.get('nonce'),now=Math.floor(Date.now()/1000);
      const payload={iss:canvas.origin,aud:'client-browser',sub:'synthetic-browser-subject',nonce,iat:now-1,exp:now+120,
        [C+'version']:'1.3.0',[C+'message_type']:'LtiResourceLinkRequest',[C+'deployment_id']:'deployment-browser',
        [C+'target_link_uri']:target,[C+'resource_link']:{id:'browser-resource'},[C+'roles']:[]};
      const unsigned=encode({alg:'RS256',kid:jwk.kid})+'.'+encode(payload),token=unsigned+'.'+sign('RSA-SHA256',Buffer.from(unsigned),pair.privateKey).toString('base64url');
      const storageTarget=url.searchParams.get('login_hint')!=='cookie';tokens.set(state,{token,storageTarget});return launchForm(res,state,token,storageTarget);
    }
    if(url.pathname==='/replay') {const state=url.searchParams.get('state'),stored=tokens.get(state);if(!stored){res.writeHead(404);res.end();return;}return launchForm(res,state,stored.token,stored.storageTarget);}
    if(url.pathname==='/parent') {
      const storageTarget=url.searchParams.get('storage')!=='false';
      const login=connectorOrigin+base+'/login?'+new URLSearchParams({iss:canvas.origin,login_hint:storageTarget?'storage':'cookie',target_link_uri:target,
        ...(storageTarget?{lti_storage_target:'post_message_forwarding'}:{})});
      return html(res,`<!doctype html><iframe name="post_message_forwarding" src="/storage"></iframe><iframe name="evil" src="${evil.origin}"></iframe><iframe name="tool" id="tool"></iframe><script>addEventListener('message',e=>{if(e.origin===${JSON.stringify(canvas.origin)}&&e.source===frames['post_message_forwarding']&&e.data.fixture)frames['tool'].postMessage(e.data.fixture,${JSON.stringify(connectorOrigin)});});addEventListener('load',()=>document.getElementById('tool').src=${JSON.stringify(login)},{once:true});</script>`);
    }
    res.writeHead(404);res.end();
  })().catch(()=>{res.writeHead(500);res.end();});});
  const completion=new Promise(resolve=>{finish=resolve;});
  await writeFile(metadataPath,JSON.stringify({canvasOrigin:canvas.origin,connectorOrigin,registrationId,base,cap}));
  console.log('Owned LTI browser fixture ready; metadata stored outside repository');
  await completion;
} finally {
  await Promise.allSettled([canvas.close(),connector.close(),evil.close()]);
  await unlink(metadataPath).catch(()=>{});
}
