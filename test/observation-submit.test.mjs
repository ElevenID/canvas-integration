// SPDX-License-Identifier: AGPL-3.0-only
import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {httpsFixture,json} from './support/canvas-https-fixture.mjs';
import {encodeExternalObservation,createObservationSubmitter,ObservationSubmissionError} from '../src/observation-submit.mjs';
const KEY='synthetic_gateway_api_key_00000000000001';
const envelope=()=>({binding_id:'binding-one',binding_revision:3,observation_id:'observation-one',sequence:7,
  observed_at_ms:1794804000000,effective_at_ms:1794803999000,claims:{score:null,completed:false,provider_state:'unsubmitted'}});
let fixture;let requests=[];
before(async()=>{fixture=await httpsFixture();});
after(async()=>{await fixture.close();});
const client=overrides=>createObservationSubmitter({gatewayOrigin:fixture.origin,ca:fixture.ca,
  apiKeyProvider:{getApiKey:async()=>KEY},...overrides});
function handler(reply) {
  requests=[];fixture.setHandler(async(req,res)=>{
    const chunks=[];for await(const chunk of req)chunks.push(chunk);
    requests.push({url:req.url,method:req.method,headers:{...req.headers},body:Buffer.concat(chunks).toString('utf8')});
    reply(req,res);
  });
}
const rejected=(code,status)=>error=>{
  assert.ok(error instanceof ObservationSubmissionError);assert.equal(error.code,code);
  assert.equal(error.status,status);assert.equal(error.cause,undefined);assert.equal(error.message.includes(KEY),false);return true;
};
test('Encoder emits deterministic bounded primitive bytes without authority fields',()=>{
  const body=encodeExternalObservation(envelope());
  assert.equal(body,'{"binding_id":"binding-one","binding_revision":3,"observation_id":"observation-one","sequence":7,"observed_at_ms":1794804000000,"effective_at_ms":1794803999000,"claims":{"completed":false,"provider_state":"unsubmitted","score":null}}');
  assert.equal(encodeExternalObservation({...envelope(),claims:{completed:false,score:null,provider_state:'unsubmitted'}}),body);
  assert.equal(typeof body,'string');
});
for(const [name,change] of [
 ['extra-tenant',v=>({...v,organization_id:'forged'})],['extra-subject',v=>({...v,subject_id:'forged'})],
 ['bad-binding',v=>({...v,binding_id:'../binding'})],['fractional-revision',v=>({...v,binding_revision:1.5})],
 ['unsafe-sequence',v=>({...v,sequence:Number.MAX_SAFE_INTEGER+1})],['zero-time',v=>({...v,effective_at_ms:0})],
 ['future-effective',v=>({...v,effective_at_ms:v.observed_at_ms+1})],['empty-claims',v=>({...v,claims:{}})],
 ['array-claim',v=>({...v,claims:{completed:[]}})],['nested-claim',v=>({...v,claims:{completed:{value:true}}})],
 ['nonfinite',v=>({...v,claims:{score:NaN}})],['unsafe-number',v=>({...v,claims:{score:1e40}})],
 ['long-utf8',v=>({...v,claims:{label:'\u00e9'.repeat(257)}})],['control',v=>({...v,claims:{label:'bad\u0085'}})],
 ['surrogate',v=>({...v,claims:{label:'\ud800'}})],['reserved',v=>({...v,claims:{VeRiFiEd:true}})],
 ['too-many',v=>({...v,claims:Object.fromEntries(Array.from({length:33},(_,i)=>['field'+i,true]))})],
])test('Encoder rejects '+name,()=>assert.throws(()=>encodeExternalObservation(change(envelope())),/invalid_observation/));
test('Encoder rejects accessors without invoking them',()=>{
 let called=false;const value=envelope();Object.defineProperty(value,'claims',{enumerable:true,get(){called=true;return{};}});
 assert.throws(()=>encodeExternalObservation(value),/invalid_observation/);assert.equal(called,false);
});
test('Only canonical stored bytes can be submitted; no duplicate-name ambiguity or timestamp recoding',async()=>{
 let credentials=0;const submitter=client({apiKeyProvider:{getApiKey:async()=>{credentials++;return KEY;}}});
 const valid=encodeExternalObservation(envelope());
 for(const body of [' '+valid,valid.replace('"sequence":7','"sequence":7,"sequence":7'),valid.replace('"sequence":7','"sequence":7.0'),'{',JSON.stringify({...envelope(),claims:{completed:true,access_token:KEY}})]) {
  await assert.rejects(()=>submitter.submit(body),rejected('invalid_observation'));}
 assert.equal(credentials,0);
});
test('Exact public POST bytes and idempotency; tenant only from fresh API key, no automatic retry/cache',async()=>{
 let credentials=0;handler((_req,res)=>json(res,{receipt_id:'receipt-one',replayed:requests.length>1}));
 const submitter=client({apiKeyProvider:{getApiKey:async()=>{credentials++;return KEY;}}});
 const body=encodeExternalObservation(envelope());
 assert.deepEqual(await submitter.submit(body),{receipt_id:'receipt-one',replayed:false});
 assert.deepEqual(await submitter.submit(body),{receipt_id:'receipt-one',replayed:true});
 assert.equal(credentials,2);assert.equal(requests.length,2);
 for(const request of requests) {
  assert.equal(request.url,'/v1/evidence/observations');assert.equal(request.method,'POST');assert.equal(request.body,body);
  assert.equal(request.headers['x-api-key'],KEY);assert.equal(request.headers['idempotency-key'],'observation-one');
  assert.equal(request.headers['x-organization-id'],undefined);assert.equal(request.headers['x-user-id'],undefined);
  assert.equal(request.headers.authorization,undefined);assert.equal(request.headers['content-length'],String(Buffer.byteLength(body)));
 }
});
test('Receipt field order and JSON whitespace are accepted without widening shape',async()=>{
 handler((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end('{ "replayed" : true, "receipt_id" : "receipt_two" }');});
 assert.deepEqual(await client().submit(encodeExternalObservation(envelope())),{receipt_id:'receipt_two',replayed:true});
});
for(const status of [400,401,403,404,409,413,429,500,503,302])test('HTTP '+status+' is redacted and never retried or followed',async()=>{
 handler((_req,res)=>{res.writeHead(status,{'Content-Type':'application/json',Location:fixture.origin+'/wrong'});res.end(KEY);});
 await assert.rejects(()=>client().submit(encodeExternalObservation(envelope())),rejected(status>=400&&status<500?'submission_rejected':'submission_outcome_unknown',status));
 assert.equal(requests.length,1);
});
for(const body of ['{}','{"receipt_id":"one","receipt_id":"two","replayed":false}',
 '{"receipt_id":"one","replayed":false,"verified":true}','{"receipt_id":"one","replayed":"false"}',
 '{"receipt_id":"one","replayed":false}trailing','{"receipt_id":"a/b","replayed":false}'])test('Malformed receipt is uncertain: '+body,async()=>{
 handler((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(body);});
 await assert.rejects(()=>client().submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
});
test('Malformed UTF-8, oversized, compressed and wrong-format receipts are uncertain',async()=>{
 for(const [type,encoding,bytes] of [['application/json','identity',Buffer.from([0xff])],['application/json','identity','x'.repeat(2049)],
  ['application/json','gzip','{}'],['text/html','identity','{}']]) {
  handler((_req,res)=>{res.writeHead(200,{'Content-Type':type,'Content-Encoding':encoding});res.end(bytes);});
  await assert.rejects(()=>client().submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
 }
});
test('TLS verification fails closed',async()=>{
 handler((_req,res)=>json(res,{receipt_id:'one',replayed:false}));
 await assert.rejects(()=>client({ca:undefined}).submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
 assert.equal(requests.length,0);
});
test('Lost response never becomes a receipt or a negative observation',async()=>{
 handler((req,_res)=>{req.socket.destroy();});
 await assert.rejects(()=>client().submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
 assert.equal(requests.length,1);
});
test('Whole-operation deadline includes credential lookup; late keys start no request',async()=>{
 let aborted=false;handler((_req,res)=>json(res,{receipt_id:'one',replayed:false}));
 const submitter=client({timeoutMs:75,apiKeyProvider:{getApiKey:({signal})=>new Promise(resolve=>{
  signal.addEventListener('abort',()=>{aborted=true;},{once:true});setTimeout(()=>resolve(KEY),150);
 })}});
 await assert.rejects(()=>submitter.submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
 await new Promise(resolve=>setTimeout(resolve,180));assert.equal(aborted,true);assert.equal(requests.length,0);
});
test('Headers plus slow response cannot reset deadline',async()=>{
 handler((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.write('{');});
 await assert.rejects(()=>client({timeoutMs:100}).submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
});
test('Provider errors and invalid keys never expose content or open network',async()=>{
 handler((_req,res)=>json(res,{receipt_id:'one',replayed:false}));
 for(const getApiKey of [async()=>{throw Error(KEY);},async()=>{throw new ObservationSubmissionError(KEY);},async()=>{throw new ObservationSubmissionError('submission_rejected',403);},async()=>'',async()=>KEY+'\r\nInjected: secret'])
  await assert.rejects(()=>client({apiKeyProvider:{getApiKey}}).submit(encodeExternalObservation(envelope())),rejected('submission_outcome_unknown'));
 assert.equal(requests.length,0);
});
for(const changes of [{gatewayOrigin:'http://gateway.example'},{gatewayOrigin:'https://issuance.internal'},
 {gatewayOrigin:'https://gateway.example/path'},{gatewayOrigin:'https://gateway.example#x'},
 {organizationId:'forged'},{apiKey:KEY},{apiKeyProvider:null},{timeoutMs:0},{ca:'-----BEGIN CERTIFICATE----- PRIVATE KEY'}])
 test('Submission configuration rejects alternate routes or authority '+JSON.stringify(changes),()=>{
  assert.throws(()=>client(changes),/invalid_submission_configuration/);
 });
test('Observation client is denied under browser export condition',async()=>{
 await assert.rejects(promisify(execFile)(process.execPath,['--conditions=browser','--input-type=module','-e',
  "await import('@elevenid/canvas-integration/observations')"]),error=>{assert.match(error.stderr,/server-only/);return true;});
});
