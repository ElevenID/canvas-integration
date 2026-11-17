// SPDX-License-Identifier: AGPL-3.0-only
import { request } from 'node:https';
import { canvasOrigin, approvedPrivateAddresses, resolveAddress, pinnedLookup } from './canvas-rest-network.mjs';
import { exactRecord, canvasId } from './canvas-rest-contract.mjs';
import { parsePrivateJson } from './private-json.mjs';
import { prepareLtiToolKey, signLtiClientAssertion } from './lti-tool-assertion.mjs';

export const ltiReadScopes=Object.freeze({
  results:'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
  lineitems:'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',
  memberships:'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly',
});
export class CanvasLtiServiceError extends Error {
  constructor(code,status) {super('canvas_lti_service_'+code);this.name='CanvasLtiServiceError';this.code=code;if(status!==undefined)this.status=status;}
}
const fail=(code='unavailable',status)=>{throw new CanvasLtiServiceError(code,status);};
const visible=value=>typeof value==='string'&&/^[\x21-\x7e]{1,255}$/.test(value);
const bearer=value=>typeof value==='string'&&/^[A-Za-z0-9._~+/-]{16,16384}={0,2}$/.test(value);
function scopes(value) {
  if(!Array.isArray(value)||!value.length||value.length>3||new Set(value).size!==value.length||value.some(item=>!Object.values(ltiReadScopes).includes(item)))fail('invalid_scope');
  return [...value].sort();
}
function object(value) {if(value===null||typeof value!=='object'||Array.isArray(value))fail('invalid_payload');return value;}
function identifier(value) {if(!visible(value))fail('invalid_resource');return value;}

export function createCanvasLtiServiceClient(configuration) {
  let origin,toolOrigin,key,allowed,ca,timeoutMs,maxBytes,maxPages;
  try {
    if(typeof globalThis.window!=='undefined')fail('server_only');
    exactRecord(configuration,['canvasOrigin','toolOrigin','clientId','toolKey','ca','allowedPrivateAddresses','timeoutMs','maxResponseBytes','maxPages','beforeTokenSend'],'invalid_configuration');
    if(configuration.beforeTokenSend!==undefined&&typeof configuration.beforeTokenSend!=='function')fail('invalid_configuration');
    origin=canvasOrigin(configuration.canvasOrigin);toolOrigin=new URL(configuration.toolOrigin);
    if(typeof configuration.toolOrigin!=='string'||toolOrigin.protocol!=='https:'||toolOrigin.origin!==configuration.toolOrigin||!visible(configuration.clientId))fail('invalid_configuration');
    toolOrigin=toolOrigin.origin;key=prepareLtiToolKey(configuration.toolKey);allowed=approvedPrivateAddresses(configuration.allowedPrivateAddresses);
    ca=configuration.ca;timeoutMs=configuration.timeoutMs??15000;maxBytes=configuration.maxResponseBytes??1048576;maxPages=configuration.maxPages??8;
    if(!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>120000||!Number.isInteger(maxBytes)||maxBytes<256||maxBytes>8388608
      ||!Number.isInteger(maxPages)||maxPages<1||maxPages>16||(ca!==undefined&&(typeof ca!=='string'||ca.length>65536||!ca.includes('-----BEGIN CERTIFICATE-----')||/PRIVATE KEY/.test(ca))))fail('invalid_configuration');
  }catch{fail('invalid_configuration');}
  const clientId=configuration.clientId,beforeTokenSend=configuration.beforeTokenSend;
  async function operation(work,validUntil) {
    const expired=()=>validUntil!==undefined && Date.now()>=validUntil;
    if(expired())fail('expired_credential');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),
      Math.max(1,Math.min(timeoutMs,validUntil===undefined?timeoutMs:validUntil-Date.now())));
    try {
      const pinned=await resolveAddress(origin,allowed,controller.signal);let used=0;
      const send=(path,{token,body,accept='application/json'}={})=>new Promise((resolve,reject)=>{
        let req,settled=false;
        const finish=(error,value)=>{if(settled)return;settled=true;if(error){req?.destroy();reject(error);}else resolve(value);};
        try {
          // DNS and preceding pages may consume the remaining credential life.
          // Fence every actual send against the original immutable deadline.
          if(expired())fail('expired_credential');
          const url=new URL(path,origin);if(url.origin!==origin||url.username||url.password||url.hash)fail('invalid_resource');
          req=request(url,{method:body===undefined?'GET':'POST',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,
            family:pinned.family,autoSelectFamily:false,lookup:pinnedLookup(url.hostname.replace(/^\[|\]$/g,''),pinned),signal:controller.signal,
            ...(ca===undefined?{}:{ca}),headers:{Accept:accept,'Accept-Encoding':'identity',
              ...(token===undefined?{}:{Authorization:'Bearer '+token}),...(body===undefined?{}:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)})}},response=>{
            response.on('error',()=>finish(new CanvasLtiServiceError('transport_error')));response.on('aborted',()=>finish(new CanvasLtiServiceError('transport_error')));
            const status=response.statusCode;
            if(status!==200)return finish(new CanvasLtiServiceError(status>=300&&status<400?'redirect_denied':'unexpected_status',status));
            const count=name=>response.rawHeaders.filter((_,index)=>index%2===0&&response.rawHeaders[index].toLowerCase()===name).length;
            const type=String(response.headers['content-type']??'').toLowerCase().split(';').map(item=>item.trim());
            if(count('content-type')!==1||count('content-encoding')>1||count('content-length')>1||count('link')>1
              ||![accept,'application/json'].includes(type[0])||type.slice(1).some(item=>!/^charset="?utf-8"?$/.test(item))
              ||!['','identity'].includes(String(response.headers['content-encoding']??'')))return finish(new CanvasLtiServiceError('invalid_response'));
            const length=response.headers['content-length'];if(length!==undefined&&(!/^[0-9]{1,8}$/.test(length)||Number(length)>maxBytes-used))return finish(new CanvasLtiServiceError('response_budget'));
            const chunks=[];
            response.on('data',chunk=>{used+=chunk.length;if(used>maxBytes)return finish(new CanvasLtiServiceError('response_budget'));if(!settled)chunks.push(chunk);});
            response.on('end',()=>{
              if(settled)return;
              try {const data=parsePrivateJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));finish(null,{data,link:response.headers.link});}
              catch{finish(new CanvasLtiServiceError('invalid_payload'));}
            });
          });
          req.on('error',()=>finish(new CanvasLtiServiceError(expired()?'expired_credential':controller.signal.aborted?'timeout':'transport_error')));
          // Do not queue a credential-bearing HTTP message until TLS identity
          // verification completes. A stalled handshake must not flush a body
          // or Authorization header after its original credential expires.
          req.once('socket',socket=>socket.once('secureConnect',()=>{
            void(async()=>{
              if(settled)return;
              if(expired())fail('expired_credential');
              if(controller.signal.aborted)fail('timeout');
              if(socket.authorized!==true)fail('transport_error');
              if(body!==undefined&&beforeTokenSend!==undefined&&await beforeTokenSend(Object.freeze({signal:controller.signal}))!==true)fail('dispatch_denied');
              // The durable permit query may itself cross expiry or timeout.
              if(settled)return;
              if(expired())fail('expired_credential');
              if(controller.signal.aborted)fail('timeout');
              req.end(body);
            })().catch(error=>finish(error instanceof CanvasLtiServiceError?error:new CanvasLtiServiceError('dispatch_denied')));
          }));
        }catch(error){finish(error instanceof CanvasLtiServiceError?error:new CanvasLtiServiceError('unavailable'));}
      });
      return await work(send);
    }catch(error){if(error instanceof CanvasLtiServiceError)throw error;fail(controller.signal.aborted?'timeout':'unavailable');}
    finally{clearTimeout(timer);}
  }
  function authorization(value,required) {
    exactRecord(value,['accessToken','scopes','expiresAtMs'],'invalid_token');
    if(Object.keys(value).length!==3||!bearer(value.accessToken)||!scopes(value.scopes).includes(required)
      ||!Number.isSafeInteger(value.expiresAtMs)||value.expiresAtMs<=Date.now())fail('invalid_token');
    return value.accessToken;
  }
  function next(link,current,baseline,seen) {
    if(link===undefined)return null;
    if(typeof link!=='string'||link.length>8192)fail('invalid_pagination');
    let target=null;const relations=new Set();
    for(const part of link.split(/,\s*(?=<)/)) {
      const match=/^<([^<>\s]+)>;\s*rel="(current|next|first|last|prev)"$/.exec(part.trim());
      if(!match||relations.has(match[2]))fail('invalid_pagination');relations.add(match[2]);
      if(match[2]!=='next')continue;
      const url=new URL(match[1],current);
      if(url.origin!==origin||url.pathname!==baseline.pathname||url.username||url.password||url.hash||url.href.length>4096)fail('invalid_pagination');
      for(const [name,value] of baseline.searchParams)if(url.searchParams.getAll(name).length!==1||url.searchParams.get(name)!==value)fail('invalid_pagination');
      if([...url.searchParams.keys()].some(name=>name!=='page'&&!baseline.searchParams.has(name))||url.searchParams.getAll('page').length!==1
        ||!/^[A-Za-z0-9._~:-]{1,256}$/.test(url.searchParams.get('page'))||seen.has(url.href))fail('invalid_pagination');
      target=url;
    }
    return target;
  }
  function sameUrl(value,expected) {if(typeof value!=='string'||value!==expected)fail('resource_mismatch');}
  return Object.freeze({
    publicJwk:key.publicJwk,
    async requestAccessToken(input) {
      try {
        exactRecord(input,['requestId','issuedAt','expiresAt','scopes'],'invalid_token_request');
        const requested=scopes(input.scopes),now=Math.floor(Date.now()/1000);
        if(!Number.isSafeInteger(input.issuedAt)||!Number.isSafeInteger(input.expiresAt)||input.issuedAt>now+5||input.issuedAt<now-120||input.expiresAt<=now)fail('expired_assertion');
        const assertion=signLtiClientAssertion(key,{toolOrigin,clientId,tokenEndpoint:origin+'/login/oauth2/token',requestId:input.requestId,issuedAt:input.issuedAt,expiresAt:input.expiresAt});
        const body=new URLSearchParams({grant_type:'client_credentials',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,scope:requested.join(' ')}).toString();
        return await operation(async send=>{
          const {data,link}=await send('/login/oauth2/token',{body});object(data);
          if(link!==undefined||!bearer(data.access_token)||typeof data.token_type!=='string'||data.token_type.toLowerCase()!=='bearer'
            ||!Number.isSafeInteger(data.expires_in)||data.expires_in<1||data.expires_in>86400||typeof data.scope!=='string')fail('invalid_token_response');
          const granted=scopes(data.scope.split(' '));if(granted.some(scope=>!requested.includes(scope)))fail('invalid_token_response');
          return Object.freeze({accessToken:data.access_token,expiresIn:data.expires_in,scopes:Object.freeze(granted)});
        },input.expiresAt*1000);
      }catch(error){if(error instanceof CanvasLtiServiceError)throw error;fail('invalid_token_request');}
    },
    async readLineItem(input) {
      exactRecord(input,['token','courseId','lineItemId'],'invalid_resource');
      const {token,courseId,lineItemId}=input,expiresAtMs=token?.expiresAtMs;
      const access=authorization(token,ltiReadScopes.lineitems),path=`/api/lti/courses/${canvasId(courseId)}/line_items/${canvasId(lineItemId)}`;
      return operation(async send=>{
        const {data,link}=await send(path,{token:access,accept:'application/vnd.ims.lis.v2.lineitem+json'});object(data);sameUrl(data.id,origin+path);
        if(link!==undefined||typeof data.scoreMaximum!=='number'||!Number.isFinite(data.scoreMaximum)||data.scoreMaximum<0
          ||(data.resourceLinkId!==undefined&&!visible(data.resourceLinkId))||expiresAtMs<=Date.now())fail('invalid_payload');
        return Object.freeze({id:data.id,scoreMaximum:data.scoreMaximum,resourceLinkId:data.resourceLinkId??null});
      },expiresAtMs);
    },
    async readResults(input) {
      exactRecord(input,['token','courseId','lineItemId','userId'],'invalid_resource');
      const {token,courseId,lineItemId,userId}=input,expiresAtMs=token?.expiresAtMs;
      const access=authorization(token,ltiReadScopes.results),user=identifier(userId),lineitem=`${origin}/api/lti/courses/${canvasId(courseId)}/line_items/${canvasId(lineItemId)}`;
      const initial=new URL(lineitem+'/results');initial.searchParams.set('user_id',user);initial.searchParams.set('limit','100');
      return operation(async send=>{
        let url=initial,found=null;const seen=new Set();
        for(let page=0;url!==null;page++) {
          if(page>=maxPages||seen.has(url.href))fail('response_budget');seen.add(url.href);
          const {data,link}=await send(url.href,{token:access,accept:'application/vnd.ims.lis.v2.resultcontainer+json'});
          if(!Array.isArray(data)||data.length>100)fail('invalid_payload');
          for(const row of data) {
            object(row);const member=typeof row.userId==='number'&&Number.isSafeInteger(row.userId)&&row.userId>0?String(row.userId):row.userId;
            if(member!==user||found!==null)fail('resource_mismatch');sameUrl(row.scoreOf,lineitem);
            if(typeof row.id!=='string'||!row.id.startsWith(lineitem+'/results/')||!/^\d+$/.test(row.id.slice((lineitem+'/results/').length)))fail('resource_mismatch');
            const score=row.resultScore??null,maximum=row.resultMaximum===undefined?1:row.resultMaximum;
            if((score!==null&&(typeof score!=='number'||!Number.isFinite(score)))||typeof maximum!=='number'||!Number.isFinite(maximum)||maximum<0)fail('invalid_payload');
            found=Object.freeze({userId:user,resultScore:score,resultMaximum:maximum,lineItemUrl:lineitem});
          }
          url=next(link,url,initial,seen);
        }
        if(expiresAtMs<=Date.now())fail('expired_token');return found;
      },expiresAtMs);
    },
    async readMembership(input) {
      exactRecord(input,['token','courseId','userId','contextId','resourceLinkId'],'invalid_resource');
      const {token,courseId,userId,contextId,resourceLinkId}=input,expiresAtMs=token?.expiresAtMs;
      const access=authorization(token,ltiReadScopes.memberships),user=identifier(userId),context=identifier(contextId),resource=identifier(resourceLinkId);
      const initial=new URL(`/api/lti/courses/${canvasId(courseId)}/names_and_roles`,origin);initial.searchParams.set('rlid',resource);initial.searchParams.set('limit','100');
      return operation(async send=>{
        let url=initial,found=null;const seen=new Set();
        for(let page=0;url!==null;page++) {
          if(page>=maxPages||seen.has(url.href))fail('response_budget');seen.add(url.href);
          const {data,link}=await send(url.href,{token:access,accept:'application/vnd.ims.lti-nrps.v2.membershipcontainer+json'});object(data);object(data.context);
          if(data.context.id!==context||typeof data.id!=='string')fail('resource_mismatch');
          const returned=new URL(data.id);if(returned.origin!==origin||returned.pathname!==initial.pathname||returned.username||returned.password||returned.hash)fail('resource_mismatch');
          if(!Array.isArray(data.members)||data.members.length>100)fail('invalid_payload');
          for(const row of data.members) {
            object(row);if(!visible(row.user_id)||!['Active','Inactive','Deleted'].includes(row.status)||!Array.isArray(row.roles)||row.roles.length>64||new Set(row.roles).size!==row.roles.length)fail('invalid_payload');
            for(const role of row.roles){if(typeof role!=='string'||role.length>2048)fail('invalid_payload');const parsed=new URL(role);if(!['http:','https:','urn:'].includes(parsed.protocol)||parsed.username||parsed.password)fail('invalid_payload');}
            if(row.user_id!==user)continue;if(found!==null)fail('resource_mismatch');
            found=Object.freeze({userId:user,contextId:context,status:row.status,roles:Object.freeze([...row.roles].sort())});
          }
          url=next(link,url,initial,seen);
        }
        if(expiresAtMs<=Date.now())fail('expired_token');return found;
      },expiresAtMs);
    },
  });
}
