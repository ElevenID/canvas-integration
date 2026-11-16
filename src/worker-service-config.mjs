// SPDX-License-Identifier: AGPL-3.0-only
import {resolve,isAbsolute} from 'node:path';
import {parsePrivateJson} from './private-json.mjs';
import {createPrivateTextFile} from './private-file.mjs';
import {createConnectorDatabasePasswordFile,createConnectorOpenBaoTokenFile,createConnectorGatewayApiKeyFile} from './file-credentials.mjs';
import {prepareCaptureSchedule} from './capture-scheduler.mjs';
const unavailable=()=>new Error('connector_worker_configuration_unavailable');
const id=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
function fields(value,allowed) {
  if(value===null || typeof value!=='object' || Array.isArray(value) || Object.keys(value).some(key=>!allowed.includes(key))) throw unavailable();
}
export async function loadConnectorWorkerConfiguration(options={}) {
  try {
    fields(options,['path','signal','timeoutMs']);
    const {path,signal,timeoutMs=1000}=options;
    const read=filename=>createPrivateTextFile({path:filename,timeoutMs,maxBytes:65536}).readText({signal});
    const configuration=parsePrivateJson(await read(path));
    fields(configuration,['schemaVersion','database','keyCustody','canvas','gateway','refreshTargets','producers','pollIntervalMs','captureSchedules']);
    if(configuration.schemaVersion!==1) throw unavailable();
    const {database,keyCustody,canvas,gateway,refreshTargets,producers,pollIntervalMs}=configuration;
    fields(database,['host','port','database','user','caFile','passwordFile','maxConnections','connectTimeoutMs','queryTimeoutMs']);
    fields(keyCustody,['openbaoOrigin','mount','keyPath','keyNamespace','caFile','tokenFile','timeoutMs']);
    fields(canvas,['caFile','allowedPrivateAddresses','timeoutMs','maxResponseBytes']);
    fields(gateway,['gatewayOrigin','caFile','timeoutMs']);
    if(!Array.isArray(refreshTargets)||refreshTargets.length>32||!Array.isArray(producers)||producers.length>32) throw unavailable();
    for(const target of refreshTargets) {
      fields(target,['organizationId','platformId']);if(!id(target.organizationId)||!id(target.platformId)) throw unavailable();
    }
    for(const slot of producers) {
      fields(slot,['organizationId','producerRef','apiKeyFile']);
      if(!id(slot.organizationId)||!id(slot.producerRef)) throw unavailable();
    }
    const schedules=configuration.captureSchedules===undefined?[]:configuration.captureSchedules;
    if(!Array.isArray(schedules)||schedules.length>32)throw unavailable();
    const captureSchedules=schedules.map(value=>prepareCaptureSchedule(value));
    if(new Set(captureSchedules.map(v=>v.organizationId+':'+v.routeId)).size!==captureSchedules.length
     || captureSchedules.some(value=>!producers.some(slot=>slot.organizationId===value.organizationId&&slot.producerRef===value.producerRef)))throw unavailable();
    const files=[{path,scope:'configuration'}, {path:database.passwordFile,scope:'database'},
      {path:keyCustody.tokenFile,scope:'openbao'},...producers.map(slot=>({path:slot.apiKeyFile,scope:'gateway:'+slot.organizationId}))];
    const paths=new Map(),inodes=new Map(),identities=[];
    for(const [index,file] of files.entries()) {
      if(typeof file.path!=='string'||!isAbsolute(file.path)) throw unavailable();
      const identity=await createPrivateTextFile({path:resolve(file.path),timeoutMs,maxBytes:index===0?65536:4098}).inspect({signal});
      // Only credential slots in the same Gateway organization may share a file.
      // Configuration/database/OpenBao and other tenants never share custody.
      for(const [map,key] of [[paths,identity.path],[inodes,`${identity.dev}:${identity.ino}`]]) {
        const existing=map.get(key);
        if(existing!==undefined && (!file.scope.startsWith('gateway:')||existing!==file.scope)) throw unavailable();
        map.set(key,file.scope);
      }
      identities.push(identity);
    }
    const {passwordFile,caFile:databaseCa,...databaseOptions}=database;
    const {tokenFile,caFile:keyCa,...keyOptions}=keyCustody;
    const {caFile:canvasCa,...canvasOptions}=canvas;
    const {caFile:gatewayCa,...gatewayOptions}=gateway;
    return {
      database:{...databaseOptions,ca:await read(databaseCa),credentialProvider:createConnectorDatabasePasswordFile({path:identities[1].path,timeoutMs})},
      keyCustody:{...keyOptions,...(keyCa===undefined?{}:{ca:await read(keyCa)}),tokenProvider:createConnectorOpenBaoTokenFile({path:identities[2].path,timeoutMs})},
      canvas:{...canvasOptions,...(canvasCa===undefined?{}:{ca:await read(canvasCa)})},
      gateway:{...gatewayOptions,...(gatewayCa===undefined?{}:{ca:await read(gatewayCa)})},
      refreshTargets:refreshTargets.map(target=>({...target})),
      producers:producers.map((slot,index)=>({organizationId:slot.organizationId,producerRef:slot.producerRef,
        apiKeyProvider:createConnectorGatewayApiKeyFile({path:identities[index+3].path,timeoutMs})})),
      ...(pollIntervalMs===undefined?{}:{pollIntervalMs}),
      ...(configuration.captureSchedules===undefined?{}:{captureSchedules}),
    };
  } catch {throw unavailable();}
}
