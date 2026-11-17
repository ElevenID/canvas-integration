// SPDX-License-Identifier: AGPL-3.0-only
// Server-only orchestration. A receipt proves history; only inspect proves current state.
const fail=()=>{throw Error('lti_association_unavailable');};
function proofSnapshot(value) {
 if(value===null||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail();
 const d=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(d);
 if(keys.length!==2||keys.some(k=>!['stateHash','browserHash'].includes(k)||!Object.hasOwn(d[k],'value')
  ||!d[k].enumerable||typeof d[k].value!=='string'||!/^[a-f0-9]{64}$/.test(d[k].value)))fail();
 return Object.freeze(Object.fromEntries(keys.map(k=>[k,d[k].value])));
}
function same(a,b) {
 return a!==null&&b!==null&&a.challengeId===b.challengeId&&a.bindingId===b.bindingId&&a.code===b.code
  &&JSON.stringify(a.body)===JSON.stringify(b.body);
}
function receipt(value,a) {
 if(!value||value.operation_id!==a.body.operation_id||value.challenge_id!==a.challengeId
  ||value.action!=='create'||value.revision!==1||value.phase!=='pending')fail();
}
export function createLtiAssociationLifecycle({store,gateway}={}) {
 if(typeof globalThis.window!=='undefined'||typeof store?.claimDispatch!=='function'||typeof store?.current!=='function'
  ||typeof gateway?.execute!=='function')fail();
 async function run(value,start) {
  const proof=proofSnapshot(value);
  try {
   let a,dispatchGranted=false;
   if(start){const claim=await store.claimDispatch(proof);a=claim?.attempt;dispatchGranted=claim?.dispatchGranted;if(typeof dispatchGranted!=='boolean')fail();}
   else a=await store.current(proof);
   if(!a||!same(a,await store.current(proof)))fail();
   const scope={challengeId:a.challengeId,bindingId:a.bindingId};
   if(dispatchGranted)receipt(await gateway.execute({...scope,action:'create',body:a.body}),a);
   else {
    const history=await gateway.execute({...scope,action:'receipt',body:{operation_id:a.body.operation_id},
     expectedReceipt:{action:'create',revision:1}});
    if(history?.kind!=='receipt')fail();receipt(history.receipt,a);
   }
   // No write retries, even when a dispatch marker committed but dispatch did not.
   const status=await gateway.execute({...scope,action:'inspect',body:{}});
   if(status?.kind!=='current'||!same(a,await store.current(proof)))fail();
   const r=status.record;
   if(!r||r.challenge_id!==a.challengeId||r.binding_id!==a.bindingId||r.expires_at_ms!==a.body.expires_at_ms
    ||typeof r.current!=='boolean'||typeof r.expired!=='boolean'
    ||!['pending','confirmed','denied','abandoned','expired'].includes(r.phase))fail();
   if(r.phase==='pending') {
    if(!r.current||r.expired||r.revision!==1||r.expires_at_ms<=Date.now())fail();
    return Object.freeze({challengeId:a.challengeId,phase:'pending',code:a.code,expiresAtMs:r.expires_at_ms});
   }
   if(r.revision!==2||r.phase==='confirmed'&&!r.current)fail();
   return Object.freeze({challengeId:a.challengeId,phase:r.phase});
  }catch{fail();}
 }
 return Object.freeze({start:value=>run(value,true),recover:value=>run(value,false)});
}
