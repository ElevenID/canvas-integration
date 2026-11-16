// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomUUID} from 'node:crypto';
import {createCaptureScheduler,preflightCaptureScheduler} from '../src/capture-scheduler.mjs';
const container=process.argv[2];assert.match(container??'',/^canvas-capture-schedule-[a-f0-9]{32}$/);
const run=promisify(execFile),quote=value=>value===null?'NULL':typeof value==='number'||typeof value==='boolean'?String(value):"'"+String(value).replaceAll("'","''")+"'";
async function sql(statement,role=false) {
 const {stdout}=await run('docker',['exec',container,'psql','-X','-q','-A','-t','-U','postgres','-v','ON_ERROR_STOP=1','-c',
  (role?'SET ROLE capture_schedule_runtime; ':'')+statement]);return stdout.trim();
}
let loseReply=false,queries=0;
const pool={async query(statement,values=[]){
 queries++;
 const bound=statement.replace(/\$(\d+)/g,(_,index)=>quote(values[Number(index)-1]));
 const output=await sql(`SELECT row_to_json(q) FROM (${bound}) q;`,true);
 const rows=output.split('\n').filter(Boolean).map(line=>JSON.parse(line));
 if(loseReply&&statement.includes('tick_rest_capture_schedule')){loseReply=false;throw Error('synthetic lost commit reply');}
 return {rows};
}};
await preflightCaptureScheduler(pool);
await sql(`INSERT INTO canvas_connector.rest_capture_routes(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
 VALUES('schedule-org','node-route','producer','platform','node-binding',1,'{"factType":"canvas.course_completion","courseId":"17","userId":"29"}',ARRAY['completed'],'as_of_read',true);`);
const schedule={organizationId:'schedule-org',producerRef:'producer',routeId:'node-route',configurationId:randomUUID(),expectedRevision:0,routeVersion:1,intervalMs:1000,enabled:true};
const scheduler=createCaptureScheduler({pool,schedule});loseReply=true;
const before=queries;await assert.rejects(scheduler.runOnce(),{message:'connector_capture_scheduler_unavailable'});assert.equal(queries,before+1);
const recovered=await scheduler.runOnce();assert.equal(recovered.configuration.configurationId,schedule.configurationId);assert.equal(recovered.current,true);
assert.equal(recovered.capture.ordinal,1);assert.equal(recovered.enqueued,false);
assert.equal(await sql("SELECT count(*) FROM canvas_connector.rest_capture_jobs WHERE route_id='node-route';"),'1');
assert.deepEqual((await scheduler.runOnce()).capture,recovered.capture);
assert.ok(Object.isFrozen(recovered.capture));
for(const [change,restore] of [
 ['GRANT CREATE ON SCHEMA canvas_connector TO capture_schedule_runtime','REVOKE CREATE ON SCHEMA canvas_connector FROM capture_schedule_runtime'],
 ['ALTER TABLE canvas_connector.rest_schedule_captures DISABLE TRIGGER rest_schedule_capture_immutable','ALTER TABLE canvas_connector.rest_schedule_captures ENABLE TRIGGER rest_schedule_capture_immutable'],
 ['ALTER FUNCTION canvas_connector.guard_rest_schedule_head() SECURITY DEFINER','ALTER FUNCTION canvas_connector.guard_rest_schedule_head() SECURITY INVOKER'],
]) {
 await sql(change);try{await assert.rejects(preflightCaptureScheduler(pool),{message:'connector_capture_scheduler_unavailable'});}finally{await sql(restore);}
}
await sql(`CREATE ROLE schedule_history_writer;GRANT UPDATE(receipt) ON canvas_connector.rest_schedule_captures TO schedule_history_writer;
 GRANT schedule_history_writer TO capture_schedule_runtime WITH INHERIT FALSE;`);
try{await assert.rejects(preflightCaptureScheduler(pool),{message:'connector_capture_scheduler_unavailable'});}
finally{await sql('REVOKE schedule_history_writer FROM capture_schedule_runtime;DROP OWNED BY schedule_history_writer;DROP ROLE schedule_history_writer;');}
await preflightCaptureScheduler(pool);
console.log('Production scheduler decoder/parameterized SQL and original lost-commit receipt recovery passed against PG16; startup rejects unsafe grants,disabled guards,security-definer and NOINHERIT history writers');
