#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Owned, network-isolated PostgreSQL cadence/backpressure/receipt contracts."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
IMAGE='postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'

def main():
 name='canvas-capture-schedule-'+uuid.uuid4().hex
 subprocess.run(['docker','run','--detach','--name',name,'--network','none','--label','elevenid.owner=canvas-capture-schedule-test',
  '--env','POSTGRES_PASSWORD=synthetic-only',IMAGE],check=True)
 try:
  def sql(statement,role=False):
   result=subprocess.run(['docker','exec','-i',name,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','postgres','-v','ON_ERROR_STOP=1'],
    input=('SET ROLE capture_schedule_runtime; ' if role else '')+statement,text=True,capture_output=True)
   if result.returncode:raise RuntimeError('owned schedule SQL contract failed: '+result.stderr)
   return result.stdout.strip()
  for _ in range(60):
   if subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('owned schedule PostgreSQL readiness failed')
  for migration in sorted((ROOT/'schema').glob('*.sql')):sql(migration.read_text(encoding='utf-8'))
  sql("""CREATE ROLE capture_schedule_runtime;
   GRANT USAGE ON SCHEMA canvas_connector TO capture_schedule_runtime;
   GRANT SELECT ON canvas_connector.platforms,canvas_connector.connections,canvas_connector.rest_capture_routes,
    canvas_connector.rest_capture_jobs,canvas_connector.observation_outbox,canvas_connector.rest_schedule_heads,
    canvas_connector.rest_schedule_configurations,canvas_connector.rest_schedule_captures TO capture_schedule_runtime;
   GRANT UPDATE(id) ON canvas_connector.platforms,canvas_connector.rest_capture_routes TO capture_schedule_runtime;
   GRANT UPDATE(created_at) ON canvas_connector.connections TO capture_schedule_runtime;
   GRANT INSERT ON canvas_connector.rest_schedule_heads,canvas_connector.rest_schedule_configurations,canvas_connector.rest_schedule_captures TO capture_schedule_runtime;
   GRANT UPDATE(configuration_id,revision,route_version,interval_ms,enabled,next_ordinal,next_due_at,last_capture_id,updated_at)
    ON canvas_connector.rest_schedule_heads TO capture_schedule_runtime;
   GRANT INSERT(organization_id,capture_id,producer_ref,route_id,route_version,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,available_at)
    ON canvas_connector.rest_capture_jobs TO capture_schedule_runtime;
   GRANT EXECUTE ON FUNCTION canvas_connector.tick_rest_capture_schedule(text,text,text,uuid,bigint,bigint,integer,boolean) TO capture_schedule_runtime;
   INSERT INTO canvas_connector.platforms(organization_id,id,canvas_origin,enabled) VALUES('schedule-org','platform','https://canvas.example',true);
   INSERT INTO canvas_connector.connections(organization_id,platform_id,platform_config_version,canvas_origin,client_id,client_secret_ref,access_token_ref,capabilities,scopes,status)
    VALUES('schedule-org','platform',1,'https://canvas.example','client','client-secret','access-token',ARRAY['course_completion'],ARRAY['url:GET|/api/v1/courses/:course_id/users/:user_id/progress'],'connected');
   INSERT INTO canvas_connector.rest_capture_routes(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
    VALUES('schedule-org','route','producer','platform','binding',1,'{"factType":"canvas.course_completion","courseId":"17","userId":"29"}',ARRAY['completed'],'as_of_read',true);""")
  config=str(uuid.uuid4())
  def tick(configuration=config,expected=0,version=1,cadence=1000,enabled=True,org='schedule-org',producer='producer',route='route'):
   value=sql(f"SELECT canvas_connector.tick_rest_capture_schedule('{org}','{producer}','{route}','{configuration}',{expected},{version},{cadence},{str(enabled).lower()});",True)
   return json.loads(value) if value else None
  with ThreadPoolExecutor(max_workers=8) as workers:results=list(workers.map(lambda _:tick(),range(8)))
  assert sum(value['enqueued'] for value in results)==1,results
  first=next(value for value in results if value['enqueued'])
  capture=first['capture']['captureId']
  assert all(value['capture']==first['capture'] for value in results)
  assert sql('SELECT count(*) FROM canvas_connector.rest_schedule_configurations;')=='1'
  assert sql('SELECT count(*) FROM canvas_connector.rest_capture_jobs;')=='1'
  assert tick(cadence=2000) is None,'same configuration UUID cannot change cadence'
  assert tick(configuration=str(uuid.uuid4())) is None,'new policy requires current CAS revision'
  assert tick(org='other-org') is None and tick(producer='other-producer') is None
  time.sleep(1.1)
  assert tick()['reason']=='capture_pending','pending work must not multiply'
  assert sql('SELECT next_ordinal FROM canvas_connector.rest_schedule_heads;')=='2'
  lease=sql("SELECT lease_id FROM canvas_connector.claim_rest_capture('schedule-org','producer');")
  now=int(sql('SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint;'))
  assert sql(f"SELECT canvas_connector.complete_rest_capture('schedule-org','producer','{capture}','{lease}',{now},{now},'{{\"completed\":true,\"effective_time_source\":\"observation_read\"}}');")=='t'
  assert tick()['reason']=='delivery_pending','unacknowledged delivery must backpressure capture'
  body=json.dumps({'binding_id':'binding','binding_revision':1,'observation_id':capture,'sequence':1,'observed_at_ms':now,'effective_at_ms':now,
   'claims':{'completed':True,'effective_time_source':'observation_read'}},separators=(',',':'))
  assert sql(f"SELECT canvas_connector.seal_observation('schedule-org','producer','{capture}','{body}');")=='t'
  delivery_lease=sql("SELECT lease_id FROM canvas_connector.claim_observation('schedule-org','producer');")
  assert sql(f"SELECT canvas_connector.acknowledge_observation('schedule-org','producer','{capture}','{delivery_lease}','synthetic-receipt',false);")=='t'
  second=tick();assert second['enqueued'] and second['capture']['ordinal']==2
  assert second['capture']['captureId']!=capture
  assert tick()['capture']==second['capture'],'same cursor receipt reconciles a committed-but-lost tick reply'
  disabled=tick(configuration=str(uuid.uuid4()),expected=1,enabled=False)
  assert disabled['configuration']['revision']==2 and disabled['reason']=='disabled'
  old=tick();assert not old['current'] and old['reason']=='superseded' and old['configuration']==first['configuration']
  for scenario,table,timing,body in [
   ('audit','rest_schedule_captures','INSERT',"RAISE EXCEPTION 'synthetic schedule audit failure';"),
   ('job','rest_capture_jobs','INSERT',"NEW.requirement:=jsonb_set(NEW.requirement,'{userId}','\"999\"');RETURN NEW;"),
   ('cursor','rest_schedule_heads','UPDATE',"NEW.next_ordinal:=NEW.next_ordinal+1;RETURN NEW;"),
   ('timestamp','rest_schedule_configurations','INSERT',"NEW.created_at:='2000-01-01'::timestamptz;RETURN NEW;"),
   ('expiry','rest_schedule_captures','INSERT',"PERFORM pg_sleep(2.2);RETURN NEW;"),
  ]:
   route='rollback-'+scenario;operation=str(uuid.uuid4())
   sql(f"""INSERT INTO canvas_connector.rest_capture_routes(organization_id,id,producer_ref,platform_id,binding_id,binding_revision,requirement,claim_names,effective_time_policy,enabled)
    VALUES('schedule-org','{route}','producer','platform','binding-{scenario}',1,'{{"factType":"canvas.course_completion","courseId":"17","userId":"29"}}',ARRAY['completed'],'as_of_read',true);
    CREATE FUNCTION canvas_connector.test_schedule_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN {body} END;$$;
    CREATE TRIGGER zz_schedule_fault BEFORE {timing} ON canvas_connector.{table} FOR EACH ROW EXECUTE FUNCTION canvas_connector.test_schedule_fault();""")
   if scenario=='expiry':sql("UPDATE canvas_connector.connections SET token_expires_at=clock_timestamp()+interval '2 seconds' WHERE organization_id='schedule-org';")
   try:
    try:tick(configuration=operation,route=route);raise AssertionError('schedule mutation/expiry did not roll back: '+scenario)
    except RuntimeError:pass
   finally:
    sql(f'DROP TRIGGER zz_schedule_fault ON canvas_connector.{table};DROP FUNCTION canvas_connector.test_schedule_fault();')
    if scenario=='expiry':sql("UPDATE canvas_connector.connections SET token_expires_at=NULL WHERE organization_id='schedule-org';")
   assert sql(f"SELECT count(*) FROM canvas_connector.rest_capture_jobs WHERE route_id='{route}';")=='0'
   assert sql(f"SELECT count(*) FROM canvas_connector.rest_schedule_heads WHERE route_id='{route}';")=='0'
   assert sql(f"SELECT count(*) FROM canvas_connector.rest_schedule_configurations WHERE configuration_id='{operation}';")=='0'
  for statement in ['DELETE FROM canvas_connector.rest_schedule_heads;','UPDATE canvas_connector.rest_schedule_captures SET receipt=\'{}\';',
    'DELETE FROM canvas_connector.rest_schedule_configurations;','SELECT * FROM canvas_connector.secrets;']:
   try:sql(statement,True);raise AssertionError('forbidden scheduler privilege succeeded')
   except RuntimeError:pass
  subprocess.run(['node',str(ROOT/'test/capture-scheduling-contract.mjs'),name],check=True,cwd=ROOT)
  print('Actual PG16 automatic capture scheduling:8-way idempotent configuration,deterministic capture receipts,CAS,cadence,queue/outbox backpressure,supersession and selected-role denials passed')
 finally:subprocess.run(['docker','rm','--force',name],check=True)

if __name__=='__main__':main()
