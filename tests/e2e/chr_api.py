#!/usr/bin/env python3
"""Product Phase 4 production HTTPS CLI on the disposable pinned localhost CHR.

Builder fixtures use separate api4 ownership and 198.19.128/17 allocator state.
Never targets a real router. Safe API results contain no bearer token or keys.
Native RAM leases and cached TCP/UDP/HTTP3 are checked independently.
"""
import argparse, base64, copy, gzip, hashlib, io, itertools, json, pathlib, socket, ssl, tarfile, time, urllib.error, urllib.request
from chr_dataplane import ROOT, request, assert_success
from chr_binding_policy import workload
from chr_protocols import quic
CACHE=ROOT/'.cache/api-native'
FILES=CACHE/'files'
AUTH='Basic '+base64.b64encode(b'admin:').decode()
TOKEN=None
SEQ=itertools.count(1)
RUN_ID=str(time.time_ns())

def native(method,path,body=None):
 req=urllib.request.Request('http://127.0.0.1:18080/rest/'+path,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':AUTH,'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req,timeout=120) as response:
   raw=response.read();return json.loads(raw) if raw else None
 except urllib.error.HTTPError as error:raise RuntimeError(error.read().decode()) from None

def api(method,path,body=None,authenticated=True):
 headers={'Content-Type':'application/json','Host':'172.30.0.2:8443'}
 if authenticated and TOKEN:headers['Authorization']='Bearer '+TOKEN
 req=urllib.request.Request('https://127.0.0.1:18444/api/v1'+path,method=method,headers=headers,data=json.dumps(body).encode() if body is not None else None)
 try:
  with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(FILES/'api.crt')),timeout=100) as response:return response.status,response.read()
 except urllib.error.HTTPError as error:return error.code,error.read()

def value(method,path,body=None,expect=200):
 status,raw=api(method,path,body);assert status==expect,(path,status,raw)
 return json.loads(raw)

def login():
 global TOKEN
 code,raw=api('POST','/auth/login',{'password':'API4DisposablePasswordOnly-2026'},False)
 assert code==200,(code,raw);TOKEN=json.loads(raw)['access_token']

def native_state():
 watches=[r for r in native('GET','tool/netwatch') if r.get('comment')=='mikrocentauri:api4:netwatch:readiness']
 authority=[r for r in native('GET','ip/firewall/address-list') if r.get('list') in ('mc-api4-watch-count','mc-api4-up-lease')]
 return {'watchdog':[{k:r[k] for k in ['disabled','status','host','port'] if k in r} for r in watches],'authority':[{k:r[k] for k in ['list','address','comment','dynamic','timeout'] if k in r} for r in authority]}

def settled(up=True,timeout=90):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  state=native_state()
  lease=next((r for r in state['authority'] if r['list']=='mc-api4-up-lease'),None)
  if up:
   try:
    status=value('GET','/system')['status']
    if status['ready'] and lease and lease['dynamic']=='true' and lease['address']=='192.168.88.0/24':
     time.sleep(1);return {'api':status,'native':state}
   except (OSError,AssertionError,urllib.error.URLError):pass
  elif not state['authority'] and all(w['status'] in ('down','unknown') for w in state['watchdog']):
   time.sleep(1);return state
  time.sleep(.3)
 raise AssertionError('Native API readiness did not settle: '+json.dumps(state))

def read_file(path):
 rows=native('POST','file/read',{'file':path,'offset':'0','chunk-size':'32768'})
 if isinstance(rows,dict):rows=[rows]
 return json.loads(''.join(r['data'] for r in rows if 'data' in r))

def aliases(container):
 root=container['root-dir'].lstrip('/')
 data=read_file(root+'/data/api4/runtime/publication/mappings.json')
 return data

def mapping_aliases():
 return {r['dst-address']:r['to-addresses'] for r in native('GET','ip/firewall/nat') if r.get('chain')=='mc-api4-backup'}

def matrix(bindings,active,revision):
 report={}
 for domain,alias in bindings.items():
  peer='10.77.0.10' if domain in active else '10.77.0.1'
  tcp=workload('unselected.test',domain=domain,address=alias);assert_success(tcp,peer)
  h3=quic('unselected.test',alias);assert h3['remote_ip']==peer,h3
  marker=f'phase4-{RUN_ID}-{revision}-{domain}-{next(SEQ)}'
  req=urllib.request.Request('http://127.0.0.1:19010/udp',data=json.dumps({'domain':domain,'address':alias,'skip_dns':True,'payload':marker}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=16) as response:udp=json.load(response)
  assert_success(udp);udp['capture_marker']=marker
  report[domain]={'expected_peer':peer,'tcp':tcp,'http3':h3,'udp':udp}
 return report

def draft(model):
 saved=value('POST','/config/draft',model)
 validated=value('POST','/config/validate',{'draft_revision':saved['draft_revision']})
 plan=value('POST','/config/plan',{'draft_revision':saved['draft_revision']})
 return {'saved':saved,'validated':validated,'plan':plan}

def provision():
 assert native('GET','system/resource')['board-name'].startswith('CHR ')
 if not (CACHE/'native-before.json').exists():
  before={p:native('GET',p) for p in ['ip/service','certificate','ip/route','ip/firewall/nat','tool/netwatch','system/scheduler','container']}
  (CACHE/'native-before.json').write_text(json.dumps(before,indent=2)+'\n')
 # Require old owners stopped before sharing the fixture veth and Linux table.
 assert all(r.get('stopped')=='true' or r.get('name')=='mc-core-phase3-first-import' for r in native('GET','container'))
 objects=json.loads((FILES/'objects.json').read_text())
 for obj in objects:
  matches=[r for r in native('GET',obj['path']) if r.get('comment')==obj['fields']['comment']]
  assert not matches,('existing owned profile; preserve and inspect',obj['fields']['comment'])
  fields=dict(obj['fields'])
  if obj.get('place_before'):fields['place-before']=obj['place_before']
  if obj['path'] in ('tool/netwatch','system/scheduler'):fields['disabled']='false'
  native('PUT',obj['path'],fields)
 # Preserve the older DNS rules, but prevent them from steering DOWN traffic.
 for row in native('GET','ip/firewall/nat'):
  if row.get('comment') in ('mikrocentauri:lab:nat:dns-tcp','mikrocentauri:lab:nat:dns-udp'):native('PATCH','ip/firewall/nat/'+row['.id'],{'disabled':'true'})
 native('PUT','ip/firewall/nat',{'comment':'mikrocentauri:api4:nat:api-management','chain':'dstnat','action':'dst-nat','dst-address':'10.0.2.15','protocol':'tcp','dst-port':'18444','to-addresses':'172.30.0.2','to-ports':'8443','disabled':'false'})
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
  sock.connect(str(ROOT/'.cache/chr-lab/monitor'));sock.settimeout(2);sock.recv(4096)
  sock.sendall(b'hostfwd_add wan tcp:127.0.0.1:18444-:18444\n');print(sock.recv(4096).decode(errors='replace').strip())
 native('POST','tool/fetch',{'url':'http://10.0.2.2:19030/api-gateway-image.tar','dst-path':'pcie2/api4-image.tar','keep-result':'yes'})
 native('PUT','container',{'file':'pcie2/api4-image.tar','root-dir':'pcie2/mc-api4','interface':'mc-probe','name':'mc-api4','logging':'true','start-on-boot':'false'})
 print('native profile staged; container import asynchronous')

def repin(container_name):
 container=next(r for r in native('GET','container') if r.get('name')==container_name)
 assert container_name=='mc-api4' and container['root-dir']=='/pcie2/mc-api4'
 if container.get('stopped')!='true':native('POST','container/stop',{'numbers':container['.id']})
 deadline=time.monotonic()+45
 while next(r for r in native('GET','container') if r['.id']==container['.id']).get('stopped')!='true':
  assert time.monotonic()<deadline;time.sleep(.2)
 settled(False)
 native('POST','tool/fetch',{'url':'http://10.0.2.2:19030/mikrocentauri','dst-path':'pcie2/mc-api4/bin/mikrocentauri','keep-result':'yes'})
 # Existing inode/mode is retained; failure must be repaired only while stopped.
 native('POST','container/start',{'numbers':container['.id']})

def run(args):
 global TOKEN
 report={'run_id':RUN_ID,'scope':'CHR 7.24.5 x86_64; production CLI api-serve; TLS1.3; new connections; SIGKILL owner loss; isolated fixtures'}
 try:
  if args.provision:provision()
  if args.repin:repin(args.container)
  report['build']=json.loads((FILES/'api-gateway-image.metadata.json').read_text())
  # Establish DNS lifetimes before recovery can refresh the durable ledger.
  fixture=urllib.request.Request('http://127.0.0.1:19020/dns-fixture',data=json.dumps({'target':'10.77.0.20','ttl':30,'all_ttl':30,'fail':False}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(fixture,timeout=5) as response:report['dns_fixture']=json.load(response)
  deadline=time.monotonic()+180
  while True:
   container=next(r for r in native('GET','container') if r.get('name')==args.container)
   if container.get('stopped')=='true' or container.get('running')=='true':break
   assert time.monotonic()<deadline,container;time.sleep(1)
  if container.get('running')!='true':native('POST','container/start',{'numbers':container['.id']})
  deadline=time.monotonic()+90
  while True:
   try:login();break
   except (OSError,urllib.error.URLError,AssertionError):
    assert time.monotonic()<deadline,'TLS API startup timed out';time.sleep(.5)
  report['initial']=settled()
  baseline=json.loads((FILES/'model.json').read_text())
  current=value('GET','/config')['policy']['dns']['selected_domains']
  if sorted(current)!=sorted(baseline['dns']['selected_domains']):
   baseline_plan=draft(baseline)['plan']
   report['baseline_applied']=value('POST','/config/apply',{'plan_id':baseline_plan['plan_id']})
   report['initial']=settled()
  report['unauthorized_status']=api('GET','/config',authenticated=False)[0];assert report['unauthorized_status']==401
  report['protected_readiness_status']=api('GET','/health/ready',authenticated=False)[0];assert report['protected_readiness_status']==401
  with socket.create_connection(('127.0.0.1',18444),timeout=5) as sock:
   with ssl.create_default_context(cafile=str(FILES/'api.crt')).wrap_socket(sock,server_hostname='127.0.0.1') as tls:
    report['tls_version']=tls.version();assert report['tls_version']=='TLSv1.3'
  native('POST','ip/dns/cache/flush',{});time.sleep(1)
  bindings={}
  for name in ['selected.test','second.test','third.test']:
   result=request(name,path='/api4-initial');assert_success(result,'10.77.0.10');bindings[name]=result['resolved_ipv4']
   assert __import__('ipaddress').ip_address(bindings[name]) in __import__('ipaddress').ip_network('198.19.128.0/17')
  report['bindings']=bindings
  # The RAM authority identity must survive repeated healthy refreshes.
  lease_ids=[]
  for _ in range(4):
   leases=[r for r in native('GET','ip/firewall/address-list') if r.get('list')=='mc-api4-up-lease']
   assert len(leases)==1 and leases[0]['dynamic']=='true',leases
   lease_ids.append(leases[0]['.id']);time.sleep(2.1)
  assert len(set(lease_ids))==1,lease_ids
  report['healthy_lease_refresh']={'row_ids':lease_ids,'stable_identity':True,'observed_seconds':8.4}
  report['initial_cached']=matrix(bindings,list(bindings),report['initial']['api']['revision'])
  model=json.loads((FILES/'model.json').read_text())
  # Removing a domain changes all future cached-alias protocols to DIRECT.
  changed=copy.deepcopy(model);changed['dns']['selected_domains']=['selected.test','third.test'];changed['rules'][1]['domains']=changed['dns']['selected_domains']
  prepared=draft(changed);report['retirement_workflow']=prepared
  plan=prepared['plan'];plan_id=plan['plan_id']
  report['applied']=value('POST','/config/apply',{'plan_id':plan_id});report['retirement_up']=settled()
  report['replayed_plan_status']=api('POST','/config/apply',{'plan_id':plan_id})[0];assert report['replayed_plan_status']==409
  report['retired_cached']=matrix(bindings,changed['dns']['selected_domains'],report['retirement_up']['api']['revision'])
  # Operator topology is immutable; a rejected plan cannot replace the core.
  oldrev=report['retirement_up']['api']['revision'];bad=copy.deepcopy(changed);bad['instance']='other'
  pid_before=read_file(container['root-dir'].lstrip('/')+'/data/api4/runtime/process/journal.json')['pid']
  saved=value('POST','/config/draft',bad)
  report['bad_topology_status']=api('POST','/config/plan',{'draft_revision':saved['draft_revision']})[0];assert report['bad_topology_status']==422
  after_reject=value('GET','/system')['status']
  assert after_reject==report['retirement_up']['api'],{'after_reject':after_reject,'before':report['retirement_up']['api'],'events':value('GET','/logs')[-12:]}
  pid_after=read_file(container['root-dir'].lstrip('/')+'/data/api4/runtime/process/journal.json')['pid']
  assert pid_after==pid_before
  report['invalid_plan_process']={'before_pid':pid_before,'after_pid':pid_after}
  report['invalid_candidate_kept_cache']=matrix(bindings,changed['dns']['selected_domains'],oldrev)
  # A second save consumes eligibility of the preceding plan.
  stale=draft(changed);value('POST','/config/draft',changed)
  report['stale_plan_status']=api('POST','/config/apply',{'plan_id':stale['plan']['plan_id']})[0];assert report['stale_plan_status']==409
  pid_stale=read_file(container['root-dir'].lstrip('/')+'/data/api4/runtime/process/journal.json')['pid']
  assert pid_stale==pid_before
  report['stale_plan_process']={'before_pid':pid_before,'after_pid':pid_stale}
  backup=value('GET','/backup');raw=json.dumps(backup)
  for secret in ['bf000d23-0752-40b4-affe-68f7707a9661','DisposableLabOnly','/data/api4',TOKEN]:assert secret not in raw
  report['safe_backup_schema']=backup['schema']
  report['restore_preview']=value('POST','/backup/restore-preview',backup)
  restored=value('POST','/backup/restore-draft',backup)
  report['restore_draft']=restored
  dr=restored['draft_revision']
  value('POST','/config/validate',{'draft_revision':dr});rp=value('POST','/config/plan',{'draft_revision':dr})
  report['restore_applied']=value('POST','/config/apply',{'plan_id':rp['plan_id']});report['restore_up']=settled()
  assert mapping_aliases()=={v:'10.77.0.20' for v in bindings.values()}
  # Parent process death removes API readiness and finite lease, cached maps survive.
  native('PATCH','container/'+container['.id'],{'stop-signal':'9-SIGKILL'})
  native('POST','container/stop',{'numbers':container['.id']});report['stopped_native']=settled(False)
  report['owner_loss_signal']='9-SIGKILL'
  native('PATCH','container/'+container['.id'],{'stop-signal':'15-SIGTERM'})
  report['stopped_cached']=matrix(bindings,[],report['restore_up']['api']['revision'])
  native('POST','container/start',{'numbers':container['.id']});TOKEN=None
  deadline=time.monotonic()+90
  while True:
   try:login();break
   except (OSError,urllib.error.URLError,AssertionError):assert time.monotonic()<deadline;time.sleep(.5)
  report['restart']=settled();report['recovered_cached']=matrix(bindings,changed['dns']['selected_domains'],report['restart']['api']['revision'])
  published=value('GET','/openapi.json');assert published==json.loads((ROOT/'docs/api/openapi.json').read_text())
  report['openapi_matches_published']=True
  code,bundle=api('GET','/diagnostics/bundle');assert code==200
  with tarfile.open(fileobj=io.BytesIO(bundle),mode='r:gz') as archive:
   names=archive.getnames();assert names==['status.json','model-preview.json','events.json','routeros.json','subscriptions.json']
   contents=b''.join(archive.extractfile(name).read() for name in names)
  for secret in ['bf000d23-0752-40b4-affe-68f7707a9661','DisposableLabOnly','/data/api4',TOKEN]:assert secret.encode() not in contents
  report['diagnostic_bundle']={'files':names,'compressed_bytes':len(bundle),'redacted':True}
  value('POST','/auth/logout',{})
  report['revoked_session_status']=api('GET','/config')[0];assert report['revoked_session_status']==401
  report['completed']=True
 except Exception as error:report['error']=str(error);raise
 finally:
  (CACHE/'native-results.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'completed':report.get('completed',False),'report':str(CACHE/'native-results.json')},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provision',action='store_true');p.add_argument('--repin',action='store_true');p.add_argument('--container',default='mc-api4');run(p.parse_args())
