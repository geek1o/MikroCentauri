#!/usr/bin/env python3
"""Product Phase2 native HTTPS controller acceptance, disposable CHR only."""
import base64, hashlib, http.server, json, pathlib, ssl, subprocess, threading, time, urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]
CACHE=ROOT/'.cache/router-managed';CACHE.mkdir(mode=0o700,exist_ok=True)
CONNECTION=ROOT/'.cache/router-stage/router.json'
BINARY=ROOT/'.cache/router-stage/mikrocentauri'
TARGET='https://127.0.0.1:18443/rest'
INSTANCE='phase2full'
PATHS=['ip/route','ip/firewall/nat','ip/firewall/mangle','ip/firewall/filter','tool/netwatch','system/scheduler']
CTX=ssl.create_default_context(cafile=str(ROOT/'.cache/router-stage/tls.crt'))
AUTH='Basic '+base64.b64encode(b'mc-lab:DisposableLabOnly-2026').decode()
RESULT={};READY=503
class Health(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(READY);self.end_headers();self.wfile.write(b'readiness-fixture')
 def log_message(self,*args):pass

def api(method,path,body=None):
 req=urllib.request.Request(TARGET+'/'+path,method=method,headers={'Authorization':AUTH,'Content-Type':'application/json'},data=json.dumps(body).encode() if body is not None else None)
 with urllib.request.urlopen(req,context=CTX,timeout=15) as r:
  data=r.read();return json.loads(data) if data else None

def cli(action,*args,ok=True):
 r=subprocess.run([str(BINARY),action,'-router-config',str(CONNECTION),*args],capture_output=True,text=True,timeout=90)
 assert (r.returncode==0)==ok,{'action':action,'returncode':r.returncode,'stderr':r.stderr}
 return {'returncode':r.returncode,'stderr':r.stderr}
def private(name,value):
 p=CACHE/(name+'.json');p.write_text(json.dumps(value,indent=2)+'\n');p.chmod(0o600);return str(p)
def plan(name,objects):
 desired=private(name+'-desired',{'instance':INSTANCE,'objects':objects});out=str(CACHE/(name+'-plan.json'))
 cli('router-managed-plan','-desired',desired,'-out',out);return out

def owned():return [dict(path=p,**r) for p in PATHS for r in api('GET',p) if r.get('comment','').startswith('mikrocentauri:'+INSTANCE+':')]
def wait_state(disabled,timeout=20):
 start=time.monotonic()
 while time.monotonic()-start<timeout:
  rows=[r for r in owned() if r['path'] in ['ip/route','ip/firewall/nat']]
  if len(rows)==2 and all(r['disabled']==disabled for r in rows):return {'elapsed_seconds':round(time.monotonic()-start,3),'objects':rows}
  time.sleep(.4)
 raise AssertionError('watchdog state not reached: '+str(owned()))
def configured():
 # Exclude runtime counters, preserve all other server fields and native order.
 ignored={'.id','dynamic','active','inactive','invalid','immediate-gw','gateway-status','belongs-to','last-up','last-down','status','since','done-tests','failed-tests','bytes','packets','run-count','next-run'}
 state={p:[{k:v for k,v in r.items() if k not in ignored} for r in api('GET',p) if not r.get('comment','').startswith('mikrocentauri:'+INSTANCE+':') and not r.get('comment','').startswith('phase2-fixture:')] for p in PATHS}
 return hashlib.sha256(json.dumps(state,sort_keys=True).encode()).hexdigest()

def run():
 global READY
 assert api('GET','system/resource')['board-name'].startswith('CHR ')
 assert not owned(),'clean managed scope required'
 RESULT['unrelated_before']=configured()
 # Foreign anchors are deliberately disabled disposable fixtures, removed last.
 anchors=[]
 for name in ['left','middle','right']:
  anchors.append(api('PUT','ip/firewall/filter',{'comment':'phase2-fixture:'+name,'disabled':'true','chain':'input','action':'accept','src-address':'203.0.113.0/24'}))
 managed=[]
 for name,anchor in [('one',anchors[1]),('two',anchors[2])]:
  managed.append({'path':'ip/firewall/filter','place_before':anchor['.id'],'fields':{'comment':'mikrocentauri:'+INSTANCE+':filter:'+name,'disabled':'false','chain':'input','action':'accept','src-address':'203.0.113.0/24'}})
 journal=str(CACHE/'placement-journal')
 original=plan('ordered',managed);RESULT['active_apply']=cli('router-apply','-plan',original,'-journal',journal)
 RESULT['repeat_exact_apply']=cli('router-apply','-plan',original,'-journal',journal)
 RESULT['verify']=cli('router-verify','-plan',original,'-journal',journal)
 before=[r['comment'] for r in api('GET','ip/firewall/filter')]
 RESULT['ordered_before']=before
 cleanup=plan('ordered-delete',[]);cli('router-apply','-plan',cleanup,'-journal',journal)
 RESULT['rollback']=cli('router-rollback','-journal',journal)
 after=[r['comment'] for r in api('GET','ip/firewall/filter')]
 assert after==before,(before,after)
 RESULT['ordered_after']=after
 # A real external reorder must block destructive compensation.
 cleanup=plan('ordered-delete-again',[]);cli('router-apply','-plan',cleanup,'-journal',journal)
 # Native PATCH user anchor changes snapshot digest; rollback must refuse it.
 api('PATCH','ip/firewall/filter/'+anchors[1]['.id'],{'src-address':'203.0.113.128/25'})
 RESULT['anchor_edit_refused']=cli('router-rollback','-journal',journal,ok=False)
 api('PATCH','ip/firewall/filter/'+anchors[1]['.id'],{'src-address':'203.0.113.0/24'})
 cli('router-managed-recover','-journal',journal)
 RESULT['cleanup_filters']=cli('router-cleanup','-instance',INSTANCE,'-journal',journal)
 for a in anchors:api('DELETE','ip/firewall/filter/'+a['.id'])
 targets=[{'path':'ip/route','fields':{'comment':'mikrocentauri:'+INSTANCE+':route:canary','disabled':'true','dst-address':'203.0.113.125/32','gateway':'10.0.2.2','routing-table':'main','distance':'1'}}, {'path':'ip/firewall/nat','fields':{'comment':'mikrocentauri:'+INSTANCE+':nat:dns','disabled':'true','chain':'dstnat','in-interface':'bridge-lan','dst-address':'192.0.2.53','protocol':'udp','dst-port':'53','action':'dst-nat','to-addresses':'10.0.2.2','to-ports':'19083'}}]
 spec={'instance':INSTANCE,'host':'10.0.2.2','port':19083,'interval':2000000000,'timeout':1000000000,'success_threshold':3,'targets':targets}
 specpath=private('watchdog-spec',spec);watchplan=str(CACHE/'watchdog-plan.json')
 cli('router-watchdog-plan','-watchdog-config',specpath,'-out',watchplan)
 watchjournal=str(CACHE/'watchdog-journal')
 RESULT['install_watchdog']=cli('router-apply','-plan',watchplan,'-journal',watchjournal)
 staged=json.loads(pathlib.Path(watchplan).read_text())['desired']
 for o in staged:
  if o['path'] in ['tool/netwatch','system/scheduler']:o['fields']['disabled']='false'
 activeplan=plan('observer-active',staged);RESULT['activate_observer']=cli('router-apply','-plan',activeplan,'-journal',watchjournal)
 RESULT['initial_down']=wait_state('true')
 READY=200;start=time.monotonic();RESULT['healthy_up']=wait_state('false');assert time.monotonic()-start>=2,'debounce bypassed'
 READY=503;RESULT['failure_down']=wait_state('true')
 READY=200;RESULT['recovery_up']=wait_state('false')
 # Full generation mismatch must block readiness even though HTTP returns200.
 route=next(r for r in owned() if r['path']=='ip/route')
 api('PATCH','ip/route/'+route['.id'],{'distance':'2'})
 RESULT['wrong_generation_down']=wait_state('true')
 api('PATCH','ip/route/'+route['.id'],{'distance':'1'});RESULT['repaired_up']=wait_state('false')
 # Preserve a forged duplicate; observer denies readiness and disables exact set.
 duplicate=api('PUT','ip/route',targets[0]['fields'])
 start=time.monotonic()
 while time.monotonic()-start<15:
  routes=[r for r in owned() if r['path']=='ip/route']
  if len(routes)==2 and all(r['disabled']=='true' for r in routes):break
  time.sleep(.4)
 else:raise AssertionError('duplicate did not fail open')
 RESULT['duplicate_refused']=True;api('DELETE','ip/route/'+duplicate['.id']);wait_state('false')
 # A static counterfeit debounce entry must remain untouched and deny readiness.
 static=api('PUT','ip/firewall/address-list',{'list':'mc-'+INSTANCE+'-watch-count','address':'127.0.0.2','comment':'mikrocentauri:'+INSTANCE+':watchdog-counter'})
 RESULT['static_counter_down']=wait_state('true')
 assert any(r['.id']==static['.id'] and r['dynamic']=='false' for r in api('GET','ip/firewall/address-list'))
 api('DELETE','ip/firewall/address-list/'+static['.id']);RESULT['static_counter_recovery']=wait_state('false')
 # An unrelated healthy endpoint is rejected by the script's own tuple check.
 observer=next(r for r in owned() if r['path']=='tool/netwatch')
 api('PATCH','tool/netwatch/'+observer['.id'],{'port':'19084'})
 RESULT['observer_tuple_down']=wait_state('true')
 api('PATCH','tool/netwatch/'+observer['.id'],{'port':'19083'});wait_state('false')
 READY=503
 # Administrative console reboot is requested by the parent while this marker exists.
 (CACHE/'reboot-requested').write_text('ready\n')
 print('READY_FOR_NATIVE_REBOOT',flush=True)
 while not (CACHE/'reboot-issued').exists():time.sleep(.2)
 deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  try:
   uptime=api('GET','system/resource')['uptime']
   if 'm' not in uptime and 'h' not in uptime and 'd' not in uptime:break
  except Exception:pass
  time.sleep(1)
 else:raise AssertionError('reboot management did not return')
 RESULT['reboot_down']=wait_state('true',25)
 READY=200;RESULT['reboot_recovery']=wait_state('false',25)
 READY=503;wait_state('true')
 # Quiesce the observer before verifying or reconciling its mutable targets.
 stagednext=json.loads(pathlib.Path(watchplan).read_text())['desired']
 stop=plan('observer-stop',stagednext);cli('router-apply','-plan',stop,'-journal',watchjournal)
 RESULT['idempotent']=cli('router-managed-reconcile','-plan',stop,'-journal',watchjournal)
 RESULT['cleanup_watchdog']=cli('router-cleanup','-instance',INSTANCE,'-journal',watchjournal)
 assert not owned()
 RESULT['unrelated_after']=configured();assert RESULT['unrelated_after']==RESULT['unrelated_before']
 RESULT['completed']=True

if __name__=='__main__':
 server=http.server.ThreadingHTTPServer(('127.0.0.1',19083),Health)
 alternate=http.server.ThreadingHTTPServer(('127.0.0.1',19084),Health)
 threading.Thread(target=alternate.serve_forever,daemon=True).start()
 for marker in ['reboot-requested','reboot-issued']:(CACHE/marker).unlink(missing_ok=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
 try:run()
 finally:
  (CACHE/'results.json').write_text(json.dumps(RESULT,indent=2)+'\n');server.shutdown();alternate.shutdown()
