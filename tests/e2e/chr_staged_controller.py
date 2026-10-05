#!/usr/bin/env python3
"""CLI acceptance against native disposable CHR www-ssl, never a real router."""
import base64
import hashlib
import json
import pathlib
import ssl
import subprocess
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[2]
CACHE=ROOT/'.cache/router-stage'
TARGET='https://127.0.0.1:18443/rest'
INSTANCE='stage2secure'
PATHS=['ip/route','ip/firewall/nat','ip/firewall/mangle','ip/firewall/filter','tool/netwatch']
CTX=ssl.create_default_context(cafile=str(CACHE/'tls.crt'))
AUTH='Basic '+base64.b64encode(b'mc-lab:DisposableLabOnly-2026').decode()

def api(method,path,body=None):
 req=urllib.request.Request(TARGET+'/'+path,method=method,headers={'Authorization':AUTH,'Content-Type':'application/json'},data=json.dumps(body).encode() if body is not None else None)
 with urllib.request.urlopen(req,context=CTX,timeout=15) as response:
  data=response.read();return json.loads(data) if data else None

def cli(action,*args,ok=True):
 r=subprocess.run([str(CACHE/'mikrocentauri'),action,'-router-config',str(CACHE/'router.json'),*args],capture_output=True,text=True,timeout=70)
 result={'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
 assert (r.returncode==0)==ok,result
 return result

def artifact(name,changes,desired):
 p=CACHE/(name+'.json')
 p.write_text(json.dumps({'schema_version':1,'target':TARGET,'plan':{'instance':INSTANCE,'gate':'STAGING ONLY','changes':changes},'desired':desired},indent=2)+'\n');p.chmod(0o600);return str(p)

def owned():
 return [r for r in api('GET','ip/route') if r.get('comment','').startswith('mikrocentauri:'+INSTANCE+':')]

def untouched():
 fields=['comment','disabled','dst-address','gateway','routing-table','distance','scope','target-scope','chain','action','src-address','src-address-list','dst-address-list','protocol','dst-port','src-port','to-addresses','to-ports','host','type','port','interval','timeout','up-script','down-script','test-script','in-interface','out-interface','connection-mark','new-routing-mark','passthrough','reject-with']
 result={p:[{k:r[k] for k in ['.id',*fields] if k in r} for r in api('GET',p) if not r.get('comment','').startswith('mikrocentauri:'+INSTANCE+':')] for p in PATHS}
 return hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()

def run():
 out={};journal=str(CACHE/'journal')
 try:
  assert api('GET','system/resource')['board-name'].startswith('CHR ')
  assert not owned(),'Clean owned canary scope required'
  before=untouched();out['unrelated_before_sha256']=before
  out['inspect']=json.loads(cli('router-inspect')['stdout'])
  assert out['inspect']['version_supported'] and all(out['inspect']['resources'].values())
  desired={'path':'ip/route','fields':{'comment':'mikrocentauri:'+INSTANCE+':route:canary','disabled':'true','dst-address':'203.0.113.124/32','gateway':'172.30.0.2','routing-table':'main','distance':'1'}}
  plan=artifact('create',[{'action':'create','after':desired}],[desired])
  out['create']=cli('router-stage','-plan',plan,'-journal',journal)
  first=owned();assert len(first)==1 and first[0]['disabled']=='true';out['created']=first
  out['idempotent']=cli('router-reconcile','-plan',plan,'-journal',journal)
  assert owned()==first
  old={'path':'ip/route','id':first[0]['.id'],'fields':first[0].copy()};old['fields'].pop('.id')
  newer=json.loads(json.dumps(desired));newer['fields']['distance']='2'
  update=artifact('update',[{'action':'update','before':old,'after':newer}],[newer])
  api('PATCH','ip/route/'+first[0]['.id'],{'distance':'3'})
  out['stale_rejected']=cli('router-stage','-plan',update,'-journal',journal,ok=False)
  assert owned()[0]['distance']=='3'
  out['fresh_reconcile']=cli('router-reconcile','-plan',update,'-journal',journal)
  assert owned()[0]['distance']=='2' and owned()[0]['disabled']=='true'
  active=json.loads(json.dumps(desired));active['fields']['comment']='mikrocentauri:'+INSTANCE+':route:unsafe';active['fields']['disabled']='false'
  bad=artifact('active',[{'action':'create','after':active}],[active])
  out['active_rejected']=cli('router-stage','-plan',bad,'-journal',journal,ok=False);assert len(owned())==1
  out['recover_committed']=cli('router-recover','-journal',journal)
  cleanup=artifact('cleanup',[],[])
  out['cleanup']=cli('router-reconcile','-plan',cleanup,'-journal',journal)
  assert not owned()
  out['unrelated_after_sha256']=untouched();assert out['unrelated_after_sha256']==before
  out['journal']=json.loads((CACHE/'journal/journal.json').read_text())
  out['completed']=True
 except Exception as error:out['error']=str(error);raise
 finally:
  (CACHE/'native-results.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(out,indent=2))

if __name__=='__main__':run()
