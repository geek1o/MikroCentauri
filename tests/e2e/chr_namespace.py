#!/usr/bin/env python3
"""Active/retired namespace lifecycle on the explicit disposable localhost CHR."""
import json
import time
import urllib.request
import itertools

sequence=itertools.count(1)
current_revision=0
from chr_dataplane import ROOT, rest, gateway, request, assert_success
from chr_dynamic_publication import wait, maps
from chr_binding_policy import workload
from chr_protocols import quic
from chr_target_refresh import cached


def policy():
 global current_revision
 s=gateway(path='/diagnostics/namespace');current_revision=s['revision'];return s
def settled_up():
 initial=wait(True);observations=[];stable=None;start=time.monotonic()
 while time.monotonic()-start<45:
  try:h=gateway()
  except RuntimeError:h={}
  observations.append(h)
  if h.get('ready') and h.get('consecutive_successes')==3:
   if stable is None:stable=time.monotonic()
   if time.monotonic()-stable>=1:return {'native':initial,'health_observations':observations,'scope':'Settled health before traffic, not a startup latency bound'}
  else:stable=None
  time.sleep(.5)
 raise AssertionError('Health did not settle')
def apply(body):
 rows=rest('POST','tool/fetch',{'url':'http://172.30.0.2:9099/control/namespace','http-method':'post','http-data':json.dumps(body),'http-header-field':'Content-Type: application/json','output':'user'})
 global current_revision
 s=next(json.loads(r['data']) for r in rows if r.get('data'));current_revision=s['revision'];return s
def aliases():return {b['domain']:b['alias'] for b in gateway(path='/diagnostics/generation')['admission']['bindings']}
def native_dns(name):
 rest('POST','ip/dns/cache/flush',{})
 return request(name,path='/phase7-new-dns')
def cached_matrix(binding,active):
 result={}
 revision=current_revision
 for name,alias in binding.items():
  peer='10.77.0.10' if name in active else '10.77.0.1'
  h=workload('selected.test',domain=name,address=alias);assert_success(h,peer)
  q=quic('selected.test',alias);assert q['remote_ip']==peer,q
  marker=f'phase7-{revision}-{name}-{next(sequence)}'
  q_udp=urllib.request.Request('http://127.0.0.1:19010/udp',data=json.dumps({'domain':name,'address':alias,'skip_dns':True,'payload':marker}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(q_udp,timeout=16) as r:u=json.load(r)
  assert_success(u);u['capture_marker']=marker
  result[name]={'http_foreign_active_host':h,'http3_active_sni':q,'udp':u}
 return result

if __name__=='__main__':
 out={};fault=None
 try:
  assert rest('GET','system/resource')['board-name'].startswith('CHR ')
  c=next(r for r in rest('GET','container') if r['name']=='mc-gateway-phase7')
  out['initial_up']=settled_up();initial=policy();out['initial_policy']=initial
  assert 'pending' not in initial,initial
  if initial['active']!=initial['known']:
   initial=apply({'revision':initial['revision'],'active':initial['known']});out['baseline_activation']=initial;settled_up()
  base=initial['revision']
  original=aliases();out['original_bindings']=original;assert len(original) in (3,4),original
  addition='fifth.test' if 'fourth.test' in original else 'fourth.test'
  active_old=[n for n in initial['known'] if n!='second.test']
  retired=apply({'revision':base,'active':active_old});out['retired_policy']=retired;assert retired['revision']==base+1
  out['retired_up']=settled_up();assert aliases()==original
  r=native_dns('SeCoNd.TeSt.');assert_success(r,'10.77.0.1');assert r['resolved_ipv4']=='10.77.0.20';out['retired_new_dns']=r
  out['retired_cached']=cached_matrix(original,retired['active'])
  out['retired_source']={}
  for source,peer in [('192.168.88.20','10.77.0.10'),('192.168.88.30','10.77.0.1')]:
   r=workload('selected.test',source=source);assert_success(r,peer)
   q=quic('selected.test',original['second.test'],source);assert q['remote_ip']==peer
   out['retired_source'][source]={'http':r,'http3':q}
  expanded=apply({'revision':base+1,'active':active_old+[addition]});out['expanded_policy']=expanded
  out['expanded_up']=settled_up();allbind=aliases();out['expanded_bindings']=allbind
  assert all(allbind[n]==a for n,a in original.items()) and len(set(allbind.values()))==len(original)+1
  r=native_dns(addition);assert_success(r,'10.77.0.10');assert r['resolved_ipv4']==allbind[addition];out['addition_dns']=r
  out['expanded_cached']=cached_matrix(allbind,expanded['active']);assert len(maps())==len(allbind)
  rest('POST','container/stop',{'numbers':c['.id']});out['container_down']=wait(False)
  out['all_cached_direct']=cached_matrix(allbind,[])
  rest('POST','container/start',{'numbers':c['.id']});out['container_up']=settled_up()
  assert policy()==expanded and aliases()==allbind
  out['restarted_retired_dns']=native_dns('second.test');assert out['restarted_retired_dns']['resolved_ipv4']=='10.77.0.20'
  out['restarted_cached']=cached_matrix(allbind,expanded['active'])
  restored=apply({'revision':base+2,'active':expanded['known']});out['reactivated_policy']=restored;out['reactivated_up']=settled_up()
  r=native_dns('second.test');assert_success(r,'10.77.0.10');assert r['resolved_ipv4']==original['second.test'];out['reactivated_dns']=r
  out['reactivated_cached']=cached_matrix(allbind,restored['active'])
  try:apply({'revision':base,'active':['selected.test']});raise AssertionError('Stale revision accepted')
  except RuntimeError as e:out['stale_denied']=str(e)
  assert policy()==restored and aliases()==allbind
  out['invalid_candidate_denied']={}
  for label,active in [('duplicate',['selected.test','selected.test']),('capacity',['selected.test']+[f'overflow{i}.test' for i in range(32)])]:
   try:apply({'revision':base+3,'active':active});raise AssertionError('Invalid candidate accepted')
   except RuntimeError as e:out['invalid_candidate_denied'][label]=str(e)
   assert policy()==restored and gateway(path='/diagnostics/generation')['engine_running']
  out['healthy_after_invalid_candidates']=cached_matrix(allbind,restored['active'])
  # Disable one owned fallback object only within this disposable fault test.
  # Restore it before checking DIRECT; no fallback is claimed while it is damaged.
  fault=next(m for m in maps() if m['dst-address']==allbind['third.test'])
  rest('PATCH','ip/firewall/nat/'+fault['.id'],{'disabled':'true'})
  try:apply({'revision':base+3,'active':[n for n in expanded['known'] if n!='third.test']});raise AssertionError('Damaged backend admitted')
  except RuntimeError as e:out['backend_denied']=str(e)
  pending=policy();out['pending_policy']=pending;assert pending['revision']==base+3 and pending['pending']['revision']==base+4
  out['pending_down']=wait(False)
  rest('PATCH','ip/firewall/nat/'+fault['.id'],{'disabled':'false'});fault=None
  rest('POST','container/stop',{'numbers':c['.id']});time.sleep(2)
  rest('POST','container/start',{'numbers':c['.id']});time.sleep(4)
  out['pending_after_restart']=policy();assert out['pending_after_restart']==pending
  d=gateway(path='/diagnostics/generation');out['pending_generation']=d
  assert not d['engine_running'] and not d['admission']['admitted'] and 'blackhole' in d['ingress_route']
  out['pending_cached_direct']=cached_matrix(allbind,[])
  out['resumed_policy']=apply({'revision':base+4,'resume':True});out['resumed_up']=settled_up()
  assert aliases()==allbind and 'third.test' not in out['resumed_policy']['active']
  out['resumed_cached']=cached_matrix(allbind,out['resumed_policy']['active'])
  out['final_policy']=apply({'revision':base+4,'active':expanded['known']});out['final_up']=settled_up()
  assert aliases()==allbind and out['final_policy']['revision']==base+5
  out['final_cached']=cached_matrix(allbind,out['final_policy']['active'])
  out['completed']=True
 except Exception as e:out['error']=str(e);raise
 finally:
  if fault:rest('PATCH','ip/firewall/nat/'+fault['.id'],{'disabled':'false'})
  (ROOT/'.cache/dataplane/namespace-results.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(out,indent=2))
