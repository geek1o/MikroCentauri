#!/usr/bin/env python3
"""Continuous new-flow probes across an isolated CHR reboot; never a production target."""
import concurrent.futures
import json
import re
import threading
import time
import urllib.request
from chr_dataplane import ROOT, rest, gateway
from chr_dynamic_publication import wait


def uptime_seconds(text):
    units={'w':604800,'d':86400,'h':3600,'m':60,'s':1}
    parts=re.findall(r'(\d+)([wdhms])',text)
    if not parts or ''.join(n+u for n,u in parts)!=text:raise ValueError('Unsupported native uptime')
    return sum(int(n)*units[u] for n,u in parts)


def lease():
    return [r for r in rest('GET','ip/firewall/address-list') if r.get('list')=='mc-lab-up-lease']


def probe(kind,seq):
    body={'domain':'second.test','path':'/phase6-boot-'+str(seq),'timeout_ms':300}
    if kind!='dns':body.update(address='198.18.0.3',skip_dns=True)
    if kind=='udp':body['payload']='phase6-boot-udp-'+str(seq)
    q=urllib.request.Request('http://127.0.0.1:19010/'+('udp' if kind=='udp' else 'request'),data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(q,timeout=2) as r:return json.load(r)


if __name__=='__main__':
    result={'scope':'Fresh flows to one saved alias and new domain queries; first observed success after each stream outage, not a loss/timing bound'}
    stop=threading.Event();samples={k:[] for k in ('http','udp','dns')}
    started=time.monotonic()
    def worker(kind):
        seq=0
        while not stop.is_set() and time.monotonic()-started < 90:
            seq+=1;begin=time.monotonic()
            try:r=probe(kind,seq)
            except Exception as e:r={'error':str(e)}
            samples[kind].append({'sequence':seq,'start_ms':round((begin-started)*1000),'end_ms':round((time.monotonic()-started)*1000),'result':r})
            stop.wait(.05)
    try:
        pre=rest('GET','system/resource');assert pre['board-name'].startswith('CHR ')
        result['before_resource']=pre
        result['before_up']=wait(True)
        result['before_lease']=lease();assert len(result['before_lease'])==1 and result['before_lease'][0]['dynamic']=='true'
        c=next(r for r in rest('GET','container') if r['name']=='mc-gateway-phase6')
        assert c['start-on-boot']=='false'
        scheduler=next(r for r in rest('GET','system/scheduler') if r['name']=='mc-lab-boot-direct')
        assert scheduler['disabled']=='true','Scheduler must be disabled for independent boot proof'
        result['scheduler_disabled']=scheduler['disabled']
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=3)
        try:
            futures=[pool.submit(worker,k) for k in samples]
            time.sleep(2)
            result['trigger_ms']=round((time.monotonic()-started)*1000)
            print('REBOOT_TRIGGER',result['trigger_ms'],flush=True)
            try:rest('POST','system/reboot',{})
            except Exception as e:
                result['reboot_reply']=str(e)
                print('REBOOT_REPLY',str(e),flush=True)
            deadline=time.monotonic()+60
            saw_unavailable=False
            while time.monotonic()<deadline:
                try:
                    resource=rest('GET','system/resource')
                    # Uptime in the same native kernel must have reset.
                    if saw_unavailable and uptime_seconds(resource['uptime']) < uptime_seconds(pre['uptime']):
                        result['after_resource']=resource
                        result['first_management_ms']=round((time.monotonic()-started)*1000)
                        break
                except Exception:saw_unavailable=True
                time.sleep(.2)
            else:
                stop.set()
                raise AssertionError('No observed management outage/recovery')
            result['after_lease']=lease()
            if result['after_lease']:
                stop.set()
                raise AssertionError('Readiness lease survived reboot')
            time.sleep(4)
            stop.set()
            for f in futures:f.result()
        finally:
            stop.set()
            pool.shutdown(wait=True)
        result['samples']=samples
        result['first_after_outage']={}
        for kind,rows in samples.items():
            errors=[i for i,r in enumerate(rows) if r['start_ms']>=result['trigger_ms'] and r['result'].get('error')]
            assert errors,(kind,'no observed outage')
            following=[r for r in rows[errors[0]+1:] if not r['result'].get('error')]
            assert following,(kind,'no recovery')
            first=following[0];result['first_after_outage'][kind]=first
            if kind!='udp':assert first['result']['proxy_seen_ip']=='10.77.0.1',first
            if kind=='dns':assert first['result']['resolved_ipv4']=='10.77.0.20',first
        rest('POST','container/start',{'numbers':c['.id']})
        result['admitted_up']=wait(True)
        result['restored_generation']=gateway(path='/diagnostics/generation')
        r=probe('http',999999);assert not r.get('error') and r['proxy_seen_ip']=='10.77.0.10',r
        result['restored_proxy']=r
        result['completed']=True
    except Exception as e:
        result['error']=str(e);raise
    finally:
        stop.set();result['samples']=samples
        (ROOT/'.cache/dataplane/boot-lease-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
