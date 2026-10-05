#!/usr/bin/env python3
"""Bound-domain policy through native CHR TUN; explicit disposable lab only."""
import json
import urllib.request
from chr_dataplane import ROOT, rest, assert_success, gateway
from chr_dynamic_publication import wait
from chr_protocols import quic


def workload(host, source='', domain='second.test', address='198.18.0.3'):
    q=urllib.request.Request('http://127.0.0.1:19010/request',data=json.dumps({
        'domain':domain,'address':address,'skip_dns':True,'source':source,
        'host':host,'path':'/phase6-bound-domain'}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(q,timeout=16) as r:return json.load(r)


if __name__=='__main__':
    result={}
    try:
        assert rest('GET','system/resource')['board-name'].startswith('CHR ')
        result['up']=wait(True)
        result['generation']=gateway(path='/diagnostics/generation')
        assert result['generation']['admission']['admitted']
        result['host']={}
        for host in ['second.test','SECOND.TEST','SeCoNd.TeSt.','unselected.test','198.18.0.3']:
            r=workload(host);assert_success(r,'10.77.0.10');result['host'][host]=r
        result['sni']={}
        for name in ['second.test','SECOND.TEST','SeCoNd.TeSt.','unselected.test']:
            r=quic(name,'198.18.0.3');assert not r.get('error') and r['remote_ip']=='10.77.0.10',r
            result['sni'][name]=r
        result['devices']={}
        for source,peer in [('192.168.88.30','10.77.0.1'),('192.168.88.20','10.77.0.10')]:
            r=workload('unselected.test',source);assert_success(r,peer)
            h3=quic('unselected.test','198.18.0.3',source)
            assert not h3.get('error') and h3['remote_ip']==peer,h3
            result['devices'][source]={'http':r,'http3':h3}
        result['real_ip']={}
        # Real IPv4 bypasses the hybrid FakeIP TUN route on this topology.
        for host,peer in [('selected.test','10.77.0.1'),('unselected.test','10.77.0.1')]:
            r=workload(host,domain=host,address='10.77.0.20');assert_success(r,peer)
            result['real_ip'][host]=r
        result['completed']=True
    except Exception as e:
        result['error']=str(e);raise
    finally:
        (ROOT/'.cache/dataplane/binding-policy-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
