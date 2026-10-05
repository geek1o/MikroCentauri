#!/usr/bin/env python3
"""Fixed-namespace generation admission; only the isolated localhost CHR fixture."""
import argparse
import json
import time
from chr_dataplane import ROOT, rest, request, assert_success, gateway
from chr_dynamic_publication import wait, maps
from chr_target_refresh import cached
from chr_protocols import quic


def diagnostic():
    return gateway(path='/diagnostics/generation')


def control(action):
    return gateway(method='post',path='/control/'+action)


def traffic(bindings, peer):
    out = {}
    for b in bindings:
        name,alias=b['domain'],b['alias']
        tcp,udp,h3=cached(name,alias),cached(name,alias,True),quic(name,alias)
        assert_success(tcp,peer)
        assert_success(udp)
        assert h3['remote_ip']==peer,h3
        out[name]={'tcp':tcp,'udp':udp,'http3':h3}
    return out


if __name__=='__main__':
    args=argparse.ArgumentParser()
    args.add_argument('scenario',choices=['healthy','missing','mismatch','recovered'])
    scenario=args.parse_args().scenario
    assert rest('GET','system/resource')['board-name'].startswith('CHR ')
    c=next(c for c in rest('GET','container') if c['name']=='mc-gateway-phase5')
    result={'scenario':scenario}
    prior=ROOT/'.cache/dataplane/generation-healthy-results.json'
    bindings=None
    try:
        if scenario=='healthy':
            result['up']=wait(True)
            result['admitted']=diagnostic()
            bindings=result['admitted']['admission']['bindings']
            assert result['admitted']['admission']['admitted'] and len(bindings)==3,result
            assert 'dev mc-tun' in result['admitted']['ingress_route'],result
            result['canonical_queries']={}
            aliases={b['domain']:b['alias'] for b in bindings}
            for name in ('second.test','SECOND.TEST','SeCoNd.TeSt.'):
                rest('POST','ip/dns/cache/flush',{})
                # UDP isolates DNS casing from HTTP Host sniffing. HTTP Host
                # normalization belongs to the separate routing-policy gate.
                r=request(name,udp=True)
                assert_success(r)
                assert r['resolved_ipv4']==aliases['second.test'],r
                result['canonical_queries'][name]=r
            assert len(maps())==3,maps()
            result['proxy']=traffic(bindings,'10.77.0.10')
            rest('POST','container/stop',{'numbers':c['.id']})
            result['container_down']=wait(False)
            result['direct']=traffic(bindings,'10.77.0.1')
            rest('POST','container/start',{'numbers':c['.id']})
            result['container_up']=wait(True)
            result['restart_admitted']=diagnostic()
            assert result['restart_admitted']['admission']['bindings']==bindings,result
            result['restored_proxy']=traffic(bindings,'10.77.0.10')
            control('stop')
            result['stopped']=wait(False)
        else:
            bindings=json.loads(prior.read_text())['admitted']['admission']['bindings']
            try:
                control('start')
                assert scenario=='recovered','unsafe generation accepted'
            except RuntimeError as e:
                if scenario=='recovered':raise
                result['start_denied']=str(e)
            if scenario=='recovered':
                result['up']=wait(True)
                result['admitted']=diagnostic()
                assert result['admitted']['admission']['bindings']==bindings,result
                result['proxy']=traffic(bindings,'10.77.0.10')
                control('stop')
                result['stopped']=wait(False)
            else:
                result['down']=wait(False)
                result['denied']=diagnostic()
                assert not result['denied']['admission']['admitted'],result
                assert not result['denied']['engine_running'],result
                assert 'blackhole default' in result['denied']['ingress_route'],result
                result['direct']=traffic(bindings,'10.77.0.1')
                # Deliberately simulate a stale native UP route: the Linux barrier
                # still prevents cached aliases from reaching any proxy engine.
                rest('POST','system/script/run',{'number':'mc-lab-up'})
                time.sleep(1)
                blocked=cached('second.test',next(b['alias'] for b in bindings if b['domain']=='second.test'))
                assert blocked.get('error'),blocked
                result['forced_up_cached_blocked']=blocked
                rest('POST','ip/dns/cache/flush',{})
                denied=request('second.test')
                assert denied.get('error') and not denied.get('resolved_ipv4'),denied
                result['unadmitted_dns_denied']=denied
                result['dns_diagnostics']=gateway(path='/diagnostics/dns')
                rest('POST','system/script/run',{'number':'mc-lab-down'})
        result['completed']=True
    except Exception as e:
        result['error']=str(e)
        raise
    finally:
        rest('POST','system/script/run',{'number':'mc-lab-down'})
        (ROOT/f'.cache/dataplane/generation-{scenario}-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
