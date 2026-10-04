#!/usr/bin/env python3
"""TCG fixture-transfer diagnostics; never hardware throughput claims."""
import json
import time
from chr_dataplane import ROOT, rest, request, assert_success, set_owned


def run_batch(domain, egress, n=3):
    # One warmup, then actual fully read 256KiB transfers, including lookup/setup.
    assert_success(request(domain,path='/bench?bytes=262144'),egress)
    results=[]
    for _ in range(n):
        resource=rest('GET','system/resource')
        result=request(domain,path='/bench?bytes=262144')
        assert_success(result,egress);assert result['bytes']==262144,result
        result['end_to_end_mbps']=round(result['bytes']*8/max(1,result['elapsed_ms'])/1000,3)
        result['router_before']={k:resource[k] for k in ['cpu-load','free-memory','total-memory']}
        results.append(result)
    return results


def run():
    # Requires explicit disposable lab with both experimental watchdogs installed.
    for w in rest('GET','tool/netwatch'):
        if w.get('comment') in ['mikrocentauri:lab:netwatch:readiness','mikrocentauri:lab:netwatch:realip']:
            rest('PATCH','tool/netwatch/'+w['.id'],{'disabled':'true'})
    rest('POST','system/script/run',{'number':'mc-lab-real-down'})
    for dns in rest('GET','ip/dns/static'):
        if dns.get('comment')=='mikrocentauri:lab:dns:selected-real':rest('PATCH','ip/dns/static/'+dns['.id'],{'disabled':'true'})
    set_owned(False);rest('POST','ip/dns/cache/flush',{})
    result={'environment':'QEMU TCG x86 on macOS arm64; 3 samples/mode, IPv4 HTTP, no load/loss or hardware conclusions'}
    result['native_direct']=run_batch('unselected.test','10.77.0.1')
    set_owned(True)
    result['hybrid_direct']=run_batch('unselected.test','10.77.0.1')
    result['hybrid_proxy']=run_batch('selected.test','10.77.0.10')
    route=rest('PUT','ip/route',{'dst-address':'0.0.0.0/0','gateway':'172.30.0.2@main','routing-table':'mc-lab-full','comment':'mikrocentauri:lab:route:benchmark-full'})
    mark=rest('PUT','ip/firewall/mangle',{'chain':'prerouting','in-interface':'bridge-lan','dst-address':'10.77.0.20','action':'mark-routing','new-routing-mark':'mc-lab-full','passthrough':'false','comment':'mikrocentauri:lab:mangle:benchmark-full'})
    connection=rest('PUT','ip/firewall/mangle',{'chain':'prerouting','in-interface':'bridge-lan','dst-address':'10.77.0.20','connection-state':'new','action':'mark-connection','new-connection-mark':'mc-lab-selected','passthrough':'true','place-before':mark['.id'],'comment':'mikrocentauri:lab:mangle:benchmark-connection'})
    try:
        time.sleep(1)
        result['full_fixture_direct']=run_batch('unselected.test','10.77.0.1')
        result['full_fixture_proxy']=run_batch('selected.test','10.77.0.10')
    finally:
        rest('DELETE','ip/firewall/mangle/'+connection['.id']);rest('DELETE','ip/firewall/mangle/'+mark['.id']);rest('DELETE','ip/route/'+route['.id'])
        set_owned(False)
    return result

if __name__=='__main__':
    result=run();(ROOT/'.cache/dataplane/benchmark-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
