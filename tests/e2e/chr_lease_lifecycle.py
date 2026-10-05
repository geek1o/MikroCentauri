#!/usr/bin/env python3
"""RAM readiness lease expiry and invalid-token rejection on isolated CHR."""
import json
import time
from chr_dataplane import ROOT, rest, request, assert_success
from chr_dynamic_publication import wait
from chr_binding_policy import workload
from chr_protocols import quic


def leases():
    return [r for r in rest('GET','ip/firewall/address-list') if r.get('list')=='mc-lab-up-lease']


def wait_empty(timeout=20):
    start=time.monotonic()
    while time.monotonic()-start < timeout:
        if not leases():return round((time.monotonic()-start)*1000)
        time.sleep(.1)
    raise AssertionError('Lease did not expire/revoke')


if __name__=='__main__':
    result={}
    watch=next(r for r in rest('GET','tool/netwatch') if r.get('comment')=='mikrocentauri:lab:netwatch:readiness')
    try:
        assert rest('GET','system/resource')['board-name'].startswith('CHR ')
        result['before']=wait(True)
        result['lease_before']=leases()
        rest('PATCH','tool/netwatch/'+watch['.id'],{'disabled':'true'})
        result['lease_immediately_after_monitor_stop']=leases()
        assert result['lease_immediately_after_monitor_stop'],'Expected token to survive until timeout; no DOWN script executed'
        result['expiry_observed_ms']=wait_empty()
        result['cached_direct']=workload('unselected.test');assert_success(result['cached_direct'],'10.77.0.1')
        result['cached_http3_direct']=quic('unselected.test','198.18.0.3');assert result['cached_http3_direct']['remote_ip']=='10.77.0.1'
        rest('POST','ip/dns/cache/flush',{})
        result['new_dns_direct']=request('second.test');assert_success(result['new_dns_direct'],'10.77.0.1')
        assert result['new_dns_direct']['resolved_ipv4']=='10.77.0.20'
        rest('PATCH','tool/netwatch/'+watch['.id'],{'disabled':'false'})
        result['restored']=wait(True)
        # Keep probes active but suspend automatic mutation for exact fault tests.
        rest('PATCH','tool/netwatch/'+watch['.id'],{'test-script':'','up-script':''})
        deadline=time.monotonic()+20
        while rest('GET','tool/netwatch')[0]['status']!='up':
            if time.monotonic()>deadline:raise AssertionError('Probe not UP')
            time.sleep(.2)
        result['invalid']={}
        for kind in ['static','duplicate']:
            rest('POST','system/script/run',{'number':'mc-lab-down'})
            if kind=='duplicate':
                rest('POST','system/script/run',{'number':'mc-lab-up'})
                row={'list':'mc-lab-up-lease','address':'192.168.88.10','timeout':'6s','comment':'mikrocentauri:lab:lease:conflict'}
            else:row={'list':'mc-lab-up-lease','address':'192.168.88.0/24','comment':'mikrocentauri:lab:lease:up'}
            rest('PUT','ip/firewall/address-list',row)
            before=leases()
            try:
                rest('POST','system/script/run',{'number':'mc-lab-up'})
                raise AssertionError('Invalid token accepted')
            except RuntimeError as e:denied=str(e)
            assert not leases(),'Invalid list survived validation'
            result['invalid'][kind]={'before':before,'denied':denied,'after':leases()}
        # An unrelated HTTP200 endpoint must never renew readiness.
        rest('PATCH','tool/netwatch/'+watch['.id'],{'host':'10.77.0.20','port':'8080'})
        deadline=time.monotonic()+20
        while rest('GET','tool/netwatch')[0]['status']!='up':
            if time.monotonic()>deadline:raise AssertionError('Wrong-target probe not UP')
            time.sleep(.2)
        try:
            rest('POST','system/script/run',{'number':'mc-lab-up'})
            raise AssertionError('Changed readiness target accepted')
        except RuntimeError as e:result['wrong_watch_denied']=str(e)
        assert not leases()
        result['completed']=True
    except Exception as e:
        result['error']=str(e);raise
    finally:
        rest('POST','system/script/run',{'number':'mc-lab-down'})
        rest('PATCH','tool/netwatch/'+watch['.id'],{'host':'172.30.0.2','port':'9099','disabled':'false','test-script':'/system/script/run mc-lab-lease-refresh','up-script':'/system/script/run mc-lab-up'})
        (ROOT/'.cache/dataplane/lease-lifecycle-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
