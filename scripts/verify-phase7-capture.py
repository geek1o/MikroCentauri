#!/usr/bin/env python3
"""Bind scoped IPv6 bypass/guard observations to exact-run LAN/WAN PCAP."""
import argparse
import json
import pathlib


def verify(report, captures):
    assert report.get('accepted') and report.get('completed') and report['hardening'].get('completed')
    v6 = report['hardening']['ipv6']
    lan = next(c for c in captures if c['file']=='lan.pcap')
    wan = next(c for c in captures if c['file']=='wan.pcap')
    witnesses=[]
    for record in v6['literal_bypass']+[v6['after_guard_removed']]:
        assert record['result']['remote_ip']==record['source']
        matches=[]
        for capture in (lan,wan):
            rows=[p for p in capture['ipv6_fixture_tcp'] if p['marker']==record['marker']
                  and p['source']==record['source'] and p['destination']=='fd7a:7:2::20' and p['destination_port']==8087]
            assert rows, 'Missing IPv6 marker '+record['marker']+' on '+capture['file']
            matches.append(rows[0])
        witnesses.append({'marker':record['marker'],'lan_packet':matches[0],'wan_packet':matches[1]})
    start,end=v6['blocked_window_epoch']
    assert 0<end-start<20 and v6['guard_packets']>0 and v6['operator_scoped_guard']['result'].get('error')
    def attempts(capture):
        return [p for p in capture['ipv6_fixture_tcp'] if start<=p['time_utc_epoch']<=end
                and p['source']=='fd7a:7:1::30' and p['destination']=='fd7a:7:2::20'
                and p['destination_port']==8087 and p['syn']]
    ingress=attempts(lan); egress=attempts(wan)
    assert ingress and not egress, 'Scoped guard did not contain IPv6 SYN forwarding'
    return {'run_id':report['run_id'],'lan_sha256':lan['sha256'],'wan_sha256':wan['sha256'],
            'bypass_and_guard_removal_witnesses':witnesses,'guard_lan_syn':ingress,'guard_wan_syn':egress,
            'blocked_window_epoch':[start,end],
            'scope':'fixed literal IPv6 target and operator scoped guard only; alternate DNS/DoH enforcement not established'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results',required=True,type=pathlib.Path)
    p.add_argument('--captures',required=True,type=pathlib.Path)
    p.add_argument('--out',required=True,type=pathlib.Path)
    a=p.parse_args()
    result=verify(json.loads(a.results.read_text()),json.loads(a.captures.read_text()))
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('Verified IPv6 bypass, scoped guard SYN containment and restored reachability')
