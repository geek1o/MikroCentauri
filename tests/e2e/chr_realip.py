#!/usr/bin/env python3
"""Real-IP alternative: cached real destination survives engine failure."""
import json
import time
from chr_dataplane import ROOT, rest, gateway, request, assert_success

COMMENTS = {'mikrocentauri:lab:route:realip','mikrocentauri:lab:mangle:realip'}

def flags():
    return {r['comment']: r.get('disabled','false') == 'true'
            for r in rest('GET','ip/route') + rest('GET','ip/firewall/mangle') if r.get('comment') in COMMENTS}

def wait_state(disabled, start):
    while time.monotonic()-start < 15:
        state = flags()
        watch = next(w for w in rest('GET','tool/netwatch') if w.get('comment')=='mikrocentauri:lab:netwatch:realip')
        if len(state)==2 and all(v==disabled for v in state.values()) and watch['status']==('down' if disabled else 'up'):
            time.sleep(1)
            return round((time.monotonic()-start)*1000)
        time.sleep(.1)
    raise AssertionError('Real-IP watchdog timeout')

def run():
    healthy = request('selected.test',path='/realip-healthy'); assert_success(healthy,'10.77.0.10')
    assert healthy['resolved_ipv4']=='10.77.0.20'
    cohost=request('unselected.test',path='/realip-cohost');assert_success(cohost,'10.77.0.1')
    direct_priority=request('selected.test','192.168.88.30',path='/realip-direct-priority');assert_success(direct_priority,'10.77.0.1')
    started=time.monotonic();gateway('post','/control/stop');down_ms=wait_state(True,started)
    cached=request(healthy['resolved_ipv4'],path='/cached-realip-during-failure');assert_success(cached,'10.77.0.1')
    fresh=request('selected.test',path='/realip-fresh-during-failure');assert_success(fresh,'10.77.0.1')
    started=time.monotonic();gateway('post','/control/start');up_ms=wait_state(False,started)
    recovered=request('selected.test',path='/realip-recovered');assert_success(recovered,'10.77.0.10')
    return {'healthy':healthy,'cohost_sniff_direct':cohost,'direct_priority':direct_priority,
            'engine_down_ms':down_ms,'cached_real_destination':cached,'fresh_dns':fresh,
            'engine_up_ms':up_ms,'recovered':recovered,
            'scope':'IPv4 HTTP lab only; shared-IP generic UDP, TTL expiry and ECH remain limitations'}

if __name__=='__main__':
    result=run();(ROOT/'.cache/dataplane/realip-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
