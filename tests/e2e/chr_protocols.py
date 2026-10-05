#!/usr/bin/env python3
"""HTTP/3 control runner for the prepared Linux VM forward (localhost19110)."""
import json
import urllib.request
from chr_dataplane import ROOT, request, assert_success


def quic(domain, address, source=""):
    req=urllib.request.Request('http://127.0.0.1:19110/request',
        data=json.dumps({'domain':domain,'address':address,'source':source}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=16) as response:result=json.load(response)
    assert not result.get('error'),result
    assert result['protocol']=='HTTP/3.0',result
    return result

if __name__=='__main__':
    # Hybrid/FakeIP must be active; this test does not mutate routing mode.
    selected=request('selected.test');assert_success(selected,'10.77.0.10')
    direct=request('unselected.test');assert_success(direct,'10.77.0.1')
    selected_quic=quic('selected.test',selected['resolved_ipv4'])
    direct_quic=quic('unselected.test',direct['resolved_ipv4'])
    assert selected_quic['remote_ip']=='10.77.0.10',selected_quic
    assert direct_quic['remote_ip']=='10.77.0.1',direct_quic
    result={'selected':selected_quic,'direct':direct_quic}
    (ROOT/'.cache/dataplane/quic-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
