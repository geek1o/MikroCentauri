#!/usr/bin/env python3
"""Install/verify isolated user FastTrack fixture plus exact managed exceptions."""
import json
import time
import urllib.request
from chr_dataplane import ROOT, rest, request, assert_success

if __name__=='__main__':
    assert rest('GET','system/resource')['board-name'].startswith('CHR ')
    filters=rest('GET','ip/firewall/filter')
    if any(f.get('comment')=='disposable-user-fasttrack' for f in filters):
        raise SystemExit('Fixture exists: inspect it instead of installing duplicates')
    ft=rest('PUT','ip/firewall/filter',{'chain':'forward','action':'fasttrack-connection','connection-state':'established,related','comment':'disposable-user-fasttrack'})
    rest('PUT','ip/firewall/filter',{'chain':'forward','action':'accept','connection-state':'established,related','comment':'disposable-user-established'})
    rest('PUT','ip/firewall/filter',{'chain':'forward','action':'accept','connection-mark':'mc-lab-selected','connection-state':'established,related','place-before':ft['.id'],'comment':'mikrocentauri:lab:filter:no-fasttrack'})
    routing=next(m for m in rest('GET','ip/firewall/mangle') if m.get('comment')=='mikrocentauri:lab:mangle:realip')
    rest('PUT','ip/firewall/mangle',{'chain':'prerouting','in-interface':'bridge-lan','dst-address-list':'mc-lab-domains','connection-state':'new','action':'mark-connection','new-connection-mark':'mc-lab-selected','passthrough':'true','place-before':routing['.id'],'comment':'mikrocentauri:lab:mangle:connection-mark'})
    time.sleep(1)
    selected=request('selected.test',path='/with-fasttrack');assert_success(selected,'10.77.0.10')
    body={'domain':'unselected.test','address':'203.0.113.20','path':'/direct-fasttrack'}
    req=urllib.request.Request('http://127.0.0.1:19010/request',data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=16) as response:direct=json.load(response)
    assert_success(direct,'203.0.113.1')
    filters=rest('GET','ip/firewall/filter');connections=rest('GET','ip/firewall/connection')
    result={'selected':selected,'direct':direct,'filters':filters,'lab_connections':[c for c in connections if c.get('src-address')=='192.168.88.10' and c.get('dst-port')=='8080']}
    assert int(next(f for f in filters if f.get('comment')=='disposable-user-fasttrack')['packets'])>0
    assert int(next(f for f in filters if f.get('comment')=='mikrocentauri:lab:filter:no-fasttrack')['packets'])>0
    (ROOT/'.cache/dataplane/fasttrack-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
