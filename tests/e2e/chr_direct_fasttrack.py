#!/usr/bin/env python3
"""Specific DIRECT conntrack proof on the disposable Phase 7 clone."""
import base64
import json
import pathlib
import time
import urllib.request
from chr_dataplane import assert_success
from chr_app_hardening import control


def run():
    def native(method,path,body=None):
        req=urllib.request.Request('http://127.0.0.1:18336/rest/'+path,method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization':'Basic '+base64.b64encode(b'admin:').decode(),'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=30) as response:return json.load(response)
    resource=native('GET','system/resource')
    assert resource['version']=='7.24.5 (stable)' and resource['board-name'].startswith('CHR ')
    fixture=next(r for r in native('GET','ip/firewall/filter') if r.get('comment')=='disposable-user-fasttrack')
    from chr_app_hardening import direct_fasttrack
    return direct_fasttrack(native,fixture['.id'])

if __name__=='__main__':
    proof=run()
    pathlib.Path('.cache/phase7-hardening/direct-fasttrack.json').write_text(json.dumps(proof,indent=2)+'\n')
    print('DIRECT specific conntrack fasttrack=false/true verified')
