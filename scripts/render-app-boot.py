#!/usr/bin/env python3
"""Render an operator-reviewed, digest-bound RouterOS App startup scheduler.

No RouterOS writes. Install after protected provisioning/identity review; replace
or disable before image changes. Disabled Apps are never enabled by this script.
"""
import argparse
import json
import pathlib
import re


def render(app, container, digest):
    for name in (app,container):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',name):
            raise ValueError('literal reviewed App/container names required')
    if not re.fullmatch(r'[0-9a-f]{64}',digest):
        raise ValueError('exact reviewed OCI config digest without sha256 prefix required')
    source=(f':delay 5s; :local appId [/app find where name="{app}"]; '
        ':if ([:len $appId] != 1) do={:error "MikroCentauri boot App identity differs"}; '
        ':if ([/app get $appId disabled] = false) do={'
        f':local coreId [/container find where name="{container}"]; '
        ':if ([:len $coreId] != 1) do={:error "MikroCentauri boot container identity differs"}; '
        f':if ([/container get $coreId image-id] != "{digest}") do={{:error "MikroCentauri boot image differs"}}; '
        '/app disable $appId; :local waited 0; '
        ':while ([/container get $coreId stopped] != true) do={'
        ':if ($waited >= 60) do={:error "MikroCentauri boot stop timeout"}; '
        ':delay 1s; :set waited ($waited + 1)}; '
        f':if ([/container get $coreId image-id] != "{digest}") do={{:error "MikroCentauri boot image changed"}}; '
        '/app enable $appId}')
    return {'name':'mc-app-boot-'+app,'comment':'mikrocentauri:operator:app-boot:'+app,
            'start-time':'startup','interval':'0s','disabled':'false','policy':'read,write,policy,test',
            'on-event':source}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app',required=True);p.add_argument('--container',required=True)
    p.add_argument('--config-sha256',required=True);p.add_argument('--out',required=True,type=pathlib.Path)
    a=p.parse_args();result=render(a.app,a.container,a.config_sha256)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('Rendered digest-bound operator scheduler; review and installation remain explicit')
