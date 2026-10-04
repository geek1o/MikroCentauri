#!/usr/bin/env python3
"""Corrupt only the disposable pinned map; UP must refuse and restoration is explicit."""
import json
from chr_dataplane import ROOT, rest
from chr_cached_fallback import COMMENTS, wait_state

if __name__ == '__main__':
    wait_state(True)
    watch = next(r for r in rest('GET', 'tool/netwatch')
                 if r.get('comment') == 'mikrocentauri:lab:netwatch:readiness')
    fallback = next(r for r in rest('GET', 'ip/firewall/nat')
                    if r.get('comment') == 'mikrocentauri:lab:nat:cached-selected')
    assert fallback['to-addresses'] == '10.77.0.20'
    rest('PATCH', 'tool/netwatch/'+watch['.id'], {'disabled': 'true'})
    try:
        rest('PATCH', 'ip/firewall/nat/'+fallback['.id'], {'to-addresses': '10.77.0.99'})
        try:
            rest('POST', 'system/script/run', {'number': 'mc-lab-up'})
            raise AssertionError('Malformed map accepted')
        except RuntimeError as error:
            assert 'MC_LAB_FALLBACK_INVALID' in str(error), error
        rows = rest('GET', 'ip/route') + rest('GET', 'ip/firewall/nat')
        flags = {r['comment']: r.get('disabled', 'false') for r in rows if r.get('comment') in COMMENTS}
        assert len(flags) == 4 and set(flags.values()) == {'true'}, flags
        result = {'malformed_mapping_up_refused': True, 'disabled': flags}
        (ROOT/'.cache/dataplane/mapping-invalid-results.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))
    finally:
        rest('PATCH', 'ip/firewall/nat/'+fallback['.id'], {'to-addresses': '10.77.0.20'})
        rest('POST', 'system/script/run', {'number': 'mc-lab-down'})
        rest('PATCH', 'tool/netwatch/'+watch['.id'], {'disabled': 'false'})
    wait_state(True)
