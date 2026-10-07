"""Phase 7 acceptance extension: disposable pinned App/CHR/Linux fixtures only."""
import concurrent.futures
import datetime
import json
import importlib.util
import pathlib
import re
import subprocess
import time
import urllib.request
from chr_dataplane import request, assert_success
from chr_protocols import quic
from chr_boot_lease import uptime_seconds


def control(port, path, body):
    req = urllib.request.Request(f'http://127.0.0.1:{port}/{path}', data=json.dumps(body).encode(),
                                headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as response: return json.load(response)


def direct_fasttrack(native, ft_id):
    original=native('GET','ip/firewall/filter/'+ft_id).get('disabled','false')
    result={}
    try:
        for enabled in (False,True):
            native('PATCH','ip/firewall/filter/'+ft_id,{'disabled':str(not enabled).lower()});time.sleep(1)
            before={r['.id'] for r in native('GET','ip/firewall/connection')}
            observed=[]
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                transfer=pool.submit(control,19010,'request',{'domain':'unselected.test','address':'10.77.0.20',
                    'skip_dns':True,'path':'/bench?bytes=524288'})
                while True:
                    observed.extend(r for r in native('GET','ip/firewall/connection') if r['.id'] not in before
                        and r.get('src-address')=='192.168.88.10' and r.get('dst-address')=='10.77.0.20'
                        and r.get('dst-port')=='8080' and r.get('seen-reply')=='true')
                    if transfer.done():break
                    time.sleep(.02)
                value=transfer.result();assert_success(value,'10.77.0.1');assert value['bytes']==524288
            matching=[r for r in observed if r.get('fasttrack')==str(enabled).lower()]
            assert matching, 'No specific DIRECT fasttrack='+str(enabled)+' connection witness'
            assert len({r['src-port'] for r in observed})==1,'Ambiguous DIRECT transfer'
            row={k:matching[0][k] for k in ('.id','src-address','dst-address','src-port','dst-port','fasttrack')}
            result[str(enabled)]={'connection':row,'transfer':value}
    finally:native('PATCH','ip/firewall/filter/'+ft_id,{'disabled':original})
    return result


def run(*, native, api, settle, ready, core, stopped, app_id, ip, baseline, work,
        name, marked_udp, relogin):
    print('HARDENING_START', flush=True)
    report = {'scope': 'pinned CHR/App; controlled failures; new flows only', 'forwarding': []}
    sequence = str(time.time_ns())
    original_ft = next(r for r in native('GET', 'ip/firewall/filter')
                       if r.get('comment') == 'disposable-user-fasttrack')
    report['watchdog_profile'] = [{k:r[k] for k in ('interval','timeout','type','port','http-codes') if k in r}
        for r in native('GET','tool/netwatch') if r.get('comment')=='mikrocentauri:app6:netwatch:readiness']
    ft_id = original_ft['.id']
    ft_counter = lambda: int(next(r for r in native('GET', 'ip/firewall/filter') if r['.id'] == ft_id).get('packets', '0'))
    def lease(): return [r for r in native('GET', 'ip/firewall/address-list') if r.get('list') == 'mc-app6-up-lease']
    def down():
        targets = [r for path in ('ip/route','ip/firewall/nat') for r in native('GET',path)
            if r.get('comment') in ('mikrocentauri:app6:route:fakeip','mikrocentauri:app6:nat:dns-tcp','mikrocentauri:app6:nat:dns-udp')]
        return not lease() and len(targets)==3 and all(r.get('disabled')=='true' for r in targets)
    def observed(label, alias=baseline, peer='10.77.0.10', source='', domain='selected.test'):
        tcp = control(19010, 'request', {'domain': domain, 'address': alias, 'skip_dns': True,
            'source': source, 'host': 'unselected.test', 'path': '/phase7-' + label})
        if tcp.get('error') or tcp.get('proxy_seen_ip')!=peer:
            report['failed_observation']={'stage':label,'tcp':tcp,'ready_after':ready(),
                'lease_after':lease(),'system':api('GET','/system'),'logs':api('GET','/logs'),'watchdog_after':[{k:r[k] for k in ('status','interval','timeout') if k in r}
                    for r in native('GET','tool/netwatch') if r.get('comment')=='mikrocentauri:app6:netwatch:readiness']}
            (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        assert_success(tcp, peer)
        h3 = quic('unselected.test', alias, source); assert h3['remote_ip'] == peer, h3
        udp = marked_udp(domain, source=source, address=alias)
        item = {'stage': label, 'source': source or '192.168.88.10', 'expected_peer': peer,
                'tcp': tcp, 'http3': h3, 'udp': udp}
        report['forwarding'].append(item)
        return label
    def recovered(label):
        def authenticated_ready():
            status, value = api('GET','/health/ready')
            if status==401:
                report.setdefault('session_refreshes',[]).append({'stage':label,'old_status':401})
                if not relogin():return False
                status,value=api('GET','/health/ready')
            return status==200 and value.get('ready')
        try: settle(authenticated_ready, label + ' readiness')
        except AssertionError:
            report['failed_recovery']={'stage':label,'system':api('GET','/system'),
                'logs':api('GET','/logs'),'native_rows':{path:[r for r in native('GET',path)
                    if r.get('comment','').startswith('mikrocentauri:app6:')]
                    for path in ('ip/route','ip/firewall/nat','tool/netwatch','system/scheduler','ip/firewall/address-list')}}
            (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
            raise
        settle(lambda: bool(lease()), label + ' lease')
        assert all(r.get('dynamic') == 'true' for r in lease())
        time.sleep(1)
        return observed(label)
    def ssh(command):
        result = subprocess.run(['ssh', '-p', '22336', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(work / 'private/known_hosts'),
            'admin+ct@127.0.0.1', '/container/shell app-' + name + ' cmd="' + command + '"'],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result.stdout.decode())
    def engine_pid():
        output = ssh('/bin/pidof sing-box')
        lines = [line.strip() for line in output.splitlines() if re.fullmatch(r'[0-9 ]+', line.strip())]
        assert len(lines) == 1 and len(lines[0].split()) == 1, 'ambiguous engine PID'
        return int(lines[0])
    def resource_sample():
        owner = ssh('/bin/cat /proc/1/status'); pid = engine_pid(); engine = ssh('/bin/cat /proc/' + str(pid) + '/status')
        def memory(text):
            return {k: int(v) for k, v in re.findall(r'^(VmRSS|VmSwap):\s+([0-9]+) kB', text, re.M)}
        return {'router': {k: native('GET', 'system/resource')[k] for k in ('free-memory','cpu-load')},
                'owner_kib': memory(owner), 'engine_kib': memory(engine)}
    temporary = []
    try:
        # The native user FastTrack stays installed; explicit ON/OFF experiments.
        alias_attempts=[]
        def second_query():
            result=request('second.test',path='/phase7-second-binding')
            alias_attempts.append(result)
            if result.get('error'): return None
            assert_success(result,'10.77.0.1')
            return result
        second=settle(second_query,'verified second-domain publication',45)
        report['new_alias_attempts']=alias_attempts
        second_alias = second['resolved_ipv4']; assert second_alias.startswith('198.19.')
        ft_results = {}
        for enabled in (False, True):
            native('PATCH', 'ip/firewall/filter/' + ft_id, {'disabled': str(not enabled).lower()})
            time.sleep(1)
            count_before = ft_counter()
            direct = request('unselected.test', path='/bench?bytes=262144'); assert_success(direct, '10.77.0.1')
            assert direct['bytes'] == 262144
            count_after = ft_counter()
            if enabled: assert count_after > count_before, 'DIRECT did not exercise user FastTrack'
            stages = []
            for label, alias, peer, source, domain in [
                ('selected', baseline, '10.77.0.10', '', 'selected.test'),
                ('native-direct', direct['resolved_ipv4'], '10.77.0.1', '', 'unselected.test'),
                ('bound-direct', second_alias, '10.77.0.1', '', 'second.test'),
                ('source-proxy', second_alias, '10.77.0.10', '192.168.88.20', 'second.test'),
                ('source-direct', baseline, '10.77.0.1', '192.168.88.30', 'selected.test')]:
                stages.append(observed(('ft-on-' if enabled else 'ft-off-') + label, alias, peer, source, domain))
            ft_results[str(enabled)] = {'counter_before_direct': count_before, 'counter_after_direct': count_after,
                'direct_bytes': direct['bytes'], 'stages': stages}
        report['direct_fasttrack_connections'] = direct_fasttrack(native, ft_id)
        report['fasttrack'] = ft_results
        print('FASTTRACK_MATRIX_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')

        # Upstream now has real AAAA: suppression must come from the managed gate.
        control(19020, 'dns-fixture', {'target': '10.77.0.20', 'ttl': 5, 'ipv6_target': 'fd7a:7:2::20'})
        v6_objects = [
            ('ipv6/address', {'address': 'fd7a:7:1::1/64', 'interface': 'bridge-lan', 'advertise': 'false'}),
            ('ipv6/address', {'address': 'fd7a:7:2::1/64', 'interface': 'ether3', 'advertise': 'false'})]
        for path, fields in v6_objects:
            fields['comment'] = 'phase7-disposable-v6-' + sequence
            object_id = native('PUT', path, fields)['.id']; temporary.append((path, object_id))
        native('POST', 'ip/dns/cache/flush', {})
        dns = []
        for tcp in (False, True):
            for domain, server, kind, answers, rcode in [
                ('selected.test','10.77.0.20',28,1,0),
                ('selected.test','192.168.88.1',28,0,0),
                ('unselected.test','192.168.88.1',28,1,0),
                ('selected.test','192.168.88.1',64,0,2),
                ('selected.test','192.168.88.1',65,0,2)]:
                value = control(19010,'dns-query',{'domain':domain,'server':server,'type':kind,'tcp':tcp})
                assert not value.get('error') and value['answers']==answers and value['rcode']==rcode,value
                dns.append({'domain':domain,**value})
        for domain in ('selected.test','unselected.test'):
            result=request(domain,path='/phase7-dual-stack-v4');assert_success(result,'10.77.0.10' if domain=='selected.test' else '10.77.0.1')
        def v6(source, label):
            marker = '/phase7-v6-' + sequence + '-' + label
            result = control(19010,'ipv6-request',{'source':source,'path':marker})
            return {'source':source,'marker':marker,'result':result}
        bypass = [v6('fd7a:7:1::10','literal'),v6('fd7a:7:1::30','before-guard')]
        for value in bypass: assert value['result'].get('remote_ip') == value['source'], value
        guard = native('PUT','ipv6/firewall/filter',{'chain':'forward','action':'drop',
            'in-interface':'bridge-lan','src-address':'fd7a:7:1::30/128','dst-address':'fd7a:7:2::20/128',
            'protocol':'tcp','dst-port':'8087','comment':'phase7-disposable-v6-guard-' + sequence})['.id']
        temporary.append(('ipv6/firewall/filter',guard))
        began=time.time(); blocked=v6('fd7a:7:1::30','blocked'); ended=time.time()
        assert blocked['result'].get('error'),blocked
        counters=native('GET','ipv6/firewall/filter/'+guard);assert int(counters.get('packets','0'))>0
        native('DELETE','ipv6/firewall/filter/'+guard);temporary.remove(('ipv6/firewall/filter',guard))
        after=v6('fd7a:7:1::30','after-guard');assert after['result'].get('remote_ip')==after['source'],after
        report['ipv6']={'dns':dns,'literal_bypass':bypass,'operator_scoped_guard':blocked,
            'guard_packets':int(counters['packets']),'blocked_window_epoch':[began,ended],
            'after_guard_removed':after,'policy':'managed AAAA controlled; alternate/literal IPv6 bypass explicitly unsupported; optional operator guard only'}

        print('IPV6_MATRIX_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Persistent remote-proxy failure: HTTP/UDP targets remain alive for DIRECT.
        fault=control(19020,'proxy-control',{'action':'stop'});assert fault['pids']
        start=time.monotonic()
        try:
            settle(down,'proxy fault lease withdrawal',90)
            time.sleep(1)
            assert not ready(), 'failed proxy still advertises readiness'
            fallback=observed('proxy-fault-down',peer='10.77.0.1')
            native('POST','ip/dns/cache/flush',{})
            fresh=request('selected.test',path='/phase7-proxy-fault-fresh');assert_success(fresh,'10.77.0.1')
            assert fresh['resolved_ipv4']=='10.77.0.20'
            report['remote_proxy_failure']={'lease_withdraw_ms':round((time.monotonic()-start)*1000),'cached':fallback,'fresh':fresh}
        finally: control(19020,'proxy-control',{'action':'resume'})
        report['remote_proxy_failure']['recovered']=recovered('proxy-restored')

        print('PROXY_FAILURE_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Real engine SIGKILL, then automatic supervised recovery; parent stays alive.
        old_pid=engine_pid();ssh('/bin/kill -9 '+str(old_pid));saw_down=False;deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            if not ready(): saw_down=True
            try: new_pid=engine_pid()
            except (AssertionError,subprocess.SubprocessError): new_pid=old_pid
            if saw_down and new_pid!=old_pid and ready() and lease(): break
            time.sleep(.2)
        else: raise AssertionError('engine death/recovery not observed')
        report['engine_sigkill']={'old_pid':old_pid,'new_pid':new_pid,'unready_observed':saw_down,'recovered':recovered('engine-recovered')}

        print('ENGINE_SIGKILL_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Parent SIGKILL and native App restart, retaining namespace/private state.
        native('PATCH','container/'+core()['.id'],{'stop-signal':'9-SIGKILL'})
        native('PATCH','app/'+app_id,{'disabled':'true'});settle(stopped,'SIGKILL parent stop')
        settle(down,'SIGKILL lease withdrawal');time.sleep(1);observed('owner-killed-down',peer='10.77.0.1')
        native('PATCH','container/'+core()['.id'],{'stop-signal':'15-SIGTERM'})
        native('PATCH','app/'+app_id,{'disabled':'false'});settle(relogin,'SIGKILL restart login')
        report['owner_sigkill']={'signal':'9-SIGKILL','cached_down_direct':True,'recovered':recovered('owner-restarted')}

        print('OWNER_SIGKILL_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        def reboot(label):
            before=native('GET','system/resource');started=time.monotonic()
            try: native('POST','system/reboot',{})
            except (OSError,RuntimeError): pass
            def booted():
                after=native('GET','system/resource')
                return after if uptime_seconds(after['uptime']) < uptime_seconds(before['uptime']) else None
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                try:
                    after=booted()
                    if after: break
                except (OSError,RuntimeError): pass
                time.sleep(.2)
            else: raise AssertionError('reboot management did not return')
            now=datetime.datetime.now(datetime.timezone.utc)
            native('POST','system/clock/set',{'time-zone-autodetect':'false','time-zone-name':'Etc/UTC',
                'date':now.strftime('%Y-%m-%d'),'time':now.strftime('%H:%M:%S')})
            return {'before_uptime':before['uptime'],'after_uptime':after['uptime'],'management_ms':round((time.monotonic()-started)*1000)}
        native('PATCH','app/'+app_id,{'disabled':'true'});settle(stopped,'cold reboot App stop');settle(down,'cold reboot DOWN')
        observer=next(r for r in native('GET','tool/netwatch') if r.get('comment')=='mikrocentauri:app6:netwatch:readiness')
        native('PATCH','tool/netwatch/'+observer['.id'],{'disabled':'true'})
        targets=[]
        for path in ('ip/route','ip/firewall/nat'):
            for row in native('GET',path):
                if row.get('comment') in ('mikrocentauri:app6:route:fakeip','mikrocentauri:app6:nat:dns-tcp','mikrocentauri:app6:nat:dns-udp'):
                    targets.append((path,row['.id']))
                    native('PATCH',path+'/'+row['.id'],{'disabled':'false'})
        assert len(targets)==3 and all(native('GET',path+'/'+object_id).get('disabled')=='false' for path,object_id in targets)
        cold=reboot('disabled App with persisted enabled steering')
        settle(lambda: all(native('GET',path+'/'+object_id).get('disabled')=='true' for path,object_id in targets),'startup guard closed steering')
        assert not lease(),'lease survived cold reboot'
        time.sleep(1)
        cold['cached_down']=observed('cold-boot-direct',peer='10.77.0.1')
        fresh=request('selected.test',path='/phase7-cold-boot-fresh');assert_success(fresh,'10.77.0.1')
        assert fresh['resolved_ipv4']=='10.77.0.20';cold['fresh_direct']=fresh
        native('PATCH','tool/netwatch/'+observer['.id'],{'disabled':'false'})
        native('PATCH','app/'+app_id,{'disabled':'false'});settle(relogin,'cold boot start login')
        cold['manual_recovery']=recovered('cold-boot-started');cold['startup_guard_verified']=True;cold['observer_disabled_during_boot']=True
        report['cold_reboot']=cold
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Persistent operator bootstrap, distinct from controller-owned steering.
        spec=importlib.util.spec_from_file_location('render_app_boot',pathlib.Path(__file__).resolve().parents[2]/'scripts/render-app-boot.py')
        boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
        boot_fields=boot.render(name,core()['name'],core()['image-id'])
        boot_id=native('PUT','system/scheduler',boot_fields)['.id'];temporary.append(('system/scheduler',boot_id))
        report['operator_boot_scheduler']={'digest_bound':True,'disabled_app_never_enabled':True,
            'native_fields':boot_fields,'scope':'explicit operator bootstrap; not runtime API/controller ownership'}
        mismatch=boot.render(name,core()['name'],'0'*64)
        wrong=native('PUT','system/script',{'name':'phase7-boot-mismatch-'+name,'source':mismatch['on-event'],'policy':mismatch['policy']})['.id']
        temporary.append(('system/script',wrong));before_pid=engine_pid()
        try:native('POST','system/script/run',{'number':'phase7-boot-mismatch-'+name})
        except RuntimeError:pass
        assert native('GET','app/'+app_id).get('disabled')=='false' and engine_pid()==before_pid, 'mismatched boot digest restarted App'
        report['operator_boot_scheduler']['mismatched_digest_preserved_owner']=True
        native('DELETE','system/script/'+wrong);temporary.remove(('system/script',wrong))
        native('PATCH','app/'+app_id,{'disabled':'true'});settle(stopped,'operator boot disabled App probe');settle(down,'operator boot probe DOWN')
        # Evaluate the exact same source through a temporary native script.
        probe=native('PUT','system/script',{'name':'phase7-boot-probe-'+name,'source':boot_fields['on-event'],'policy':boot_fields['policy']})['.id']
        temporary.append(('system/script',probe));native('POST','system/script/run',{'number':'phase7-boot-probe-'+name})
        assert native('GET','app/'+app_id).get('disabled')=='true' and stopped(), 'boot helper enabled disabled App'
        native('DELETE','system/script/'+probe);temporary.remove(('system/script',probe))
        native('PATCH','app/'+app_id,{'disabled':'false'});settle(relogin,'boot probe restart login');settle(ready,'boot probe readiness');settle(lambda:bool(lease()),'boot probe lease');time.sleep(1)
        boots=[]
        for number in (1,2):
            auto=reboot('enabled App with reviewed startup scheduler')
            settle(relogin,'automatic App login');auto['recovery']=recovered('auto-boot-admitted' if number==1 else 'auto-boot-repeated')
            auto['fresh_dynamic_lease']=lease()[0]['dynamic']=='true'
            auto['scheduler_run_count']=int(native('GET','system/scheduler/'+boot_id).get('run-count','0'))
            assert auto['scheduler_run_count']>0,'operator boot scheduler did not run'
            boots.append(auto)
        report['automatic_reboot']=boots

        print('REBOOT_MATRIX_PASS', flush=True)
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Bounded sustained TCG exercise, not a hardware performance claim.
        begin=time.monotonic();samples=[];resources=[resource_sample()]
        report['sustained_progress']={'transfers':samples,'resources':resources}
        while time.monotonic()-begin < 60:
            pair=[];samples.append(pair)
            for domain,peer in [('selected.test','10.77.0.10'),('unselected.test','10.77.0.1')]:
                result=control(19010,'request',{'domain':domain,'address':baseline if domain=='selected.test' else '10.77.0.20', 'skip_dns':True,'path':'/bench?bytes=65536'});pair.append(result)
                if result.get('error') or result.get('proxy_seen_ip')!=peer:
                    report['failed_sustained']={'elapsed_seconds':round(time.monotonic()-begin,2),
                        'domain':domain,'expected_peer':peer,'result':result,
                        'system':api('GET','/system'),'logs':api('GET','/logs'),
                        'native_rows':{path:[r for r in native('GET',path)
                            if r.get('comment','').startswith('mikrocentauri:app6:')]
                            for path in ('ip/route','ip/firewall/nat','tool/netwatch','system/scheduler','ip/firewall/address-list')}}
                (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
                assert_success(result,peer)
                assert result['bytes']==65536
            assert ready() and lease();time.sleep(5)
        resources.append(resource_sample())
        for sample in resources:
            for kind in ('owner_kib','engine_kib'): assert sample[kind]['VmRSS'] < 256*1024 and sample[kind]['VmSwap']==0
        report['sustained']={'elapsed_seconds':round(time.monotonic()-begin,2),'iterations':len(samples),'bytes_per_transfer':65536,'transfers':samples,'resources':resources,
                            'scope':'one minute TCG cached-alias/real-IP memory/liveness smoke; fresh DNS may deny expired publication proofs; no hardware throughput/loss claim'}
        report['expected_udp_witnesses']=len(report['forwarding']);report['completed']=True
        return report
    finally:
        (work / 'hardening-progress.json').write_text(json.dumps(report,indent=2)+'\n')
        # Only disposable operator fixtures are restored; application owns app6 state.
        control(19020,'proxy-control',{'action':'resume'})
        control(19020,'dns-fixture',{'target':'10.77.0.20','ttl':5})
        native('PATCH','ip/firewall/filter/'+ft_id,{'disabled':original_ft.get('disabled','false')})
        for path,object_id in reversed(temporary): native('DELETE',path+'/'+object_id)


def runtime_probe(*,api,native,work):
    """Preserve unexpected native verification withdrawals under modest load.

    This is a diagnostic experiment, never a product acceptance oracle.
    """
    report={'scope':'diagnostic only; no acceptance','started_epoch':time.time(),'samples':[]}
    begin=time.monotonic()
    def snapshot():
        return {'elapsed_seconds':round(time.monotonic()-begin,2),
            'system':api('GET','/system'),'logs':api('GET','/logs'),
            'native_rows':{path:[r for r in native('GET',path)
                if r.get('comment','').startswith('mikrocentauri:app6:')]
                for path in ('ip/route','ip/firewall/nat','tool/netwatch','ip/firewall/address-list')}}
    while time.monotonic()-begin < 240:
        transfers=[request('unselected.test',path='/bench?bytes=262144'),
                   request('selected.test',path='/bench?bytes=65536')]
        sample=snapshot();sample['transfers']=transfers;report['samples'].append(sample)
        expected=('10.77.0.1','10.77.0.10')
        if any(r.get('error') or r.get('proxy_seen_ip')!=peer for r,peer in zip(transfers,expected)) or not sample['system'][1].get('status',{}).get('ready'):
            report['unexpected_observation']=True
            report['readiness_withdrawn_observed']=(sample['system'][0]==200 and sample['system'][1].get('status',{}).get('ready') is False)
            (work/'runtime-probe.json').write_text(json.dumps(report,indent=2)+'\n')
            time.sleep(25);report['after_withdrawal']=snapshot()
            break
        (work/'runtime-probe.json').write_text(json.dumps(report,indent=2)+'\n')
        time.sleep(5)
    report['elapsed_seconds']=round(time.monotonic()-begin,2)
    (work/'runtime-probe.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
