"""Regression checks for evidence rejection; no RouterOS mutation."""
import copy
import importlib.util
import ipaddress
import struct
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

app=module('verify-app-capture')
v6=module('verify-phase7-capture')
pcap=module('summarize-lab-pcap')
boot=module('render-app-boot')

class CaptureVerification(unittest.TestCase):
    def app_fixture(self):
        report={'accepted':True,'completed':True,'run_id':'123','packets':[]}
        captures=[{'file':name,'sha256':name,'api_udp_marker':[]} for name in ('lan.pcap','wan.pcap')]
        for i in range(4):
            marker=f'phase4-123-1-selected.test-{i}'
            source='192.168.88.20' if i==0 else '192.168.88.10'
            report['packets'].append({'source':source,'expected_peer':'10.77.0.10',
                'udp':{'capture_marker':marker,'resolved_ipv4':'198.19.192.2'}})
            captures[0]['api_udp_marker'].append({'marker':marker,'protocol':'udp','source':source,
                'destination':'198.19.192.2','destination_port':9000})
            captures[1]['api_udp_marker'].append({'marker':marker,'protocol':'tcp','source':'10.77.0.1',
                'destination':'10.77.0.10','destination_port':8443})
        return report,captures

    def test_boot_renderer_binds_names_digest_and_disabled_boundary(self):
        value=boot.render('mikrocentauri','app-mikrocentauri','a'*64)
        self.assertIn('disabled] = false',value['on-event'])
        self.assertIn('image-id] != "'+'a'*64+'"',value['on-event'])
        self.assertEqual(value['start-time'],'startup')
        self.assertIn('stopped] != true',value['on-event'])
        self.assertIn('$waited >= 60',value['on-event'])
        for args in [('bad"; /system reboot','core','a'*64),('safe','bad\nname','a'*64),('safe','core','sha256:'+'a'*64)]:
            with self.assertRaises(ValueError):boot.render(*args)

    def test_ipv6_parser_and_truncated_record(self):
        ethernet=b'\0'*12+struct.pack('!H',0x86dd)
        ip=bytearray(40);ip[0]=0x60;ip[6]=6
        ip[8:24]=ipaddress.IPv6Address('fd7a:7:1::30').packed
        ip[24:40]=ipaddress.IPv6Address('fd7a:7:2::20').packed
        tcp=bytearray(20);struct.pack_into('!HH',tcp,0,12345,8087);tcp[12]=0x50;tcp[13]=2
        frame=ethernet+ip+tcp+b'GET /phase7-v6-123-before-guard HTTP/1.1\r\n'
        header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
        data=header+struct.pack('<IIII',10,500000,len(frame),len(frame))+frame
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'lan.pcap';path.write_bytes(data)
            record=pcap.summarize(path)['ipv6_fixture_tcp'][0]
            self.assertEqual(record['marker'],'/phase7-v6-123-before-guard')
            self.assertTrue(record['syn']);self.assertEqual(record['time_utc_epoch'],10.5)
            path.write_bytes(data[:-1])
            with self.assertRaises(ValueError):pcap.summarize(path)

    def test_source_policy_requires_exact_ingress(self):
        report,captures=self.app_fixture();self.assertEqual(len(app.verify(report,captures)['workloads']),4)
        captures[0]['api_udp_marker'][0]['source']='192.168.88.10'
        with self.assertRaises(AssertionError):app.verify(report,captures)

    def test_wrong_run_or_wrong_forward_path_refused(self):
        report,captures=self.app_fixture();report['run_id']='124'
        with self.assertRaises(AssertionError):app.verify(report,captures)
        report['run_id']='123';captures[1]['api_udp_marker'][0]['destination_port']=9000
        with self.assertRaises(AssertionError):app.verify(report,captures)

    def test_missing_hardening_stages_refused(self):
        report,captures=self.app_fixture()
        report['hardening']={'completed':True,'expected_udp_witnesses':1,'forwarding':[{}]}
        with self.assertRaises((AssertionError,KeyError)):app.verify(report,captures)

    def ipv6_fixture(self):
        records=[{'source':'fd7a:7:1::30','marker':'/phase7-v6-123-'+label,
                  'result':{'remote_ip':'fd7a:7:1::30'}} for label in ('before-guard','after-guard')]
        value={'literal_bypass':records[:1],'after_guard_removed':records[1],
            'blocked_window_epoch':[10,13],'guard_packets':3,'operator_scoped_guard':{'result':{'error':'timeout'}}}
        report={'accepted':True,'completed':True,'run_id':'123','hardening':{'completed':True,'ipv6':value}}
        packets=[{'source':r['source'],'destination':'fd7a:7:2::20','destination_port':8087,
                  'marker':r['marker'],'time_utc_epoch':1,'syn':False} for r in records]
        captures=[{'file':name,'sha256':name,'ipv6_fixture_tcp':copy.deepcopy(packets)} for name in ('lan.pcap','wan.pcap')]
        captures[0]['ipv6_fixture_tcp'].append({'source':'fd7a:7:1::30','destination':'fd7a:7:2::20',
            'destination_port':8087,'marker':None,'time_utc_epoch':11,'syn':True})
        return report,captures

    def test_scoped_guard_requires_positive_ingress_and_zero_egress(self):
        report,captures=self.ipv6_fixture();self.assertEqual(v6.verify(report,captures)['guard_wan_syn'],[])
        captures[1]['ipv6_fixture_tcp'].append(copy.deepcopy(captures[0]['ipv6_fixture_tcp'][-1]))
        with self.assertRaises(AssertionError):v6.verify(report,captures)

    def test_absent_bypass_witness_refused(self):
        report,captures=self.ipv6_fixture();captures[1]['ipv6_fixture_tcp']=[]
        with self.assertRaises(AssertionError):v6.verify(report,captures)

if __name__=='__main__':unittest.main()
