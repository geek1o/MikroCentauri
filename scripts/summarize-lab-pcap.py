#!/usr/bin/env python3
"""Summarize Ethernet IPv4 endpoints from lab PCAP; captures stay outside Git."""
import argparse
import collections
import hashlib
import ipaddress
import json
import pathlib
import re
import struct


def summarize(path):
    data=pathlib.Path(path).read_bytes()
    if data[:4]!=b'\xd4\xc3\xb2\xa1' or len(data)<24 or struct.unpack_from('<I',data,20)[0]!=1:
        raise ValueError('Expected little-endian classic Ethernet PCAP')
    offset=24;counts=collections.Counter();markers=[];proxy_markers=[];cached_markers=[];boot_markers=[];namespace_markers=[];activation_markers=[];api_markers=[];packets=0;ipv6=0
    while offset+16<=len(data):
        sec,usec,size,original=struct.unpack_from('<IIII',data,offset);offset+=16
        frame=data[offset:offset+size];offset+=size
        if len(frame)!=size:raise ValueError('Truncated capture record')
        packets+=1
        if len(frame)<34:continue
        ether=struct.unpack_from('!H',frame,12)[0]
        if ether==0x86dd:ipv6+=1
        if ether!=0x0800:continue
        ihl=(frame[14]&15)*4;proto=frame[23]
        src=str(ipaddress.IPv4Address(frame[26:30]));dst=str(ipaddress.IPv4Address(frame[30:34]))
        start=14+ihl
        if proto not in (6,17) or len(frame)<start+8:continue
        # Nonfirst fragments do not contain transport headers.
        if struct.unpack_from('!H',frame,20)[0]&0x1fff:continue
        sport,dport=struct.unpack_from('!HH',frame,start)
        name='tcp' if proto==6 else 'udp'
        counts[(name,src,dst,dport)]+=1
        if b'mikrocentauri-udp-probe' in frame[start+8:]:
            proxy_markers.append({'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        if b'phase4-churn-udp' in frame[start+8:]:
            cached_markers.append({'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        boot = re.search(rb'phase6-boot-udp-([0-9]+)', frame[start+8:])
        if boot:
            boot_markers.append({'time_utc_epoch':sec+usec/1000000,'sequence':int(boot[1]),'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        namespace = re.search(rb'phase7-([0-9]+)-([a-z]+\.test)-([0-9]+)', frame[start+8:])
        if namespace:
            namespace_markers.append({'time_utc_epoch':sec+usec/1000000,'revision':int(namespace[1]),'domain':namespace[2].decode(),'sequence':int(namespace[3]),'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        activation = re.search(rb'phase8-([0-9]+)-([a-z]+\.test)-([0-9]+)', frame[start+8:])
        if activation:
            activation_markers.append({'time_utc_epoch':sec+usec/1000000,'revision':int(activation[1]),'domain':activation[2].decode(),'sequence':int(activation[3]),'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        api = re.search(rb'(phase4-([0-9]+)-([0-9]+)-([a-z]+\.test)-([0-9]+))', frame[start+8:])
        if api:
            api_markers.append({'marker':api[1].decode(),'run_id':api[2].decode(),'time_utc_epoch':sec+usec/1000000,'revision':int(api[3]),'domain':api[4].decode(),'sequence':int(api[5]),'protocol':name,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
        if proto==17 and b'D-ambiguous-UDP-20261005' in frame[start+8:]:
            markers.append({'time_utc_epoch':sec+usec/1000000,'source':src,'destination':dst,'source_port':sport,'destination_port':dport})
    return {'file':pathlib.Path(path).name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'ethernet_packets':packets,'ipv6_frames':ipv6,
            'flows':[{'protocol':k[0],'source':k[1],'destination':k[2],'destination_port':k[3],'packets':v} for k,v in sorted(counts.items())],
            'realip_udp_marker':markers,'proxy_udp_marker':proxy_markers,'cached_udp_marker':cached_markers,'boot_udp_marker':boot_markers,'namespace_udp_marker':namespace_markers,'activation_udp_marker':activation_markers,'api_udp_marker':api_markers,'scope':'Endpoint counts, not TCP reconstruction or a packet-loss/loop proof'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('pcaps',nargs='+');p.add_argument('--out');a=p.parse_args()
    text=json.dumps([summarize(path) for path in a.pcaps],indent=2)+'\n'
    if a.out:pathlib.Path(a.out).write_text(text)
    else:print(text,end='')
