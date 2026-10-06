#!/usr/bin/env python3
"""Package production CLI/API ownership in an isolated pinned CHR fixture.

Public fixture credentials and certificates are cached privately, never deployment
settings. Preserves old gateway/core images and roots. Does not start or mutate CHR.
"""
import argparse, hashlib, io, json, os, pathlib, subprocess, tarfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
ROOTFS_SHA256='c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677'
GENERATOR=r'''
package main
import("encoding/json";"os";"time";"mikrocentauri.local/core/internal/application";"mikrocentauri.local/core/internal/coreconfig";"mikrocentauri.local/core/internal/endpoints";"mikrocentauri.local/core/internal/platform/routeros")
func main(){
 ep,err:=endpoints.ParseURI("vless://bf000d23-0752-40b4-affe-68f7707a9661@10.77.0.10:8443?security=none&type=tcp#API-lab-only");if err!=nil{panic(err)};ep.Enabled=true
 active:=[]string{"selected.test","second.test","third.test"}
 m:=coreconfig.Model{SchemaVersion:2,Instance:"api4",Mode:"hybrid",Endpoints:[]endpoints.Endpoint{ep},Groups:[]coreconfig.Group{{ID:"proxy",Type:"selector",Members:[]string{ep.ID},Selected:ep.ID}},DefaultOutbound:"direct",DNS:coreconfig.DNS{Bootstrap:"10.77.0.20",FakeIPRange:"198.19.128.0/17",SelectedDomains:active,CachePath:"/data/api4/runtime/cache.db"},Rules:[]coreconfig.Rule{{ID:"independent-canary",DestinationCIDRs:[]string{"10.77.0.10/32"},Outbound:"proxy"},{ID:"selected-domains",Domains:active,Outbound:"proxy"}}}
 targets:=[]routeros.Object{{Path:"ip/route",Fields:map[string]string{"comment":"mikrocentauri:api4:route:fakeip","disabled":"true","dst-address":m.DNS.FakeIPRange,"gateway":"172.30.0.2","routing-table":"main","distance":"1","scope":"30","target-scope":"10"}}}
 for _,protocol:=range []string{"tcp","udp"}{targets=append(targets,routeros.Object{Path:"ip/firewall/nat",PlaceBefore:map[string]string{"tcp":"*3","udp":"*4"}[protocol],Fields:map[string]string{"comment":"mikrocentauri:api4:nat:dns-"+protocol,"disabled":"true","chain":"dstnat","in-interface":"bridge-lan","src-address":"192.168.88.0/24","dst-address":"192.168.88.1","protocol":protocol,"dst-port":"53","action":"dst-nat","to-addresses":"172.30.0.2","to-ports":"5353"}})}
 spec:=routeros.WatchdogSpec{Instance:"api4",Host:"172.30.0.2",Port:9099,Interval:2*time.Second,Timeout:time.Second,SuccessThreshold:2,LANLeaseCIDR:"192.168.88.0/24",Targets:targets}
 p:=application.Profile{Schema:1,Directory:"/data/api4/runtime",DNSListen:"172.30.0.2:5353",ReadinessListen:"172.30.0.2:9099",ObserverClient:"172.30.0.1",IngressInterface:"mc-probe",Table:100,RulePriority:10000,LocalRulePriority:200,LANCIDR:spec.LANLeaseCIDR,LANInterface:"bridge-lan",MappingChain:"mc-api4-backup",MappingPlaceBefore:"*7",Capacity:32,RealDNSAddress:"10.77.0.20:53",CanaryURL:"http://10.77.0.10:8080/",CanaryPeerIP:"10.77.0.10",Watchdog:spec}
 if err=p.Validate(m);err!=nil{panic(err)}
 bundle,err:=routeros.WatchdogBundle(spec);if err!=nil{panic(err)}
 jump,err:=routeros.DesiredMappingJump(routeros.MappingBackendOptions{Instance:"api4",Chain:p.MappingChain,LANCIDR:p.LANCIDR,LANInterface:p.LANInterface,FakeIPRange:m.DNS.FakeIPRange,UpLeaseList:"mc-api4-up-lease",JumpComment:"mikrocentauri:api4:nat:backup-jump",JumpPlaceBefore:"*7",Observer:bundle[0]});if err!=nil{panic(err)}
 objects:=append(append(targets,bundle...),jump)
 json.NewEncoder(os.Stdout).Encode(map[string]any{"model":m,"profile":p,"objects":objects})
}
'''
def private_json(path,value):
 path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--go',default=str(ROOT/'.cache/go/bin/go'))
 p.add_argument('--out',default=str(ROOT/'.cache/api-native/files/api-gateway-image.tar'))
 a=p.parse_args();out=pathlib.Path(a.out).resolve();files=out.parent;files.mkdir(parents=True,exist_ok=True);files.chmod(0o700)
 generator=files/'profile-generator.go';generator.write_text(GENERATOR)
 result=subprocess.run([a.go,'run',str(generator)],cwd=ROOT,check=True,capture_output=True,text=True)
 fixture=json.loads(result.stdout)
 for key in ['model','profile','objects']:private_json(files/(key+'.json'),fixture[key])
 for name,sans in [('router','IP:127.0.0.1,IP:172.30.0.1'),('api','IP:172.30.0.2,IP:127.0.0.1')]:
  if not (files/(name+'.crt')).exists():
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN=api4-'+name+'-fixture','-addext','subjectAltName='+sans,'-keyout',str(files/(name+'.key')),'-out',str(files/(name+'.crt'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  (files/(name+'.key')).chmod(0o600)
 private_json(files/'router.json',{'base_url':'https://172.30.0.1/rest','username':'mc-lab','password':'DisposableLabOnly-2026','ca_file':'/data/api4/router.crt'})
 binary=files/'mikrocentauri'
 subprocess.run([a.go,'build','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',str(binary),'./cmd/mikrocentauri'],cwd=ROOT,env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0'),check=True)
 # Rootfs already provides iproute2. Quarantine precedes IPv4 forwarding.
 entry=b'''#!/bin/sh
set -eu
umask 077
/sbin/ip route replace blackhole default table 100
/sbin/ip rule add priority 10000 iif mc-probe lookup 100
echo 1 > /proc/sys/net/ipv4/ip_forward
if [ ! -f /data/api4/api/auth.json ]; then
 /bin/mikrocentauri api-auth-init -state /data/api4/api -password-file /data/api4/password
fi
exec /bin/mikrocentauri api-serve -state /data/api4/api -config /data/api4/model.json -runtime-profile /data/api4/profile.json -router-config /data/api4/router.json -listen 172.30.0.2:8443 -allow-clients 192.168.88.0/24,172.30.0.1/32,10.0.2.2/32 -tls-cert /data/api4/api.crt -tls-key /data/api4/api.key -sing-box /bin/sing-box
'''
 rootfs=ROOT/'.cache/linux-lab/rootfs.tar.gz';assert hashlib.sha256(rootfs.read_bytes()).hexdigest()==ROOTFS_SHA256
 sb=ROOT/'.cache/sing-box-1.14.2-linux-amd64-musl/sing-box'
 layer=io.BytesIO()
 with tarfile.open(fileobj=layer,mode='w') as archive:
  with tarfile.open(rootfs) as alpine:
   for member in alpine:archive.addfile(member,alpine.extractfile(member) if member.isfile() else None)
  for name in ['data','data/api4','data/api4/api','data/api4/runtime','dev/net']:
   member=tarfile.TarInfo(name);member.type=tarfile.DIRTYPE;member.mode=0o700 if name.startswith('data') else 0o755;archive.addfile(member)
  sources=[('bin/mikrocentauri',binary.read_bytes(),0o755),('bin/sing-box',sb.read_bytes(),0o755),('bin/api4-entry',entry,0o755),('data/api4/password',b'API4DisposablePasswordOnly-2026\n',0o600)]
  sources += [('data/api4/'+name,(files/name).read_bytes(),0o600) for name in ['model.json','profile.json','router.json','router.crt','api.crt','api.key']]
  for name,data,mode in sources:
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=mode;archive.addfile(member,io.BytesIO(data))
 blob=layer.getvalue()
 config=json.dumps({'architecture':'amd64','os':'linux','config':{'Entrypoint':['/bin/api4-entry'],'WorkingDir':'/'},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(blob).hexdigest()]}}).encode()
 name=hashlib.sha256(config).hexdigest()+'.json';manifest=json.dumps([{'Config':name,'RepoTags':['mikrocentauri-api:lab'],'Layers':['layer/layer.tar']}]).encode()
 with tarfile.open(out,'w') as archive:
  for filename,data in [(name,config),('manifest.json',manifest),('layer/layer.tar',blob)]:
   member=tarfile.TarInfo(filename);member.size=len(data);member.mode=0o600;archive.addfile(member,io.BytesIO(data))
 out.chmod(0o600)
 metadata={'image_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'sing_box_sha256':hashlib.sha256(sb.read_bytes()).hexdigest(),'rootfs_sha256':ROOTFS_SHA256,'pool':fixture['model']['dns']['fakeip_range'],'state_directory':'/data/api4/runtime','entrypoint':'production CLI api-serve'}
 private_json(out.with_suffix('.metadata.json'),metadata)
 print(out);print('sha256',metadata['image_sha256'])
if __name__=='__main__':main()
