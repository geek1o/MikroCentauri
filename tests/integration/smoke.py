#!/usr/bin/env python3
"""Real sing-box process smoke; deliberately NOT RouterOS/transparent/egress E2E."""
import argparse,json,pathlib,socket,struct,subprocess,tempfile,threading,time,http.server,sys

ROOT=pathlib.Path(__file__).resolve().parents[2]
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_port(p,proc):
 for _ in range(100):
  if proc.poll() is not None:raise RuntimeError('sing-box terminated; inspect private temporary log')
  try:
   with socket.create_connection(('127.0.0.1',p),.1):return
  except OSError:time.sleep(.03)
 raise RuntimeError('sing-box startup timeout')
def recv_exact(s,n):
 b=b''
 while len(b)<n:
  v=s.recv(n-len(b))
  if not v:raise RuntimeError('unexpected EOF')
  b+=v
 return b
def dns_question(name,qtype):
 q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',qtype,1)
 return struct.pack('!HHHHHH',0x4d43,0x100,1,0,0,0)+q
class Resolver:
 def __init__(self):
  self.s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.s.bind(('127.0.0.1',0));self.s.settimeout(.1);self.port=self.s.getsockname()[1];self.stop=False
  self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def run(self):
  while not self.stop:
   try:b,peer=self.s.recvfrom(2048)
   except socket.timeout:continue
   except OSError:return
   end=12
   while b[end]:end+=b[end]+1
   end+=1;qtype=struct.unpack('!H',b[end:end+2])[0];q=b[12:end+4]
   ans=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('127.0.0.1') if qtype==1 else b''
   self.s.sendto(b[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(ans)),0,0)+q+ans,peer)
 def close(self):self.stop=True;self.thread.join(1);self.s.close()
class Target(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=b'mikrocentauri-lab-target';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*args):pass

def request(socks,host,dest):
 with socket.create_connection(('127.0.0.1',socks),2) as s:
  s.settimeout(3);s.sendall(b'\x05\x01\x00');assert recv_exact(s,2)==b'\x05\x00'
  name=host.encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',dest))
  h=recv_exact(s,4);assert h[:2]==b'\x05\x00',h
  n={1:4,4:16}.get(h[3]);n=n if n is not None else recv_exact(s,1)[0];recv_exact(s,n+2)
  s.sendall(('GET / HTTP/1.0\r\nHost: '+host+'\r\n\r\n').encode());data=b''
  while True:
   b=s.recv(4096)
   if not b:break
   data+=b
  assert b'mikrocentauri-lab-target' in data

def main():
 a=argparse.ArgumentParser();a.add_argument('--sing-box',required=True);a.add_argument('--go',default='go');args=a.parse_args();binary=str(pathlib.Path(args.sing_box).resolve());go=str(pathlib.Path(args.go).resolve()) if '/' in args.go else args.go
 resolver=Resolver();target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target);threading.Thread(target=target.serve_forever,daemon=True).start();procs=[]
 try:
  with tempfile.TemporaryDirectory(prefix='mikrocentauri-smoke-') as tmp:
   tmp=pathlib.Path(tmp);cfg=json.loads((ROOT/'lab/configs/hybrid.json').read_text());vless_port,socks_port,dns_port=port(),port(),port();cfg['mode']='socksify';cfg['vless_uri']=f'vless://bf000d23-0752-40b4-affe-68f7707a9661@127.0.0.1:{vless_port}?security=none&type=tcp#Lab';cfg['dns_upstream']='127.0.0.1';app=tmp/'app.json';app.write_text(json.dumps(cfg));generated=tmp/'generated.json'
   subprocess.run([go,'run','./cmd/mikrocentauri','generate','-config',str(app),'-out',str(generated),'-sing-box',binary],cwd=ROOT,check=True,capture_output=True)
   client=json.loads(generated.read_text());client['log']={'level':'info','timestamp':False};client['dns']['servers'][0]['server_port']=resolver.port
   # Adapt only host lab listeners/cache; no Linux TUN is possible in this macOS process smoke.
   for inbound in client['inbounds']:
    inbound['listen']='127.0.0.1';inbound['listen_port']=dns_port if inbound['tag']=='dns-in' else socks_port
   client['experimental']['cache_file']['path']=str(tmp/'cache.db')
   server={'log':{'level':'info','timestamp':False},'inbounds':[{'type':'vless','tag':'test-vless','listen':'127.0.0.1','listen_port':vless_port,'users':[{'uuid':'bf000d23-0752-40b4-affe-68f7707a9661'}]}],'outbounds':[{'type':'direct','tag':'direct'}],'dns':{'servers':[{'type':'udp','tag':'local','server':'127.0.0.1','server_port':resolver.port}],'final':'local'},'route':{'final':'direct','default_domain_resolver':'local'}}
   for name,c in [('server',server),('client',client)]:
    p=tmp/(name+'.json');p.write_text(json.dumps(c));subprocess.run([binary,'check','-c',str(p)],check=True,capture_output=True);log=open(tmp/(name+'.log'),'wb');proc=subprocess.Popen([binary,'run','-c',str(p)],stdout=log,stderr=log);log.close();procs.append(proc);wait_port(vless_port if name=='server' else socks_port,proc)
   request(socks_port,'selected.test',target.server_address[1]);time.sleep(.15);before=(tmp/'server.log').read_text();assert 'inbound/vless[test-vless]' in before and 'selected.test' in before
   request(socks_port,'unselected.test',target.server_address[1]);time.sleep(.15);after=(tmp/'server.log').read_text();assert 'unselected.test' not in after,'DIRECT request entered VLESS server'
   print('PASS real VLESS TCP request and nonselected DIRECT rule (process logs; not CHR egress proof)')
   # Restart only the lab client with the generated hybrid DNS rules, preserving sockets and resolver.
   procs[-1].terminate();procs[-1].wait(3);procs.pop();cfg['mode']='hybrid';app.write_text(json.dumps(cfg));subprocess.run([go,'run','./cmd/mikrocentauri','generate','-config',str(app),'-out',str(generated),'-sing-box',binary],cwd=ROOT,check=True,capture_output=True)
   fake=json.loads(generated.read_text());fake['inbounds']=[x for x in client['inbounds']];fake['dns']['servers'][0]['server_port']=resolver.port;fake['experimental']['cache_file']['path']=str(tmp/'cache.db');p=tmp/'fake.json';p.write_text(json.dumps(fake));log=open(tmp/'fake.log','wb');proc=subprocess.Popen([binary,'run','-c',str(p)],stdout=log,stderr=log);log.close();procs.append(proc);wait_port(socks_port,proc)
   for transport in ['udp','tcp']:
    for domain,qtype,fake_expected in [('selected.test',1,True),('selected.test',28,False),('unselected.test',1,False)]:
     q=dns_question(domain,qtype)
     if transport=='udp':
      with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(2);s.sendto(q,('127.0.0.1',dns_port));answer=s.recv(2048)
     else:
      with socket.create_connection(('127.0.0.1',dns_port),2) as s:s.settimeout(2);s.sendall(struct.pack('!H',len(q))+q);answer=recv_exact(s,struct.unpack('!H',recv_exact(s,2))[0])
     _,flags,_,count,_,_=struct.unpack('!6H',answer[:12]);assert flags&15==0
     if qtype==28:assert count==0,'managed AAAA must be empty'
     elif fake_expected:assert count==1 and answer[-4:-2]==b'\xc6\x12','selected A must be FakeIP'
     else:assert answer[-4:]==socket.inet_aton('127.0.0.1'),'unselected DNS must retain real address'
   print('PASS typed FakeIP DNS on UDP/TCP, managed AAAA suppression and unselected real DNS')
   # Invalid candidate must not replace the saved output; unknown VLESS options are rejected early.
   prior=generated.read_bytes();cfg['vless_uri']=cfg['vless_uri'].replace('#Lab','&unsupported=SECRET#Lab');app.write_text(json.dumps(cfg));r=subprocess.run([go,'run','./cmd/mikrocentauri','generate','-config',str(app),'-out',str(generated),'-sing-box',binary],cwd=ROOT,capture_output=True);assert r.returncode!=0 and generated.read_bytes()==prior and b'SECRET' not in r.stderr
   print('PASS rejected candidate preserves previously validated output and redacts secrets')
 finally:
  for p in reversed(procs):
   if p.poll() is None:p.terminate()
   try:p.wait(3)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  target.shutdown();target.server_close();resolver.close()
 print('NOT RUN: RouterOS packet path, distinct egress, TUN/UDP/QUIC, restart fail-open, reboot, FastTrack')
if __name__=='__main__':main()
