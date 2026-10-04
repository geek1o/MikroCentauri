#!/usr/bin/env python3
"""Boot a user-supplied official CHR disk; keep the original and bind management to localhost."""
import argparse,os,pathlib,shutil,subprocess,sys,termios
p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--qemu',default='qemu-system-x86_64');p.add_argument('--workdir',default='.cache/chr-lab');p.add_argument('--ssh-port',type=int,default=22222);p.add_argument('--http-port',type=int,default=18080);p.add_argument('--lan-socket',type=int,default=19188);a=p.parse_args()
image=pathlib.Path(a.image).resolve();work=pathlib.Path(a.workdir).resolve();work.mkdir(parents=True,exist_ok=True)
if not image.is_file():p.error('supply an official extracted CHR raw image')
copy=work/'chr.img'
if not copy.exists():shutil.copyfile(image,copy)
# Extra raw storage for container roots, separate from the boot disk.
data=work/'containers.img'
if not data.exists():
 with data.open('wb') as f:f.truncate(2*1024**3)
qemu=shutil.which(a.qemu)
if not qemu:p.error('QEMU executable unavailable')
args=[qemu,'-machine','pc','-accel','tcg','-m','512','-smp','2','-drive',f'file={copy},format=raw,if=ide','-drive',f'file={data},format=raw,if=virtio','-netdev',f'user,id=wan,hostfwd=tcp:127.0.0.1:{a.ssh_port}-:22,hostfwd=tcp:127.0.0.1:{a.http_port}-:80','-device','virtio-net-pci,netdev=wan','-netdev',f'socket,id=lan,listen=127.0.0.1:{a.lan_socket}','-device','virtio-net-pci,netdev=lan','-display','none','-serial','stdio','-monitor',f'unix:{work}/monitor,server=on,wait=off']
# Pass Ctrl-C to the CHR console rather than killing QEMU. Restore terminal settings on return.
old=None
if sys.stdin.isatty():
 old=termios.tcgetattr(0);new=termios.tcgetattr(0);new[3]&=~termios.ISIG;termios.tcsetattr(0,termios.TCSANOW,new)
 print('Login as admin+ct for a plain console; QEMU monitor socket provides explicit quit/reset.',flush=True)
try:raise SystemExit(subprocess.call(args))
finally:
 if old is not None:termios.tcsetattr(0,termios.TCSANOW,old)
