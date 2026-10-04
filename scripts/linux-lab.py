#!/usr/bin/env python3
"""Run the Alpine laboratory VM with a serial shell, without Docker."""
import argparse
import os
import pathlib
import shutil
import socket
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/linux-lab'


def command(args):
    qemu = shutil.which('qemu-system-x86_64')
    if not qemu:
        raise SystemExit('qemu-system-x86_64 is required')
    if not (CACHE / 'initramfs.gz').exists():
        raise SystemExit('Build the image with scripts/build-linux-lab.py first')
    result = [qemu, '-machine', 'pc', '-accel', 'tcg', '-m', '512', '-smp', '1',
              '-kernel', str(CACHE / 'vmlinuz-virt'), '-initrd', str(CACHE / 'initramfs.gz'),
              '-append', f'console=ttyS0 panic=-1 quiet mc.role={args.role} mc.address={args.address} mc.gateway={args.gateway} mc.alias={args.alias}',
              '-object', 'rng-random,id=lab-rng,filename=/dev/urandom', '-device', 'virtio-rng-pci,rng=lab-rng',
              '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot']
    if args.socket:
        host, port = args.socket.rsplit(':',1)
        if host != '127.0.0.1': raise SystemExit('Lab switches must be loopback')
        deadline = time.monotonic()+15
        while True:
            try:
                with socket.create_connection((host,int(port)),timeout=.5): break
            except OSError:
                if time.monotonic()>deadline: raise SystemExit('Start the Ethernet switch first')
                time.sleep(.1)
        result += ['-netdev', f'socket,id=lan,connect={args.socket}']
    elif args.listen:
        result += ['-netdev', f'socket,id=lan,listen={args.listen}']
    else:
        result += ['-netdev', 'user,id=lan']
    result += ['-device', f'e1000,netdev=lan,mac={args.mac}']
    result += ['-netdev', f'user,id=control,ipv6=off,hostfwd=tcp:127.0.0.1:{args.control_port}-10.0.2.15:8089,hostfwd=tcp:127.0.0.1:{args.control_port+100}-10.0.2.15:8090',
               '-device', 'e1000,netdev=control']
    if args.pcap:
        result += ['-object', f'filter-dump,id=capture,netdev=lan,file={pathlib.Path(args.pcap).resolve()}']
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['client', 'server'], default='client')
    parser.add_argument('--address')
    parser.add_argument('--gateway')
    parser.add_argument('--alias', help='Optional extra address on lab Ethernet')
    parser.add_argument('--control-port', type=int, help='Local HTTP control forward, default client19010/server19020')
    parser.add_argument('--mac', default='52:54:00:88:00:10')
    network = parser.add_mutually_exclusive_group()
    network.add_argument('--socket', help='Connect Ethernet socket to CHR, e.g. 127.0.0.1:19188')
    network.add_argument('--listen', help='Listen for an Ethernet peer')
    parser.add_argument('--pcap', help='Capture Ethernet packets to this file')
    parser.add_argument('--print-command', action='store_true')
    args = parser.parse_args()
    args.address = args.address or ('10.77.0.10/24' if args.role == 'server' else '192.168.88.10/24')
    args.gateway = args.gateway or ('none' if args.role == 'server' else '192.168.88.1')
    args.alias = args.alias or ('10.77.0.20/24' if args.role == 'server' else 'none')
    args.control_port = args.control_port or (19020 if args.role == 'server' else 19010)
    cmd = command(args)
    if args.print_command:
        import shlex
        print(shlex.join(cmd))
    else:
        os.execv(cmd[0], cmd)
