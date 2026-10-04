#!/usr/bin/env python3
"""Loopback-only QEMU socket Ethernet switch with deterministic per-network capture."""
import argparse
import pathlib
import select
import signal
import socket
import struct
import time

parser = argparse.ArgumentParser()
parser.add_argument('--port', required=True, type=int)
parser.add_argument('--capture', required=True)
args = parser.parse_args()
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('127.0.0.1', args.port))
listener.listen()
listener.setblocking(False)
peers = {}
macs = {}
stop = False

def shutdown(*_):
    global stop
    stop = True

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)
path = pathlib.Path(args.capture)
path.parent.mkdir(parents=True, exist_ok=True)
with path.open('wb') as capture:
    capture.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    print(f'LAB SWITCH listening on localhost:{args.port}', flush=True)
    while not stop:
        readable, _, _ = select.select([listener, *peers], [], [], 0.2)
        for sock in readable:
            if sock is listener:
                peer, _ = listener.accept()
                peers[peer] = bytearray()
                continue
            try:
                chunk = sock.recv(65536)
            except OSError:
                chunk = b''
            if not chunk:
                del peers[sock]
                sock.close()
                macs = {m: p for m, p in macs.items() if p is not sock}
                continue
            buffer = peers[sock]
            buffer.extend(chunk)
            while len(buffer) >= 4:
                size = struct.unpack('!I', buffer[:4])[0]
                if size > 65535:
                    raise RuntimeError('Invalid QEMU Ethernet frame size')
                if len(buffer) < size + 4:
                    break
                packet = bytes(buffer[4:size + 4])
                del buffer[:size + 4]
                if len(packet) < 14:
                    continue
                now = time.time()
                sec = int(now)
                capture.write(struct.pack('<IIII', sec, int((now - sec) * 1e6), size, size))
                capture.write(packet)
                capture.flush()
                macs[packet[6:12]] = sock
                target = macs.get(packet[:6])
                outputs = [target] if target and not packet[0] & 1 else list(peers)
                for other in outputs:
                    if other is not sock:
                        try:
                            other.sendall(struct.pack('!I', size) + packet)
                        except OSError:
                            pass
for peer in peers:
    peer.close()
listener.close()
